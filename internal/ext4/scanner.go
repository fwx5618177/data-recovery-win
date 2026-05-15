package ext4

import (
	"context"
	"fmt"
	"io"
	"time"

	"data-recovery/internal/disk"
)

// ProgressFn 是分区发现阶段的进度回调；scanned 已扫描字节数，total 磁盘总字节数。
type ProgressFn = func(scanned, total int64)

// FindOptions 见 exfat.FindOptions —— 同义。BruteForce=false（默认）只解析 offset 0 超块；
// BruteForce=true 全盘扫 0xEF53 magic 找已删除/丢失的 ext 分区残骸（取证模式）。
type FindOptions struct {
	OnProgress ProgressFn
	BruteForce bool
}

// Scanner 提供 ext 文件系统的"找分区 → 走目录树 → 列文件"完整流程
type Scanner struct {
	reader disk.DiskReader
}

func NewScanner(reader disk.DiskReader) *Scanner {
	return &Scanner{reader: reader}
}

// Partition 表示发现的一个 ext 分区
type Partition struct {
	Offset     int64
	SuperBlock *SuperBlock
	GroupDescs []GroupDesc
}

// FoundFile 一条文件发现
type FoundFile struct {
	Inode        *Inode
	FullPath     string
	IsDeleted    bool
	PartitionOff int64
	SuperBlock   *SuperBlock
	GroupDescs   []GroupDesc
}

// FindPartitions 定位 ext 分区。
//
// 策略（v2.8.11 修订，对齐 v2.8.8 的 exfat/fat/ntfs 行为）：
//  1. 偏移 0 试解超块（整盘即一个 ext 分区，fast path 微秒级）
//  2. 全盘 magic（0xEF 53 在偏移 0x438）扫描 —— **仅 opts.BruteForce=true 时启用**
//
// **关键修复**：之前 bruteForce 永远跑，导致 128GB U 盘上 ext 阶段卡 12 小时
// （即使盘是 exFAT 没 ext 分区也要扫全盘）。现在跟其他 FS scanner 一致 opt-in。
func (s *Scanner) FindPartitions(ctx context.Context, opts FindOptions) ([]*Partition, error) {
	var out []*Partition

	if sb, err := ParseSuperblock(s.reader, 0); err == nil {
		gd, err := ReadGroupDescriptors(s.reader, sb)
		if err == nil {
			out = append(out, &Partition{Offset: 0, SuperBlock: sb, GroupDescs: gd})
		}
	}

	// brute-force 仅在取证模式启用
	if opts.BruteForce {
		parts2, _ := s.bruteForce(ctx, opts.OnProgress)
		for _, p := range parts2 {
			dup := false
			for _, existing := range out {
				if existing.Offset == p.Offset {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, p)
			}
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("未找到 ext 分区")
	}
	return out, nil
}

func (s *Scanner) bruteForce(ctx context.Context, onProgress ProgressFn) ([]*Partition, error) {
	size, err := s.reader.Size()
	if err != nil {
		return nil, err
	}
	const (
		blockSize int64 = 4 * 1024 * 1024
		step      int64 = 1024 * 1024
	)
	buf := make([]byte, blockSize)
	var out []*Partition

	const progressEmitInterval = 500 * time.Millisecond
	lastEmit := time.Now()

	for blockOff := int64(0); blockOff < size; blockOff += blockSize {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		read := blockSize
		if blockOff+read > size {
			read = size - blockOff
		}
		n, rerr := s.reader.ReadAt(buf[:read], blockOff)
		if rerr != nil && n == 0 {
			continue
		}
		// 在块内按 step 扫；超块 magic 在分区起点 +0x438（=1080）处
		for in := int64(0); in+0x438+2 <= int64(n); in += step {
			off := in + 0x438
			if buf[off] != 0x53 || buf[off+1] != 0xEF {
				continue
			}
			abs := blockOff + in
			sb, err := ParseSuperblock(s.reader, abs)
			if err != nil {
				continue
			}
			gd, err := ReadGroupDescriptors(s.reader, sb)
			if err != nil {
				continue
			}
			out = append(out, &Partition{Offset: abs, SuperBlock: sb, GroupDescs: gd})
		}

		if onProgress != nil && time.Since(lastEmit) >= progressEmitInterval {
			onProgress(blockOff+read, size)
			lastEmit = time.Now()
		}
	}
	if onProgress != nil {
		onProgress(size, size)
	}
	return out, nil
}

// ScanFiles 从 root inode (=2) 开始，递归遍历，发现的每个文件回调一次。
//
// 同时收集"自由 inode 表"中的孤立 inode（已删除文件）—— 这是 ext 已删文件恢复的关键：
// 即使目录条目被覆盖，inode 表里的 i_block 字段仍可能保留指向原数据块。
//
// 走两遍：
//
//	pass1：从 root 走目录树（含 deleted dentries）
//	pass2：扫所有 inode，找 dtime != 0 但还没被 pass1 看到的孤立条目
func (s *Scanner) ScanFiles(
	ctx context.Context,
	p *Partition,
	onFound func(FoundFile),
) error {
	if p == nil || p.SuperBlock == nil {
		return fmt.Errorf("无效 partition")
	}
	sb := p.SuperBlock
	hasFileType := sb.FeatureIncompat&0x0002 != 0 // INCOMPAT_FILETYPE
	ir := NewInodeReader(s.reader, sb, p.GroupDescs)

	visited := make(map[uint64]bool)

	// pass1：从 root inode = 2 递归
	rootInode, err := ir.ReadInode(2)
	if err != nil {
		return fmt.Errorf("读 root inode 失败: %w", err)
	}
	if rootInode.IsDirectory {
		s.walkDir(ctx, ir, sb, rootInode, "", 0, 32, hasFileType, visited, p, onFound)
	}

	// pass2：扫遗漏的孤立 inode（dtime != 0 而且还没访问过）
	for inum := uint64(11); inum <= uint64(sb.InodesCount); inum++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if visited[inum] {
			continue
		}
		in, err := ir.ReadInode(inum)
		if err != nil {
			continue
		}
		if !in.IsDeleted || !in.IsRegularFile {
			continue
		}
		if in.Size <= 0 {
			continue
		}
		// 孤立删除文件：没有路径，命名按 inode 编号
		onFound(FoundFile{
			Inode:        in,
			FullPath:     fmt.Sprintf("[deleted-orphan]/inode_%d", inum),
			IsDeleted:    true,
			PartitionOff: p.Offset,
			SuperBlock:   sb,
			GroupDescs:   p.GroupDescs,
		})
		visited[inum] = true
	}

	return nil
}

// walkDir 递归走目录树
func (s *Scanner) walkDir(
	ctx context.Context,
	ir *InodeReader, sb *SuperBlock,
	dir *Inode, parentPath string,
	depth, maxDepth int,
	hasFileType bool,
	visited map[uint64]bool,
	p *Partition,
	onFound func(FoundFile),
) {
	if depth > maxDepth {
		return
	}
	if visited[dir.Number] {
		return
	}
	visited[dir.Number] = true

	// 读目录数据：拼起所有数据块
	ranges, err := CollectFileBlocks(s.reader, sb, dir)
	if err != nil {
		return
	}
	dirData, err := readRangesAsBytes(s.reader, sb, ranges, dir.Size)
	if err != nil {
		return
	}

	entries := parseDirBlock(dirData, hasFileType)
	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		if e.Inode == 0 {
			continue // ghost dentry 但没有 inode 引用
		}

		childInode, err := ir.ReadInode(e.Inode)
		if err != nil {
			continue
		}

		childPath := parentPath + "/" + e.Name
		if parentPath == "" {
			childPath = e.Name
		}

		if childInode.IsDirectory && !e.IsDeleted {
			s.walkDir(ctx, ir, sb, childInode, childPath, depth+1, maxDepth, hasFileType, visited, p, onFound)
			continue
		}

		if childInode.IsRegularFile {
			onFound(FoundFile{
				Inode:        childInode,
				FullPath:     childPath,
				IsDeleted:    e.IsDeleted || childInode.IsDeleted,
				PartitionOff: p.Offset,
				SuperBlock:   sb,
				GroupDescs:   p.GroupDescs,
			})
		}
	}
}

// readRangesAsBytes 把 PhysicalRange 列表里的物理块全部读出来拼成连续字节流，
// sparse 段填零；按 maxBytes 截断
func readRangesAsBytes(
	reader disk.DiskReader,
	sb *SuperBlock,
	ranges []PhysicalRange,
	maxBytes int64,
) ([]byte, error) {
	var out []byte
	for _, r := range ranges {
		if maxBytes > 0 && int64(len(out)) >= maxBytes {
			break
		}
		segLen := int64(r.Length) * sb.BlockSize
		if maxBytes > 0 && int64(len(out))+segLen > maxBytes {
			segLen = maxBytes - int64(len(out))
		}
		if r.PhysicalBlock == 0 {
			out = append(out, make([]byte, segLen)...)
			continue
		}
		buf := make([]byte, segLen)
		_, err := reader.ReadAt(buf, sb.BlockToByteOffset(r.PhysicalBlock))
		if err != nil && err != io.EOF {
			return out, err
		}
		out = append(out, buf...)
	}
	return out, nil
}
