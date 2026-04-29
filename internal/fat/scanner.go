package fat

import (
	"context"
	"fmt"
	"io"
	"time"

	"data-recovery/internal/disk"
)

// ProgressFn 是分区发现阶段的进度回调；scanned 已扫描字节数，total 磁盘总字节数。
type ProgressFn = func(scanned, total int64)

// FindOptions 见 exfat.FindOptions —— 同义。
//
// 默认 BruteForce=false：只解析 offset 0 boot sector，failed 直接返回空，**不**隐式
// brute-force fallback。BruteForce=true：找已删除 FAT 分区，代价是 1 次全盘 IO。
type FindOptions struct {
	OnProgress ProgressFn
	BruteForce bool
}

// Scanner 扫描 FAT 分区 + 遍历目录。
type Scanner struct {
	reader disk.DiskReader
}

func NewScanner(reader disk.DiskReader) *Scanner {
	return &Scanner{reader: reader}
}

// Partition 一块 FAT 分区
type Partition struct {
	Offset     int64
	Size       int64
	Type       string
	BootSector *BootSector
}

// FoundFile 发现的文件回调结构
type FoundFile struct {
	Entry        DirEntry
	FullPath     string
	PartitionOff int64
}

// FindPartitions 定位 FAT12/16/32 分区。
//
// 策略：
//  1. **策略 a（fast path）**：解析 offset 0 boot sector，签名/字段合理性通过即返回 1 个分区。
//  2. **策略 b（brute-force）**：opts.BruteForce=true 时额外全盘扫 0xAA55 boot signature
//     + bytes-per-sector 合理性过滤，找已删除 FAT 分区。**默认关闭**（v2.8.8+）。
//
// FAT 没有独立的 "FAT   " OEM ID，brute-force 只能靠 0xAA55 + 字段过滤，假阳性比 exFAT 多。
// 默认关掉它的另一个理由 —— 现代盘上 FAT 分区罕见，大量 IO 换零结果。
func (s *Scanner) FindPartitions(ctx context.Context, opts FindOptions) ([]Partition, error) {
	var parts []Partition

	// 策略 a: offset 0（fast path）
	if bs, err := ParseBootSector(s.reader, 0); err == nil {
		if bs.FSType != TypeUnknown {
			parts = append(parts, Partition{
				Offset:     0,
				Size:       int64(bs.TotalSectors) * int64(bs.BytesPerSector),
				Type:       bs.FSType.String() + "-volume",
				BootSector: bs,
			})
		}
	}

	// 策略 b: 全盘 signature scan（仅取证模式）
	if opts.BruteForce {
		brute, err := s.bruteForceFindFAT(ctx, opts.OnProgress)
		if err == nil {
			parts = append(parts, brute...)
		}
	}

	parts = dedupePartitions(parts)
	if len(parts) == 0 {
		return nil, fmt.Errorf("未发现 FAT 分区")
	}
	return parts, nil
}

func (s *Scanner) bruteForceFindFAT(ctx context.Context, onProgress ProgressFn) ([]Partition, error) {
	size, err := s.reader.Size()
	if err != nil {
		return nil, err
	}
	const (
		blockSize int64 = 4 * 1024 * 1024
		stepSize  int64 = 512 * 1024
	)
	buf := make([]byte, blockSize)
	var result []Partition

	const progressEmitInterval = 500 * time.Millisecond
	lastEmit := time.Now()

	for blockOff := int64(0); blockOff < size; blockOff += blockSize {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		read := blockSize
		if blockOff+read > size {
			read = size - blockOff
		}
		n, rerr := s.reader.ReadAt(buf[:read], blockOff)
		if rerr != nil && rerr != io.EOF {
			continue
		}
		if n < 512 {
			continue
		}
		for in := int64(0); in+512 <= int64(n); in += stepSize {
			if buf[in+510] != 0x55 || buf[in+511] != 0xAA {
				continue
			}
			// 启发过滤：BytesPerSector 应为 512/1024/2048/4096 之一
			bps := uint16(buf[in+11]) | uint16(buf[in+12])<<8
			if bps != 512 && bps != 1024 && bps != 2048 && bps != 4096 {
				continue
			}
			abs := blockOff + in
			bs, err := ParseBootSector(s.reader, abs)
			if err != nil {
				continue
			}
			if bs.FSType == TypeUnknown {
				continue
			}
			result = append(result, Partition{
				Offset:     abs,
				Size:       int64(bs.TotalSectors) * int64(bs.BytesPerSector),
				Type:       bs.FSType.String() + "-brute",
				BootSector: bs,
			})
		}

		if onProgress != nil && time.Since(lastEmit) >= progressEmitInterval {
			onProgress(blockOff+read, size)
			lastEmit = time.Now()
		}
	}
	if onProgress != nil {
		onProgress(size, size)
	}
	return result, nil
}

func dedupePartitions(in []Partition) []Partition {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[int64]bool, len(in))
	out := make([]Partition, 0, len(in))
	for _, p := range in {
		if seen[p.Offset] {
			continue
		}
		seen[p.Offset] = true
		out = append(out, p)
	}
	return out
}

// ScanDirectory 从根目录开始递归遍历。
// FAT32: 根目录是 cluster chain（从 bs.RootCluster 开始）
// FAT12/16: 根目录在固定扇区区，连续存储、上限 RootEntryCount 条
func (s *Scanner) ScanDirectory(
	ctx context.Context,
	bs *BootSector,
	partitionOffset int64,
	onFound func(FoundFile),
) error {
	const maxDepth = 32
	visited := make(map[uint32]bool)

	// 先读根目录 raw bytes
	var rootData []byte
	if bs.FSType == TypeFAT32 {
		// 走 cluster chain
		d, err := s.readClusterChain(bs, partitionOffset, bs.RootCluster, visited)
		if err != nil {
			return fmt.Errorf("读 FAT32 根目录失败: %w", err)
		}
		rootData = d
	} else {
		// 固定区域：一次性读完
		offset := bs.RootDirByteOffset(partitionOffset)
		sizeBytes := bs.RootDirByteSize()
		if sizeBytes <= 0 {
			return fmt.Errorf("FAT12/16 根目录区大小为 0")
		}
		buf := make([]byte, sizeBytes)
		n, err := s.reader.ReadAt(buf, offset)
		if err != nil && n == 0 {
			return fmt.Errorf("读 FAT12/16 根目录失败: %w", err)
		}
		rootData = buf[:n]
	}

	return s.walk(ctx, bs, partitionOffset, rootData, "", 0, maxDepth, visited, onFound)
}

// readClusterChain 从 startCluster 开始沿 FAT 链把所有 cluster 的字节拼起来返回
func (s *Scanner) readClusterChain(
	bs *BootSector,
	partitionOffset int64,
	startCluster uint32,
	visited map[uint32]bool,
) ([]byte, error) {
	if visited[startCluster] {
		return nil, nil
	}
	chain, err := FollowFATChain(s.reader, bs, partitionOffset, startCluster)
	if err != nil && len(chain) == 0 {
		return nil, err
	}
	var out []byte
	clusterBuf := make([]byte, bs.ClusterSize)
	for _, c := range chain {
		visited[c] = true
		off := bs.ClusterToByteOffset(c, partitionOffset)
		if off < 0 {
			break
		}
		n, rerr := s.reader.ReadAt(clusterBuf, off)
		if rerr != nil && n == 0 {
			break
		}
		out = append(out, clusterBuf[:n]...)
	}
	return out, nil
}

func (s *Scanner) walk(
	ctx context.Context,
	bs *BootSector,
	partitionOffset int64,
	dirData []byte,
	parentPath string,
	depth, maxDepth int,
	visited map[uint32]bool,
	onFound func(FoundFile),
) error {
	if depth > maxDepth {
		return nil
	}
	entries := parseDirEntries(dirData)
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		childPath := parentPath + "/" + e.Name
		if parentPath == "" {
			childPath = e.Name
		}

		if e.IsDirectory && !e.IsDeleted {
			// 递归进子目录（只对在用的目录；已删目录的 cluster 链通常已被清掉）
			if e.FirstCluster < 2 {
				continue
			}
			sub, err := s.readClusterChain(bs, partitionOffset, e.FirstCluster, visited)
			if err != nil || len(sub) == 0 {
				continue
			}
			_ = s.walk(ctx, bs, partitionOffset, sub, childPath, depth+1, maxDepth, visited, onFound)
			continue
		}

		if e.IsDirectory {
			// 已删目录 —— 目录本身不回调，里面可能有文件但没链入口
			continue
		}

		// 普通文件（含已删除）
		if onFound != nil {
			onFound(FoundFile{
				Entry:        e,
				FullPath:     childPath,
				PartitionOff: partitionOffset,
			})
		}
	}
	return nil
}
