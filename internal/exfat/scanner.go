package exfat

import (
	"context"
	"fmt"
	"io"
	"time"

	"data-recovery/internal/disk"
)

// ProgressFn 是分区发现阶段的进度回调；scanned 已扫描字节数，total 磁盘总字节数。
// 调用方 (recovery dispatcher) 把它包装成 types.ScanProgress 喂给前端。
type ProgressFn = func(scanned, total int64)

// FindOptions 控制 FindPartitions 的执行策略。
//
// 默认（BruteForce=false）：只跑 strategy-a（offset-0 ParseBootSector），健康盘上
// 微秒返回。fast path 失败时直接返回 (nil, "未发现 exFAT 分区")，**不做隐式 brute-force fallback**。
// 这跟 R-Studio Quick scan / PhotoRec 默认 / DMDE Quick / TestDisk 默认行为一致。
//
// BruteForce=true（取证模式）：在 fast path 之外**总是**额外跑全盘签名扫描，找已删除/
// 丢失的 exFAT 分区。代价：125GB 盘 ≈ 1 小时 IO（取决于盘速 + 坏扇区重试）。
type FindOptions struct {
	OnProgress ProgressFn
	BruteForce bool
}

// Scanner 扫描一块磁盘 / 一份镜像中的 exFAT 分区，递归枚举所有目录条目。
// 使用方式：
//
//	s := exfat.NewScanner(reader)
//	parts, err := s.FindPartitions(ctx)
//	for _, p := range parts {
//	    s.ScanDirectory(ctx, p.BootSector, p.Offset, func(file FoundFile) { ... })
//	}
type Scanner struct {
	reader disk.DiskReader
}

// NewScanner 构造一个 exFAT Scanner
func NewScanner(reader disk.DiskReader) *Scanner {
	return &Scanner{reader: reader}
}

// Partition 表示磁盘上发现的一个 exFAT 分区
type Partition struct {
	Offset     int64 // 分区在磁盘上的起始字节偏移
	Size       int64 // 分区字节大小（估算）
	Type       string
	BootSector *BootSector
}

// FoundFile 是 Scanner 回调给上层的一条文件发现结果
type FoundFile struct {
	Entry        DirEntry
	FullPath     string // 相对于分区根的完整路径（用 "/" 分隔）
	PartitionOff int64  // 所在分区的起始偏移，recover 时需要
}

// FindPartitions 扫描磁盘定位 exFAT 分区。
//
// 策略：
//  1. **策略 a（fast path）**：尝试 offset 0 解析整盘即 exFAT volume（U 盘 / SD 卡 99% 的场景）。
//  2. **策略 b（brute-force）**：opts.BruteForce=true 时**额外**全盘扫 "EXFAT   " OEM ID
//     找被删除/丢失的旧分区。**默认关闭**（v2.8.8+ 行为，对齐 R-Studio Quick scan / PhotoRec 默认）。
//
// 关键决策：fast path 失败时**不**隐式 fallback 到 brute-force，因为：
//   - 隐式 fallback = 用户感知的"为什么我的扫描跑了 14 小时"
//   - 显式 fallback = 让上层决定（"fast path 没找到东西，要不要切到取证模式重扫？"）
//   - 行业标准是后者
func (s *Scanner) FindPartitions(ctx context.Context, opts FindOptions) ([]Partition, error) {
	var partitions []Partition

	// 策略 a：假设整盘即一个 exFAT 分区（fast path，微秒级）
	if bs, err := ParseBootSector(s.reader, 0); err == nil {
		partitions = append(partitions, Partition{
			Offset:     0,
			Size:       bs.VolumeLength * bs.BytesPerSector,
			Type:       "volume",
			BootSector: bs,
		})
	}

	// 策略 b：全盘暴力签名扫描（仅取证模式启用）。
	// 找已删除/丢失分区用，代价 = 1 次全盘 IO。
	if opts.BruteForce {
		brute, err := s.bruteForceFindEXFAT(ctx, opts.OnProgress)
		if err == nil {
			partitions = append(partitions, brute...)
		}
	}

	partitions = dedupePartitions(partitions)
	if len(partitions) == 0 {
		return nil, fmt.Errorf("未发现 exFAT 分区")
	}
	return partitions, nil
}

// bruteForceFindEXFAT 全盘按 4MB 块读入 + 512KB 步进搜索 exFAT boot sector
// "EXFAT   " OEM ID 在 boot sector 偏移 3-10 处
//
// onProgress 每 ~500ms 节流回调一次（避免事件风暴）；nil 时静默扫描。
func (s *Scanner) bruteForceFindEXFAT(ctx context.Context, onProgress ProgressFn) ([]Partition, error) {
	diskSize, err := s.reader.Size()
	if err != nil {
		return nil, err
	}

	const (
		readBlockSize int64 = 4 * 1024 * 1024
		stepSize      int64 = 512 * 1024
	)
	buf := make([]byte, readBlockSize)
	var result []Partition

	const progressEmitInterval = 500 * time.Millisecond
	lastEmit := time.Now()

	for blockOff := int64(0); blockOff < diskSize; blockOff += readBlockSize {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		readSize := readBlockSize
		if blockOff+readSize > diskSize {
			readSize = diskSize - blockOff
		}
		nr, rerr := s.reader.ReadAt(buf[:readSize], blockOff)
		if rerr != nil && rerr != io.EOF {
			continue
		}
		if nr < 512 {
			continue
		}

		for in := int64(0); in+512 <= int64(nr); in += stepSize {
			// 快速 OEM ID 检查
			if string(buf[in+3:in+11]) != exFATSignature {
				continue
			}
			abs := blockOff + in
			bs, err := ParseBootSector(s.reader, abs)
			if err != nil {
				continue
			}
			result = append(result, Partition{
				Offset:     abs,
				Size:       bs.VolumeLength * bs.BytesPerSector,
				Type:       "bruteforce",
				BootSector: bs,
			})
		}

		if onProgress != nil && time.Since(lastEmit) >= progressEmitInterval {
			onProgress(blockOff+readSize, diskSize)
			lastEmit = time.Now()
		}
	}
	if onProgress != nil {
		onProgress(diskSize, diskSize)
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

// ScanDirectory 从根目录开始递归遍历一个 exFAT 分区，逐条回调文件。
//
// 已删除条目也会回调（DirEntry.IsDeleted=true），让上层自己决定要不要恢复它。
// 目录本身（IsDirectory=true）不会回调给文件消费者——但会递归进去。
//
// 碎片化保护：maxDepth 限制子目录深度避免病态磁盘造成死循环；
// visitedClusters 防止因簇链被破坏导致的无限自引用。
func (s *Scanner) ScanDirectory(
	ctx context.Context,
	boot *BootSector,
	partitionOffset int64,
	onFound func(FoundFile),
) error {
	const maxDepth = 32
	visited := make(map[uint32]bool)
	return s.walkDir(ctx, boot, partitionOffset, boot.FirstClusterOfRootDirectory, "", 0, maxDepth, visited, onFound)
}

// walkDir 递归目录实现
func (s *Scanner) walkDir(
	ctx context.Context,
	boot *BootSector,
	partitionOffset int64,
	startCluster uint32,
	parentPath string,
	depth, maxDepth int,
	visited map[uint32]bool,
	onFound func(FoundFile),
) error {
	if depth > maxDepth {
		return nil
	}
	if startCluster < 2 || visited[startCluster] {
		return nil
	}
	visited[startCluster] = true

	// 先定义 helper（本文件最末，不污染这里的可读性）。
	//
	// 读目录数据：优先走 FAT 链拼连（完整场景），遇到 FAT 读失败退化为"从 startCluster
	// 连续读 N 簇"的启发（老版本行为）。
	const maxDirClusters = 512 // 32MB 目录上限
	startOffset := boot.ClusterToByteOffset(startCluster, partitionOffset)
	if startOffset < 0 {
		return nil
	}
	buf, err := s.readDirFollowingFAT(boot, partitionOffset, startCluster, maxDirClusters)
	if err != nil || len(buf) == 0 {
		dirDataSize := int64(maxDirClusters) * boot.ClusterSize
		buf = make([]byte, dirDataSize)
		n, rerr := s.reader.ReadAt(buf, startOffset)
		if rerr != nil && rerr != io.EOF {
			return fmt.Errorf("读取目录簇失败 (cluster=%d): %w", startCluster, rerr)
		}
		if n == 0 {
			return nil
		}
		buf = buf[:n]
	}

	pos := 0
	// 连续空 entry 计数，超过 4 个直接停止（目录边界探测启发）
	emptyStreak := 0
	for pos < len(buf) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entry, consumed := ParseEntrySet(buf, pos)
		if consumed <= 0 {
			consumed = 32 // 防死循环
		}

		// 检查是否是全零 entry
		allZero := true
		if pos+32 <= len(buf) {
			for i := 0; i < 32; i++ {
				if buf[pos+i] != 0 {
					allZero = false
					break
				}
			}
		}
		if allZero {
			emptyStreak++
			if emptyStreak > 4 {
				break // 连续空条目 → 认为已到目录尾部
			}
			pos += 32
			continue
		}
		emptyStreak = 0

		if entry == nil {
			pos += consumed
			continue
		}

		entry.DirEntryOffset = startOffset + int64(pos)

		if entry.IsDirectory && !entry.IsDeleted {
			// 递归进入子目录（跳过 "." / ".." —— exFAT 其实没这俩，但容错）
			if entry.Name != "." && entry.Name != ".." {
				subPath := parentPath + "/" + entry.Name
				if parentPath == "" {
					subPath = entry.Name
				}
				_ = s.walkDir(ctx, boot, partitionOffset, entry.FirstCluster, subPath, depth+1, maxDepth, visited, onFound)
			}
		} else if !entry.IsDirectory {
			// 普通文件（含已删除），交给上层
			fullPath := parentPath + "/" + entry.Name
			if parentPath == "" {
				fullPath = entry.Name
			}
			if onFound != nil {
				onFound(FoundFile{
					Entry:        *entry,
					FullPath:     fullPath,
					PartitionOff: partitionOffset,
				})
			}
		}
		pos += consumed
	}

	return nil
}

// readDirFollowingFAT 顺着 FAT 链把整个目录数据拼起来。
// 比 "连续读 N 簇" 的旧启发更准 — 能正确读跨 FAT 链的目录（目录极大 / 文件系统高度碎片化时
// 的真实布局）。
//
// 返回 nil/error 时调用方应 fallback 到老启发。
func (s *Scanner) readDirFollowingFAT(boot *BootSector, partitionOffset int64, firstCluster uint32, maxClusters int) ([]byte, error) {
	chain, err := FollowFATChain(s.reader, boot, partitionOffset, firstCluster)
	if err != nil || len(chain) == 0 {
		return nil, err
	}
	if len(chain) > maxClusters {
		chain = chain[:maxClusters]
	}
	total := int64(len(chain)) * boot.ClusterSize
	out := make([]byte, total)
	for i, c := range chain {
		off := boot.ClusterToByteOffset(c, partitionOffset)
		if off < 0 {
			return nil, nil
		}
		n, rerr := s.reader.ReadAt(out[int64(i)*boot.ClusterSize:int64(i+1)*boot.ClusterSize], off)
		if rerr != nil && n == 0 {
			return nil, rerr
		}
	}
	return out, nil
}
