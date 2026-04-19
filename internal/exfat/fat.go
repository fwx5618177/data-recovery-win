package exfat

import (
	"encoding/binary"
	"fmt"

	"data-recovery/internal/disk"
)

// exFAT 的 FAT 表是一张 32-bit 整数数组，每个条目对应一个 cluster 的下一跳。
//
//	entry < 2         : 保留（entry 0 = media type，entry 1 = 预留）
//	entry == 0xFFFFFFF7: BAD cluster
//	entry == 0xFFFFFFFF: End-Of-Chain（EOC）
//	其他值            : 下一个 cluster 号
//
// 官方规范：Microsoft Extensible File Allocation Table File System Specification §8.1
const (
	fatEntrySize = 4 // 每个 FAT 条目 4 字节

	// 对外暴露，方便在测试 / 边界判断里使用
	FatEntryBad uint32 = 0xFFFFFFF7
	FatEntryEOC uint32 = 0xFFFFFFFF
)

// ReadFATEntry 读 cluster 号对应的 FAT 条目。
//
// partitionOffset 是分区起点（字节），cluster >= 2。
// 磁盘 IO：一次 4 字节读。规范实现应该 cache 整个 FAT sector 重复利用，
// 本 MVP 保持简单——让 os.File.ReadAt 的 page cache 去做这个优化。
func ReadFATEntry(
	reader disk.DiskReader,
	boot *BootSector,
	partitionOffset int64,
	cluster uint32,
) (uint32, error) {
	if boot == nil {
		return 0, fmt.Errorf("boot sector 为空")
	}
	if cluster < 2 {
		return 0, fmt.Errorf("cluster %d 无效（保留号）", cluster)
	}
	fatByteOff := boot.FatByteOffset(partitionOffset) + int64(cluster)*fatEntrySize

	buf := make([]byte, fatEntrySize)
	n, err := reader.ReadAt(buf, fatByteOff)
	if err != nil && n == 0 {
		return 0, fmt.Errorf("读取 FAT 条目失败 (cluster=%d): %w", cluster, err)
	}
	if n < fatEntrySize {
		return 0, fmt.Errorf("FAT 条目读不完整 (cluster=%d, got=%d)", cluster, n)
	}
	return binary.LittleEndian.Uint32(buf), nil
}

// FollowFATChain 从 firstCluster 开始沿 FAT 链走，返回完整 cluster 列表。
//
// 硬化措施（真实磁盘上 FAT 可能已损坏 / 已被覆写 / 循环）：
//  1. 环检测：遇到已访问过的 cluster 立即停止，避免死循环
//  2. 长度上限：超过 maxChainLen 认为 FAT 已腐化，停止
//  3. cluster 号范围校验：2 <= c < 2 + ClusterCount
//  4. 遇到 BAD cluster (0xFFFFFFF7) 视为链终止（数据不完整但能拿到前半段）
func FollowFATChain(
	reader disk.DiskReader,
	boot *BootSector,
	partitionOffset int64,
	firstCluster uint32,
) ([]uint32, error) {
	if firstCluster < 2 {
		return nil, fmt.Errorf("firstCluster %d 无效", firstCluster)
	}
	maxChainLen := int(boot.ClusterCount) + 2
	if maxChainLen <= 0 || maxChainLen > 8_000_000 {
		// 上限 8M cluster ≈ 32TB @ 4KB cluster，防 uint32 拿到病态值
		maxChainLen = 8_000_000
	}

	visited := make(map[uint32]bool, 64)
	chain := make([]uint32, 0, 64)

	current := firstCluster
	for i := 0; i < maxChainLen; i++ {
		// cluster 号合法性
		if current < 2 || current >= 2+boot.ClusterCount {
			return chain, fmt.Errorf("FAT 链出现越界 cluster=%d (i=%d)", current, i)
		}
		// 环检测
		if visited[current] {
			return chain, fmt.Errorf("FAT 链检测到环 @cluster=%d (已走 %d 步)", current, i)
		}
		visited[current] = true
		chain = append(chain, current)

		next, err := ReadFATEntry(reader, boot, partitionOffset, current)
		if err != nil {
			return chain, err
		}

		switch next {
		case FatEntryEOC:
			return chain, nil
		case FatEntryBad:
			return chain, fmt.Errorf("FAT 链在 cluster=%d 遇到 BAD 标记", current)
		}
		current = next
	}
	return chain, fmt.Errorf("FAT 链超过长度上限 %d，疑似 FAT 腐化", maxChainLen)
}

// FileClusterList 选择合适的 cluster 列表策略：
//   - NoFatChain=1：文件连续存储，从 firstCluster 顺序生成所需数量的 cluster 号
//   - NoFatChain=0：走 FAT 链
//
// 返回列表不空、长度 ≥ ceil(fileSize / ClusterSize)（FAT 链可能多给几个空 cluster；
// 读者只读 fileSize 字节即可）。
func FileClusterList(
	reader disk.DiskReader,
	boot *BootSector,
	partitionOffset int64,
	entry *DirEntry,
) ([]uint32, error) {
	if entry == nil || boot == nil {
		return nil, fmt.Errorf("参数无效")
	}
	if entry.FirstCluster < 2 {
		return nil, fmt.Errorf("起始 cluster 无效: %d", entry.FirstCluster)
	}
	if entry.FileSize < 0 {
		return nil, fmt.Errorf("文件大小无效: %d", entry.FileSize)
	}

	needed := (entry.FileSize + boot.ClusterSize - 1) / boot.ClusterSize
	if needed <= 0 {
		needed = 1
	}

	if entry.NoFatChain {
		// 连续存储：cluster 号直接递增
		out := make([]uint32, 0, needed)
		for i := int64(0); i < needed; i++ {
			c := entry.FirstCluster + uint32(i)
			if c < 2 || uint64(c) >= uint64(2)+uint64(boot.ClusterCount) {
				break
			}
			out = append(out, c)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("连续存储 cluster 范围越界")
		}
		return out, nil
	}

	// 碎片化：走 FAT 链
	chain, err := FollowFATChain(reader, boot, partitionOffset, entry.FirstCluster)
	if err != nil && len(chain) == 0 {
		return nil, err
	}
	// FAT 链有可能比实际 needed 长（文件末尾的空 cluster 被分配），截断
	if int64(len(chain)) > needed {
		chain = chain[:needed]
	}
	return chain, nil
}
