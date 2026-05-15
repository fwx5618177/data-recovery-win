package fat

import (
	"encoding/binary"
	"fmt"

	"data-recovery/internal/disk"
)

// ReadFATEntry 读 cluster 对应的 FAT 条目。
// 不同 FAT 变体条目宽度不同：
//
//	FAT12: 1.5 字节/条目（两个 cluster 共享 3 字节，低/高 nibble 编码）
//	FAT16: 2 字节/条目
//	FAT32: 4 字节/条目，低 28 位有效
//
// 返回值已统一成 uint32；FAT12 / FAT16 的 EOC / BAD 值会映射到 FAT32 的常量便于上层统一判断。
func ReadFATEntry(
	reader disk.DiskReader,
	bs *BootSector,
	partitionOffset int64,
	cluster uint32,
) (uint32, error) {
	if cluster < 2 {
		return 0, fmt.Errorf("cluster %d 无效（保留）", cluster)
	}

	fatStart := partitionOffset + int64(bs.FirstFATSector)*int64(bs.BytesPerSector)

	switch bs.FSType {
	case TypeFAT32:
		buf := make([]byte, 4)
		_, err := reader.ReadAt(buf, fatStart+int64(cluster)*4)
		if err != nil {
			return 0, err
		}
		raw := binary.LittleEndian.Uint32(buf) & 0x0FFFFFFF // 低 28 位
		return raw, nil

	case TypeFAT16:
		buf := make([]byte, 2)
		_, err := reader.ReadAt(buf, fatStart+int64(cluster)*2)
		if err != nil {
			return 0, err
		}
		raw := uint32(binary.LittleEndian.Uint16(buf))
		// FAT16 EOC = 0xFFF8-0xFFFF；BAD = 0xFFF7；低于 0xFFF0 都当有效指针
		if raw >= 0xFFF8 {
			return 0x0FFFFFFF, nil // 统一成 FAT32 EOC
		}
		if raw == 0xFFF7 {
			return 0x0FFFFFF7, nil // 统一成 FAT32 BAD
		}
		return raw, nil

	case TypeFAT12:
		// 1.5 字节每条目：byte offset = cluster * 3 / 2
		off := int64(cluster) * 3 / 2
		buf := make([]byte, 2)
		_, err := reader.ReadAt(buf, fatStart+off)
		if err != nil {
			return 0, err
		}
		val := uint32(binary.LittleEndian.Uint16(buf))
		if cluster&1 == 1 {
			val >>= 4
		} else {
			val &= 0x0FFF
		}
		if val >= 0xFF8 {
			return 0x0FFFFFFF, nil
		}
		if val == 0xFF7 {
			return 0x0FFFFFF7, nil
		}
		return val, nil

	default:
		return 0, fmt.Errorf("未知 FAT 类型")
	}
}

// FatEntryEOC / FatEntryBad 是统一的 "End Of Chain" / "BAD" 判定值（FAT32 宽度）
const (
	FatEntryEOC uint32 = 0x0FFFFFFF
	FatEntryBad uint32 = 0x0FFFFFF7
)

// FollowFATChain 沿 FAT 链走，返回完整 cluster 列表。
// 和 exfat.FollowFATChain 同思路：环检测 / 长度上限 / 越界校验 / BAD 视为链终止。
func FollowFATChain(
	reader disk.DiskReader,
	bs *BootSector,
	partitionOffset int64,
	firstCluster uint32,
) ([]uint32, error) {
	if firstCluster < 2 {
		return nil, fmt.Errorf("firstCluster %d 无效", firstCluster)
	}
	maxLen := int(bs.ClusterCount) + 2
	if maxLen <= 0 || maxLen > 8_000_000 {
		maxLen = 8_000_000
	}

	visited := make(map[uint32]bool, 64)
	chain := make([]uint32, 0, 64)
	current := firstCluster
	for i := 0; i < maxLen; i++ {
		if current < 2 || uint64(current) >= uint64(bs.ClusterCount)+2 {
			return chain, fmt.Errorf("FAT 链越界 cluster=%d (i=%d)", current, i)
		}
		if visited[current] {
			return chain, fmt.Errorf("FAT 链检测到环 @cluster=%d", current)
		}
		visited[current] = true
		chain = append(chain, current)

		next, err := ReadFATEntry(reader, bs, partitionOffset, current)
		if err != nil {
			return chain, err
		}
		if next == FatEntryEOC {
			return chain, nil
		}
		if next == FatEntryBad {
			return chain, fmt.Errorf("FAT 链在 cluster=%d 遇到 BAD", current)
		}
		current = next
	}
	return chain, fmt.Errorf("FAT 链超过长度上限 %d", maxLen)
}

// FileClusterList 根据 entry 给出完整 cluster 列表（已截断到 fileSize 所需数量）。
// FAT 家族没有 exFAT 那种"NoFatChain"标志——任何文件都要走 FAT 链。
func FileClusterList(
	reader disk.DiskReader,
	bs *BootSector,
	partitionOffset int64,
	entry *DirEntry,
) ([]uint32, error) {
	if entry == nil || entry.FirstCluster < 2 {
		return nil, fmt.Errorf("firstCluster 无效: %d", entry.FirstCluster)
	}
	if entry.FileSize <= 0 {
		return nil, fmt.Errorf("FileSize=0 的文件无法恢复")
	}
	needed := (entry.FileSize + int64(bs.ClusterSize) - 1) / int64(bs.ClusterSize)

	// 已删除文件的 FAT 链基本会被清零 —— 这是 FAT 家族比 exFAT 更残酷的地方，
	// 因为 FAT 对"删除"动作比 exFAT 更彻底（把 FAT 条目链路整个清 0）。
	// 策略：先尝试走 FAT 链；如果第一步就拿到 0（free），退化成"连续假设"：
	// 按 firstCluster 往后数 needed 个 cluster，赌文件是连续写入。
	//
	// 这与 R-Studio / DMDE 的启发相似：对已删 FAT 文件，连续恢复 + 签名验证是主力路径。
	chain, err := FollowFATChain(reader, bs, partitionOffset, entry.FirstCluster)
	if err != nil && len(chain) == 0 {
		// 完全走不下去，退化成连续假设
		chain = []uint32{entry.FirstCluster}
	}
	if int64(len(chain)) < needed {
		// 链太短：补齐连续 cluster（典型"已删"情况）
		for i := int64(len(chain)); i < needed; i++ {
			c := entry.FirstCluster + uint32(i)
			if uint64(c) >= uint64(bs.ClusterCount)+2 {
				break
			}
			chain = append(chain, c)
		}
	}
	if int64(len(chain)) > needed {
		chain = chain[:needed]
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("构造 cluster 列表失败")
	}
	return chain, nil
}
