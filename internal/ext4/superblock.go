// Package ext4 实现 ext2 / ext3 / ext4 文件系统的只读读取，用于从 Linux / Android
// 设备上恢复被删除的文件。
//
// 三个版本共享相同的"超块 + 块组描述符 + 索引节点 + 目录项"骨架，区别是：
//
//   - ext2: 数据指针走 indirect block（间接块），不带 journal
//   - ext3: 同 ext2 + journal（我们只读，journal 不参与）
//   - ext4: 数据指针默认走 extent tree（更高效），保留 indirect 兼容；可选大目录 htree
//
// 本实现路径：superblock 检测 → 列举所有块组 → 按 inode 号读 inode → 走 extent
// 或 indirect 取出文件数据块 → 目录项遍历做文件名/路径恢复。
//
// 已删除文件恢复：ext 系列在 unlink 时会清掉目录项的 inode 字段（把 inode 标记为
// 自由）和 inode 内的某些字段（链接计数清 0）。但**数据块本身**通常**不立刻清零**，
// 我们仍能通过 inode 表里的旧记录拿到数据块号 —— 只要 inode 还没被复用。
//
// 参考：Ext4 (and Ext2/Ext3) Wiki (kernel.org)。
package ext4

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// ext 超块固定在卷起点偏移 1024（无论块大小）。
// 这是 ext 文件系统设计的"刻字"，跨 ext2/3/4 都一样。
const superblockOffset = 1024

// 超块魔术：0xEF53（little-endian 存储为 53 EF）
const ext2Magic uint16 = 0xEF53

// 文件系统类型（用于 UI 显示）
type Variant int

const (
	VariantUnknown Variant = iota
	VariantEXT2
	VariantEXT3
	VariantEXT4
)

func (v Variant) String() string {
	switch v {
	case VariantEXT2:
		return "ext2"
	case VariantEXT3:
		return "ext3"
	case VariantEXT4:
		return "ext4"
	}
	return "ext-unknown"
}

// 超块字段偏移（按 ext4 spec；部分字段在 ext2 不存在）
const (
	sbInodesCount         = 0x00 // uint32
	sbBlocksCount         = 0x04 // uint32 (低 32 位)
	sbFreeBlocksCount     = 0x0C
	sbFreeInodesCount     = 0x10
	sbFirstDataBlock      = 0x14 // uint32
	sbLogBlockSize        = 0x18 // uint32, block_size = 1024 << log_block_size
	sbBlocksPerGroup      = 0x20 // uint32
	sbInodesPerGroup      = 0x28 // uint32
	sbMagic               = 0x38 // uint16
	sbState               = 0x3A
	sbRevLevel            = 0x4C // uint32 (0=ext2 original, 1=ext2 dynamic / ext3/4)
	sbFirstInode          = 0x54 // uint32 (revs >= 1)
	sbInodeSize           = 0x58 // uint16 (revs >= 1)
	sbFeatureCompat       = 0x5C // uint32
	sbFeatureIncompat     = 0x60 // uint32
	sbFeatureROCompat     = 0x64 // uint32
	sbUUID                = 0x68 // 16 bytes
	sbVolumeName          = 0x78 // 16 bytes
	sbBlocksCountHi       = 0x150 // uint32 (ext4 64bit feature)
	sbDescSize            = 0xFE  // uint16 (group descriptor size; ext4 64bit feature)
)

// FEATURE_INCOMPAT 标志位（用于判断 ext2/ext3/ext4）
const (
	incompatExtents = 0x0040 // 文件用 extent tree 而不是 indirect blocks（ext4 专属）
	incompat64bit   = 0x0080 // 64 位块号（ext4 特性）
)

// FEATURE_COMPAT 标志位
const (
	compatHasJournal = 0x0004 // 有 journal => ext3 或 ext4（ext2 没 journal）
)

// SuperBlock 解析后的 ext 超块
type SuperBlock struct {
	Variant           Variant
	BlockSize         int64  // 字节
	InodesCount       uint32 // 总 inode 数
	BlocksCount       uint64 // 总块数（拼合 32+32 位）
	FreeBlocksCount   uint32
	FreeInodesCount   uint32
	FirstDataBlock    uint32 // 块大小 ≤4KB 时一般是 1，块大小 ≥8KB 时是 0
	BlocksPerGroup    uint32
	InodesPerGroup    uint32
	FirstInode        uint32 // rev0 = 11 (固定)；rev1+ 用此字段
	InodeSize         uint16 // 一个 inode 字节数（rev0 = 128；ext3/4 默认 256）
	UUID              [16]byte
	VolumeName        string

	// extent / 64-bit 等特性标志位
	FeatureIncompat uint32
	FeatureCompat   uint32

	// 块组描述符大小（ext2/3 = 32；ext4 + 64bit feature = 64）
	GroupDescSize int

	// 计算字段
	GroupCount         uint64 // = ceil(BlocksCount / BlocksPerGroup)
	GroupDescBlock     uint64 // 紧跟超块所在块的下一块
	HasExtents         bool   // ext4 默认 true
	Has64Bit           bool
	PartitionOffset    int64
}

// ParseSuperblock 在分区 partitionOffset 处读取并解析 ext 超块。
// 返回 nil + 自定义错误意味着"不是合法 ext 文件系统"；其他错误是 IO 类。
func ParseSuperblock(reader disk.DiskReader, partitionOffset int64) (*SuperBlock, error) {
	buf := make([]byte, 1024)
	n, err := reader.ReadAt(buf, partitionOffset+superblockOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 ext 超块失败: %w", err)
	}
	if n < 0x200 {
		return nil, fmt.Errorf("ext 超块数据不足: %d 字节", n)
	}

	magic := binary.LittleEndian.Uint16(buf[sbMagic : sbMagic+2])
	if magic != ext2Magic {
		return nil, fmt.Errorf("非 ext 文件系统: magic=0x%04X", magic)
	}

	sb := &SuperBlock{
		PartitionOffset: partitionOffset,
		InodesCount:     binary.LittleEndian.Uint32(buf[sbInodesCount : sbInodesCount+4]),
		FreeBlocksCount: binary.LittleEndian.Uint32(buf[sbFreeBlocksCount : sbFreeBlocksCount+4]),
		FreeInodesCount: binary.LittleEndian.Uint32(buf[sbFreeInodesCount : sbFreeInodesCount+4]),
		FirstDataBlock:  binary.LittleEndian.Uint32(buf[sbFirstDataBlock : sbFirstDataBlock+4]),
		BlocksPerGroup:  binary.LittleEndian.Uint32(buf[sbBlocksPerGroup : sbBlocksPerGroup+4]),
		InodesPerGroup:  binary.LittleEndian.Uint32(buf[sbInodesPerGroup : sbInodesPerGroup+4]),
	}
	logBlockSize := binary.LittleEndian.Uint32(buf[sbLogBlockSize : sbLogBlockSize+4])
	if logBlockSize > 16 {
		return nil, fmt.Errorf("异常 log_block_size=%d", logBlockSize)
	}
	sb.BlockSize = int64(1024) << logBlockSize

	// 块数（低 32 位 + 高 32 位 if 64bit feature）
	blocksLo := binary.LittleEndian.Uint32(buf[sbBlocksCount : sbBlocksCount+4])
	sb.BlocksCount = uint64(blocksLo)

	// 修订级别 / inode size / 特性标志（仅 rev1+ 有效）
	revLevel := binary.LittleEndian.Uint32(buf[sbRevLevel : sbRevLevel+4])
	if revLevel >= 1 {
		sb.FirstInode = binary.LittleEndian.Uint32(buf[sbFirstInode : sbFirstInode+4])
		sb.InodeSize = binary.LittleEndian.Uint16(buf[sbInodeSize : sbInodeSize+2])
		sb.FeatureCompat = binary.LittleEndian.Uint32(buf[sbFeatureCompat : sbFeatureCompat+4])
		sb.FeatureIncompat = binary.LittleEndian.Uint32(buf[sbFeatureIncompat : sbFeatureIncompat+4])

		copy(sb.UUID[:], buf[sbUUID:sbUUID+16])
		// 卷名：UTF-8，NUL-terminated，16 字节
		raw := buf[sbVolumeName : sbVolumeName+16]
		end := 0
		for end < len(raw) && raw[end] != 0 {
			end++
		}
		sb.VolumeName = string(raw[:end])
	} else {
		sb.FirstInode = 11
		sb.InodeSize = 128
	}

	// 64-bit 特性 → 拼上块数高位 + 用更大的 group desc
	sb.Has64Bit = sb.FeatureIncompat&incompat64bit != 0
	if sb.Has64Bit && len(buf) >= sbBlocksCountHi+4 {
		blocksHi := binary.LittleEndian.Uint32(buf[sbBlocksCountHi : sbBlocksCountHi+4])
		sb.BlocksCount |= uint64(blocksHi) << 32
		descSize := binary.LittleEndian.Uint16(buf[sbDescSize : sbDescSize+2])
		if descSize > 0 {
			sb.GroupDescSize = int(descSize)
		}
	}
	if sb.GroupDescSize == 0 {
		sb.GroupDescSize = 32 // ext2/3 + ext4 不开 64bit 时
	}

	sb.HasExtents = sb.FeatureIncompat&incompatExtents != 0

	// 推断 variant
	switch {
	case sb.HasExtents:
		sb.Variant = VariantEXT4
	case sb.FeatureCompat&compatHasJournal != 0:
		sb.Variant = VariantEXT3
	default:
		sb.Variant = VariantEXT2
	}

	// 合理性
	if sb.BlocksPerGroup == 0 || sb.InodesPerGroup == 0 || sb.BlockSize < 1024 {
		return nil, fmt.Errorf("超块字段异常 BlockSize=%d BPG=%d IPG=%d", sb.BlockSize, sb.BlocksPerGroup, sb.InodesPerGroup)
	}

	sb.GroupCount = (sb.BlocksCount + uint64(sb.BlocksPerGroup) - 1) / uint64(sb.BlocksPerGroup)
	// 块组描述符块在超块所在块的下一块（块大小 1024 时超块在 block 1，描述符表在 block 2）
	if sb.BlockSize == 1024 {
		sb.GroupDescBlock = 2
	} else {
		sb.GroupDescBlock = 1
	}

	return sb, nil
}

// BlockToByteOffset 把块号换算成磁盘绝对字节偏移
func (sb *SuperBlock) BlockToByteOffset(block uint64) int64 {
	return sb.PartitionOffset + int64(block)*sb.BlockSize
}
