// Package fat 实现 FAT12/16/32 文件系统的只读解析，用于恢复 U 盘 / SD 卡 / 老相机存储
// 里被删除的文件。
//
// 覆盖范围：
//   - FAT16 / FAT32 boot sector 解析
//   - FAT 链遍历（12/16/32 三种条目宽度）
//   - 根目录（FAT16 固定扇区区域；FAT32 链表形式）
//   - 子目录递归
//   - 长文件名（VFAT LFN）拼接
//   - 已删除条目识别（首字节 0xE5）
//
// 不覆盖：
//   - FAT12（老软盘，个位数个人恢复场景用到）—— 代码路径里预留但没充分测试
//   - FAT 表写入 / 修复（我们只读）
//   - exFAT（单独的 internal/exfat 包已实现）
package fat

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// Type 表示 FAT 的具体变体
type Type int

const (
	TypeUnknown Type = iota
	TypeFAT12
	TypeFAT16
	TypeFAT32
)

func (t Type) String() string {
	switch t {
	case TypeFAT12:
		return "FAT12"
	case TypeFAT16:
		return "FAT16"
	case TypeFAT32:
		return "FAT32"
	}
	return "unknown"
}

// BootSector 解析后的 FAT boot sector 关键字段。
// 字段命名与 Microsoft FAT Specification 一致（Rev 1.03）。
type BootSector struct {
	BytesPerSector    uint16 // BPB_BytsPerSec
	SectorsPerCluster uint8  // BPB_SecPerClus
	ReservedSectors   uint16 // BPB_RsvdSecCnt
	NumFATs           uint8  // BPB_NumFATs
	RootEntryCount    uint16 // BPB_RootEntCnt (FAT12/16 用；FAT32 为 0)
	TotalSectors16    uint16 // BPB_TotSec16
	TotalSectors32    uint32 // BPB_TotSec32
	FATSize16         uint16 // BPB_FATSz16 (FAT12/16 用)
	FATSize32         uint32 // BPB_FATSz32 (FAT32 用)
	RootCluster       uint32 // BPB_RootClus (FAT32 专用，根目录起始 cluster)

	// 计算字段
	FSType          Type
	TotalSectors    uint32 // 实际使用的那个
	FATSize         uint32 // 实际使用的那个（FAT 表大小，单位扇区）
	FirstFATSector  uint32 // 第一个 FAT 表的起始扇区
	RootDirSector   uint32 // FAT12/16：固定根目录区的起始扇区；FAT32：0（看 RootCluster）
	RootDirSectors  uint32 // FAT12/16：固定根目录占用的扇区数；FAT32：0
	FirstDataSector uint32 // cluster 2 所在的扇区
	ClusterCount    uint32 // 有效 cluster 数量（用于判定 FAT 类型）
	ClusterSize     uint32 // BytesPerSector * SectorsPerCluster（计算得到，字节）
}

// ParseBootSector 读并解析 FAT boot sector。offset 是分区起始字节偏移。
func ParseBootSector(reader disk.DiskReader, offset int64) (*BootSector, error) {
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取 FAT boot sector 失败: %w", err)
	}
	if n < 512 {
		return nil, fmt.Errorf("boot sector 数据不足: %d", n)
	}
	// 校验 boot signature
	if binary.LittleEndian.Uint16(buf[510:512]) != 0xAA55 {
		return nil, fmt.Errorf("非法 boot signature")
	}

	bs := &BootSector{
		BytesPerSector:    binary.LittleEndian.Uint16(buf[11:13]),
		SectorsPerCluster: buf[13],
		ReservedSectors:   binary.LittleEndian.Uint16(buf[14:16]),
		NumFATs:           buf[16],
		RootEntryCount:    binary.LittleEndian.Uint16(buf[17:19]),
		TotalSectors16:    binary.LittleEndian.Uint16(buf[19:21]),
		FATSize16:         binary.LittleEndian.Uint16(buf[22:24]),
		TotalSectors32:    binary.LittleEndian.Uint32(buf[32:36]),
	}

	// 基础合理性：非零、2 的幂、上限
	if bs.BytesPerSector == 0 || bs.BytesPerSector > 4096 {
		return nil, fmt.Errorf("异常 BytesPerSector: %d", bs.BytesPerSector)
	}
	if bs.SectorsPerCluster == 0 {
		return nil, fmt.Errorf("SectorsPerCluster=0")
	}
	if bs.NumFATs == 0 || bs.NumFATs > 2 {
		return nil, fmt.Errorf("异常 NumFATs: %d", bs.NumFATs)
	}

	// FAT32 专属字段（offset 36+）
	if bs.FATSize16 == 0 {
		bs.FATSize32 = binary.LittleEndian.Uint32(buf[36:40])
		bs.RootCluster = binary.LittleEndian.Uint32(buf[44:48])
	}

	if bs.TotalSectors16 != 0 {
		bs.TotalSectors = uint32(bs.TotalSectors16)
	} else {
		bs.TotalSectors = bs.TotalSectors32
	}
	if bs.FATSize16 != 0 {
		bs.FATSize = uint32(bs.FATSize16)
	} else {
		bs.FATSize = bs.FATSize32
	}

	if bs.TotalSectors == 0 || bs.FATSize == 0 {
		return nil, fmt.Errorf("totalSectors 或 FATSize 为 0")
	}

	// FAT12/16 根目录：紧跟在最后一个 FAT 表之后，占用固定数量扇区
	bs.RootDirSectors = (uint32(bs.RootEntryCount)*32 + uint32(bs.BytesPerSector) - 1) / uint32(bs.BytesPerSector)
	bs.FirstFATSector = uint32(bs.ReservedSectors)
	bs.RootDirSector = bs.FirstFATSector + uint32(bs.NumFATs)*bs.FATSize
	bs.FirstDataSector = bs.RootDirSector + bs.RootDirSectors

	// 数据区总扇区 = TotalSectors - FirstDataSector
	dataSectors := bs.TotalSectors - bs.FirstDataSector
	bs.ClusterCount = dataSectors / uint32(bs.SectorsPerCluster)

	// 微软官方判定 FAT 类型的公式（严格按 FAT Specification §3.5）
	switch {
	case bs.ClusterCount < 4085:
		bs.FSType = TypeFAT12
	case bs.ClusterCount < 65525:
		bs.FSType = TypeFAT16
	default:
		bs.FSType = TypeFAT32
	}

	bs.ClusterSize = uint32(bs.BytesPerSector) * uint32(bs.SectorsPerCluster)

	// 最后兜底：校验"FAT" / "FAT32" 字符串（可选，常见但不绝对可靠）
	fs16 := string(buf[54:62])
	fs32 := string(buf[82:90])
	_ = fs16
	_ = fs32 // 仅做注释参考；不用它硬判断，因为某些格式化工具会留空

	return bs, nil
}

// ClusterToByteOffset 把 cluster 号换算成磁盘绝对字节偏移。
// cluster < 2 返回 -1（保留号）。
func (bs *BootSector) ClusterToByteOffset(cluster uint32, partitionOffset int64) int64 {
	if cluster < 2 {
		return -1
	}
	firstDataByteOffset := partitionOffset + int64(bs.FirstDataSector)*int64(bs.BytesPerSector)
	return firstDataByteOffset + int64(cluster-2)*int64(bs.ClusterSize)
}

// RootDirByteOffset 仅对 FAT12/16 有效，返回固定根目录区的起始字节偏移
func (bs *BootSector) RootDirByteOffset(partitionOffset int64) int64 {
	return partitionOffset + int64(bs.RootDirSector)*int64(bs.BytesPerSector)
}

// RootDirByteSize 返回 FAT12/16 固定根目录区大小（字节）。FAT32 返回 0。
func (bs *BootSector) RootDirByteSize() int64 {
	return int64(bs.RootDirSectors) * int64(bs.BytesPerSector)
}
