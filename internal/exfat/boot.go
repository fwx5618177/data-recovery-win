// Package exfat 实现 exFAT（Extended File Allocation Table）文件系统的只读解析，
// 用于从 U 盘 / SD 卡 / 大容量移动硬盘 恢复已删除文件。
//
// 为什么需要 exFAT：
//   - NTFS 是 Windows 内置盘的主流，但所有 U 盘 / SD 卡 / 相机存储卡几乎都是 exFAT
//   - 这个项目之前完全不支持 exFAT，等于对外接存储设备"失明"
//   - exFAT 规范公开、结构简洁，比 FAT32 更现代（64 位 cluster / 元数据更规整）
//
// 本实现的边界（诚实列出，避免误导）：
//   ✅ 读 boot sector、根目录、子目录（含已删除条目）
//   ✅ 按 UTF-16 拼接多段 FileName 条目得到完整文件名
//   ✅ 连续存储文件（NoFatChain=1）的恢复
//   ⚠️ 碎片文件（NoFatChain=0，需要走 FAT 链）仅识别，不恢复 —— 建议用 R-Studio
//   ⚠️ Allocation Bitmap 没做；已删除簇是否被覆写靠"从 cluster 读到什么就是什么"
//   ⚠️ UP-case table 没做；文件名大小写匹配不区分（但显示原样保留）
//   ❌ 文件系统检查 / 修复 / VBR 备份回滚（非本项目范围）
package exfat

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// exFATSignature 是 OEM ID 字段（偏移 3-10，共 8 字节）应有的值
const exFATSignature = "EXFAT   "

// BootSector 解析后的 exFAT 引导扇区关键字段。
//
// 字段命名与官方规范（Microsoft Extensible File Allocation Table
// File System Specification）保持一致，便于查文档。
type BootSector struct {
	// 从磁盘直接读出的字段
	PartitionOffset              int64  // 分区起始的绝对扇区号（512 字节扇区计）
	VolumeLength                 int64  // 分区总扇区数
	FatOffset                    uint32 // FAT 起始扇区（相对分区起点）
	FatLength                    uint32 // 每个 FAT 的扇区数
	ClusterHeapOffset            uint32 // 簇堆起始扇区（相对分区起点）
	ClusterCount                 uint32 // 簇总数
	FirstClusterOfRootDirectory  uint32 // 根目录起始簇号（通常 ≥ 2）
	BytesPerSectorShift          uint8  // 2^N 字节/扇区，N 在 [9, 12]（512-4096）
	SectorsPerClusterShift       uint8  // 2^N 扇区/簇
	NumberOfFats                 uint8  // FAT 数（1 或 2）

	// 计算字段
	BytesPerSector   int64 // = 1 << BytesPerSectorShift
	SectorsPerCluster int64 // = 1 << SectorsPerClusterShift
	ClusterSize       int64 // = BytesPerSector * SectorsPerCluster
}

// ParseBootSector 从磁盘读取并解析 exFAT 引导扇区。
// offset 是分区在磁盘上的起始字节偏移（对整盘扫描来说常为 0 或分区表给出的起点）。
func ParseBootSector(reader disk.DiskReader, offset int64) (*BootSector, error) {
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取 exFAT 引导扇区失败: %w", err)
	}
	if n < 512 {
		return nil, fmt.Errorf("引导扇区数据不足: %d 字节", n)
	}

	// 校验 OEM ID（偏移 3-10）
	if string(buf[3:11]) != exFATSignature {
		return nil, fmt.Errorf("非 exFAT 分区: OEM ID=%q", string(buf[3:11]))
	}

	// 校验 boot signature 0xAA55（偏移 510-511）
	if bootSig := binary.LittleEndian.Uint16(buf[510:512]); bootSig != 0xAA55 {
		return nil, fmt.Errorf("引导签名错: 0x%04X", bootSig)
	}

	bs := &BootSector{
		PartitionOffset:             int64(binary.LittleEndian.Uint64(buf[64:72])) * 512,
		VolumeLength:                int64(binary.LittleEndian.Uint64(buf[72:80])),
		FatOffset:                   binary.LittleEndian.Uint32(buf[80:84]),
		FatLength:                   binary.LittleEndian.Uint32(buf[84:88]),
		ClusterHeapOffset:           binary.LittleEndian.Uint32(buf[88:92]),
		ClusterCount:                binary.LittleEndian.Uint32(buf[92:96]),
		FirstClusterOfRootDirectory: binary.LittleEndian.Uint32(buf[96:100]),
		BytesPerSectorShift:         buf[108],
		SectorsPerClusterShift:      buf[109],
		NumberOfFats:                buf[110],
	}

	// 合理性校验
	if bs.BytesPerSectorShift < 9 || bs.BytesPerSectorShift > 12 {
		return nil, fmt.Errorf("异常的 BytesPerSectorShift: %d", bs.BytesPerSectorShift)
	}
	if bs.SectorsPerClusterShift > 25 { // cluster size 上限 32MB（2^25 * 512）
		return nil, fmt.Errorf("异常的 SectorsPerClusterShift: %d", bs.SectorsPerClusterShift)
	}
	if bs.NumberOfFats != 1 && bs.NumberOfFats != 2 {
		return nil, fmt.Errorf("异常的 NumberOfFats: %d", bs.NumberOfFats)
	}
	if bs.FirstClusterOfRootDirectory < 2 {
		return nil, fmt.Errorf("根目录起始簇号无效: %d", bs.FirstClusterOfRootDirectory)
	}

	bs.BytesPerSector = int64(1) << bs.BytesPerSectorShift
	bs.SectorsPerCluster = int64(1) << bs.SectorsPerClusterShift
	bs.ClusterSize = bs.BytesPerSector * bs.SectorsPerCluster

	return bs, nil
}

// ClusterToByteOffset 计算给定簇号在磁盘上的绝对字节偏移。
// 参数 partitionOffset 是分区起点（字节），供整盘扫描时定位。
// exFAT 的簇编号从 2 开始；2 = 簇堆第一个。
func (bs *BootSector) ClusterToByteOffset(cluster uint32, partitionOffset int64) int64 {
	if cluster < 2 {
		return -1
	}
	clusterInHeap := int64(cluster - 2)
	return partitionOffset +
		int64(bs.ClusterHeapOffset)*bs.BytesPerSector +
		clusterInHeap*bs.ClusterSize
}

// FatByteOffset 返回第一个 FAT 的绝对字节偏移（FAT 链解析时用到）。
func (bs *BootSector) FatByteOffset(partitionOffset int64) int64 {
	return partitionOffset + int64(bs.FatOffset)*bs.BytesPerSector
}
