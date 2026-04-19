package ntfs

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// ========== 分区表解析 ==========
//
// NTFS 工具在面对整盘（\\.\PhysicalDrive0 或 /dev/diskN）时需要先定位其上的
// NTFS 分区。顺序：
//   1. 解析 MBR 分区表（常见但限 4 主分区、< 2TB）
//   2. 解析 GPT 分区表（UEFI 主流）
//   3. 若前两步都找不到（分区表损坏/重置），按 1MB 步进暴力搜索 NTFS 引导扇区
//
// 常见的 MBR 签名与 GPT 相关常量也集中在这里。

const (
	mbrSignature      uint16 = 0xAA55
	mbrPartTableStart        = 0x1BE
	mbrPartEntrySize         = 16
	mbrPartCount             = 4
	ntfsPartType      byte   = 0x07

	gptHeaderSignature = "EFI PART"
)

// Partition NTFS 分区信息
type Partition struct {
	Offset     int64       // 分区起始偏移（字节）
	Size       int64       // 分区大小（字节）
	Type       string      // 分区类型描述（"MBR"/"GPT"/"bruteforce"）
	BootSector *BootSector // 解析后的引导扇区
}

// FindPartitions 扫描磁盘查找 NTFS 分区
//
// 搜索策略:
//  1. 检查 MBR 分区表
//  2. 检查 GPT 分区表
//  3. 如果前两者都没有找到有效分区，进行暴力搜索
func (s *Scanner) FindPartitions(ctx context.Context) ([]Partition, error) {
	var partitions []Partition

	// ---- 策略 a: 检查 MBR ----
	mbrPartitions, mbrErr := s.findMBRPartitions()
	if mbrErr == nil && len(mbrPartitions) > 0 {
		partitions = append(partitions, mbrPartitions...)
	}

	// ---- 策略 b: 检查 GPT ----
	gptPartitions, gptErr := s.findGPTPartitions(ctx)
	if gptErr == nil && len(gptPartitions) > 0 {
		partitions = append(partitions, gptPartitions...)
	}

	// 如果已找到分区，直接返回
	if len(partitions) > 0 {
		return dedupePartitions(partitions), nil
	}

	// ---- 策略 c: 暴力搜索（最后手段）----
	brutePartitions, bruteErr := s.bruteForceFindNTFS(ctx)
	if bruteErr == nil && len(brutePartitions) > 0 {
		partitions = append(partitions, brutePartitions...)
	}

	if len(partitions) == 0 {
		errMsg := "未找到 NTFS 分区"
		if mbrErr != nil {
			errMsg += fmt.Sprintf("; MBR: %v", mbrErr)
		}
		if gptErr != nil {
			errMsg += fmt.Sprintf("; GPT: %v", gptErr)
		}
		if bruteErr != nil {
			errMsg += fmt.Sprintf("; 暴力搜索: %v", bruteErr)
		}
		return nil, fmt.Errorf(errMsg)
	}

	return dedupePartitions(partitions), nil
}

// findMBRPartitions 解析 MBR 分区表查找 NTFS 分区
func (s *Scanner) findMBRPartitions() ([]Partition, error) {
	buf := make([]byte, 512)
	n, err := s.reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取 MBR 失败: %w", err)
	}
	if n < 512 {
		return nil, fmt.Errorf("MBR 数据不足")
	}

	// 验证 MBR 签名（偏移 510-511: 0x55 0xAA）
	sig := binary.LittleEndian.Uint16(buf[510:512])
	if sig != mbrSignature {
		return nil, fmt.Errorf("无效 MBR 签名: 0x%04X (期望 0x%04X)", sig, mbrSignature)
	}

	var partitions []Partition

	// 解析 4 个分区表项（从 0x1BE 开始，每个 16 字节）
	for i := 0; i < mbrPartCount; i++ {
		entryOffset := mbrPartTableStart + i*mbrPartEntrySize
		if entryOffset+mbrPartEntrySize > len(buf) {
			break
		}

		partEntry := buf[entryOffset : entryOffset+mbrPartEntrySize]

		// 偏移 4: 分区类型
		partType := partEntry[4]
		if partType != ntfsPartType {
			continue
		}

		// 偏移 8: 起始 LBA (uint32 LE)
		startLBA := binary.LittleEndian.Uint32(partEntry[8:12])
		// 偏移 12: 总扇区数 (uint32 LE)
		totalSectors := binary.LittleEndian.Uint32(partEntry[12:16])

		if startLBA == 0 || totalSectors == 0 {
			continue
		}

		partOffset := int64(startLBA) * 512
		partSize := int64(totalSectors) * 512

		// 尝试解析引导扇区验证是否为有效 NTFS
		bootSector, bsErr := s.ParseBootSector(partOffset)
		if bsErr != nil {
			continue // 不是有效的 NTFS，跳过
		}

		partitions = append(partitions, Partition{
			Offset:     partOffset,
			Size:       partSize,
			Type:       "MBR",
			BootSector: bootSector,
		})
	}

	return partitions, nil
}

// findGPTPartitions 解析 GPT 分区表查找 NTFS 分区
func (s *Scanner) findGPTPartitions(ctx context.Context) ([]Partition, error) {
	// GPT header 位于 LBA 1（偏移 512）
	headerBuf := make([]byte, 512)
	n, err := s.reader.ReadAt(headerBuf, 512)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取 GPT header 失败: %w", err)
	}
	if n < 92 { // GPT header 至少需要 92 字节
		return nil, fmt.Errorf("GPT header 数据不足")
	}

	// 验证 GPT 签名 "EFI PART"（偏移 0，8字节）
	if string(headerBuf[0:8]) != gptHeaderSignature {
		return nil, fmt.Errorf("无效 GPT 签名: %q", string(headerBuf[0:8]))
	}

	// 偏移 72: 分区条目起始 LBA (uint64 LE)
	partEntryStartLBA := binary.LittleEndian.Uint64(headerBuf[72:80])
	// 偏移 80: 分区条目数量 (uint32 LE)
	partEntryCount := binary.LittleEndian.Uint32(headerBuf[80:84])
	// 偏移 84: 分区条目大小 (uint32 LE, 通常 128)
	partEntrySize := binary.LittleEndian.Uint32(headerBuf[84:88])

	if partEntrySize == 0 {
		partEntrySize = 128
	}
	if partEntryCount == 0 {
		return nil, fmt.Errorf("GPT 分区条目数量为 0")
	}
	// 合理性限制
	if partEntryCount > 512 {
		partEntryCount = 512
	}

	// Microsoft Basic Data GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
	// 注意 GUID 在磁盘上的混合字节序存储:
	// 前 4 字节 LE, 接下来 2 字节 LE, 接下来 2 字节 LE, 剩余 8 字节 BE
	msBasicDataGUID := []byte{
		0xA2, 0xA0, 0xD0, 0xEB, // EBD0A0A2 (LE)
		0xE5, 0xB9, // B9E5 (LE)
		0x33, 0x44, // 4433 (LE)
		0x87, 0xC0, // 87C0 (BE)
		0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7, // 68B6B72699C7 (BE)
	}

	var partitions []Partition
	partTableOffset := int64(partEntryStartLBA) * 512

	for i := uint32(0); i < partEntryCount; i++ {
		select {
		case <-ctx.Done():
			return partitions, ctx.Err()
		default:
		}

		entryOffset := partTableOffset + int64(i)*int64(partEntrySize)
		entryBuf := make([]byte, partEntrySize)
		nr, readErr := s.reader.ReadAt(entryBuf, entryOffset)
		if readErr != nil && readErr != io.EOF {
			continue
		}
		if uint32(nr) < partEntrySize {
			continue
		}

		// 偏移 0: 分区类型 GUID (16字节)
		typeGUID := entryBuf[0:16]

		// 检查是否为空条目（全零 GUID 表示未使用）
		allZero := true
		for _, b := range typeGUID {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}

		// 检查是否为 Microsoft Basic Data 分区
		if !guidEqual(typeGUID, msBasicDataGUID) {
			continue
		}

		// 偏移 32: 起始 LBA (uint64 LE)
		startLBA := binary.LittleEndian.Uint64(entryBuf[32:40])
		// 偏移 40: 结束 LBA (uint64 LE, 包含)
		endLBA := binary.LittleEndian.Uint64(entryBuf[40:48])

		if startLBA == 0 || endLBA <= startLBA {
			continue
		}

		partOffset := int64(startLBA) * 512
		partSize := int64(endLBA-startLBA+1) * 512

		// 尝试解析引导扇区验证是否为有效 NTFS
		bootSector, bsErr := s.ParseBootSector(partOffset)
		if bsErr != nil {
			continue
		}

		partitions = append(partitions, Partition{
			Offset:     partOffset,
			Size:       partSize,
			Type:       "GPT",
			BootSector: bootSector,
		})
	}

	return partitions, nil
}

// bruteForceFindNTFS 暴力搜索 NTFS 签名（最后手段）
func (s *Scanner) bruteForceFindNTFS(ctx context.Context) ([]Partition, error) {
	diskSize, err := s.reader.Size()
	if err != nil {
		return nil, fmt.Errorf("获取磁盘大小失败: %w", err)
	}

	var partitions []Partition

	// 每 1MB 步进搜索（NTFS 分区通常在 MB 边界对齐）
	const stepSize int64 = 1024 * 1024 // 1MB
	searchBuf := make([]byte, 512)

	for offset := int64(0); offset < diskSize; offset += stepSize {
		select {
		case <-ctx.Done():
			return partitions, ctx.Err()
		default:
		}

		nr, readErr := s.reader.ReadAt(searchBuf, offset)
		if readErr != nil && readErr != io.EOF {
			continue
		}
		if nr < 512 {
			continue
		}

		// 快速检查 OEM ID
		if string(searchBuf[0x03:0x0B]) != ntfsSignature {
			continue
		}

		// 找到可能的 NTFS 签名，尝试完整解析
		bootSector, bsErr := s.ParseBootSector(offset)
		if bsErr != nil {
			continue
		}

		// 估算分区大小
		partSize := bootSector.TotalSectors * int64(bootSector.BytesPerSector)
		if partSize <= 0 {
			partSize = diskSize - offset
		}

		partitions = append(partitions, Partition{
			Offset:     offset,
			Size:       partSize,
			Type:       "bruteforce",
			BootSector: bootSector,
		})
	}

	return partitions, nil
}

func dedupePartitions(partitions []Partition) []Partition {
	if len(partitions) <= 1 {
		return partitions
	}

	sort.Slice(partitions, func(i, j int) bool {
		return partitions[i].Offset < partitions[j].Offset
	})

	deduped := make([]Partition, 0, len(partitions))
	seen := make(map[int64]struct{}, len(partitions))
	for _, partition := range partitions {
		if _, exists := seen[partition.Offset]; exists {
			continue
		}
		seen[partition.Offset] = struct{}{}
		deduped = append(deduped, partition)
	}

	return deduped
}

// guidEqual 比较两个 16 字节 GUID 是否相等
func guidEqual(a, b []byte) bool {
	if len(a) < 16 || len(b) < 16 {
		return false
	}
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
