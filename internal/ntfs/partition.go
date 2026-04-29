package ntfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// ProgressFn 是分区发现阶段的进度回调；scanned 已扫描字节数，total 磁盘总字节数。
// 调用方 (recovery dispatcher) 把它包装成 types.ScanProgress 喂给前端。
type ProgressFn = func(scanned, total int64)

// FindOptions 控制 FindPartitions 的执行策略。
//
// 默认 BruteForce=false：跑 MBR + GPT fast path（毫秒级），找到分区即返回。
//
// BruteForce=true：在 fast path 之外**额外**全盘扫 "NTFS    " OEM ID 找已删除/孤立的
// 旧 NTFS 分区残骸。**这是被盗笔记本数据恢复的核心场景**：原盘被重装系统 → 新分区表只
// 有当前系统分区，但旧 NTFS boot sector 还在磁盘上 → brute-force 能定位到然后救数据。
// 这也正是司法取证的一环。代价 = 1 次全盘 IO。
type FindOptions struct {
	OnProgress ProgressFn
	BruteForce bool
}

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

// FindPartitions 扫描磁盘查找 NTFS 分区（包括已被删除的旧分区）
//
// 搜索策略：**三条通路都跑**，因为被盗笔记本重装 Windows 后常见的情形是：
//   1. 分区表是新装 Windows 创建的 → MBR/GPT 里只有当前系统分区
//   2. 旧系统的 NTFS 分区引导扇区**仍然在磁盘上**（只是分区表条目没了）
//   3. 暴力扫能找到这些旧 NTFS 残骸，里面的 MFT 仍可能指向原主人的用户数据
//
// R-Studio / DMDE 的 "deleted partition scan" 就是这个思路；dedupePartitions 负责把
// MBR/GPT 已登记的分区去掉重复，留下孤立的旧 NTFS 残骸。
//
// 策略（v2.8.8+ 修订）：
//   - **MBR + GPT** 永远跑（毫秒级，零成本）
//   - **brute-force** 仅在 opts.BruteForce=true 时跑（取证模式专用，125GB 盘 ≈ 1h IO）
//
// 关键决策：之前注释写的"行业惯例分区表+签名扫双保险" —— 错的。R-Studio / DMDE 的双保险
// 是 **opt-in** 的 "Full scan" / "Deleted partition recovery"，不是默认。默认 (Quick scan)
// 只跑 MBR/GPT。把 brute-force 默认关上是 v2.8.8 的核心架构修复 —— 之前 v2.8.7 之前的
// 实现导致用户扫 125GB U 盘要 14 小时（3 次全盘读叠加坏扇区重试地狱）。
func (s *Scanner) FindPartitions(ctx context.Context, opts FindOptions) ([]Partition, error) {
	var partitions []Partition

	// ---- 策略 a: MBR（fast path）----
	mbrPartitions, mbrErr := s.findMBRPartitions()
	if mbrErr == nil && len(mbrPartitions) > 0 {
		partitions = append(partitions, mbrPartitions...)
	}

	// ---- 策略 b: GPT（fast path）----
	gptPartitions, gptErr := s.findGPTPartitions(ctx)
	if gptErr == nil && len(gptPartitions) > 0 {
		partitions = append(partitions, gptPartitions...)
	}

	// ---- 策略 c: 暴力搜索 NTFS 引导扇区（仅取证模式）----
	// 找 MBR/GPT 没登记但磁盘上还存在的旧 NTFS 分区残骸。
	// 这是被盗笔记本被重装系统后救回原数据的关键路径 —— 但默认不跑，让用户显式选 forensic 模式。
	var bruteErr error
	if opts.BruteForce {
		brutePartitions, err := s.bruteForceFindNTFS(ctx, opts.OnProgress)
		bruteErr = err
		if err == nil && len(brutePartitions) > 0 {
			partitions = append(partitions, brutePartitions...)
		}
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
		return nil, errors.New(errMsg)
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

// bruteForceFindNTFS 暴力搜索 NTFS 引导扇区签名，定位已删除 / 孤立的 NTFS 分区。
//
// 优化：每次读 4MB 一大块，在内存里按 512KB 步进扫描候选位置。
// 相比之前每 1MB 一个 512B 小读，大盘上 IO 次数减少 ~8000x（1TB 盘 1M 次→250 次）。
//
// NTFS 分区起始基本都在 1MB 边界对齐（Windows Vista+ 的默认），
// 但我们用 512KB 步进保留一些历史老盘（XP 时代 63 扇区对齐）的容错空间。
//
// onProgress 每 ~500ms 节流回调；nil 时静默扫描。
func (s *Scanner) bruteForceFindNTFS(ctx context.Context, onProgress ProgressFn) ([]Partition, error) {
	diskSize, err := s.reader.Size()
	if err != nil {
		return nil, fmt.Errorf("获取磁盘大小失败: %w", err)
	}

	const (
		readBlockSize int64 = 4 * 1024 * 1024 // 每次读 4MB
		stepSize      int64 = 512 * 1024      // 512KB 步进
	)

	var partitions []Partition
	buf := make([]byte, readBlockSize)

	const progressEmitInterval = 500 * time.Millisecond
	lastEmit := time.Now()

	for blockOffset := int64(0); blockOffset < diskSize; blockOffset += readBlockSize {
		select {
		case <-ctx.Done():
			return partitions, ctx.Err()
		default:
		}

		readSize := readBlockSize
		if blockOffset+readSize > diskSize {
			readSize = diskSize - blockOffset
		}
		nr, readErr := s.reader.ReadAt(buf[:readSize], blockOffset)
		if readErr != nil && readErr != io.EOF {
			continue
		}
		if nr < 512 {
			continue
		}

		// 在本块内按 stepSize 步进，检查每个候选位置的 NTFS OEM ID（偏移 0x03-0x0B = "NTFS    "）
		for in := int64(0); in+512 <= int64(nr); in += stepSize {
			if string(buf[in+0x03:in+0x0B]) != ntfsSignature {
				continue
			}
			absOffset := blockOffset + in

			// OEM ID 匹配后做完整引导扇区解析 + 几何合理性校验
			bootSector, bsErr := s.ParseBootSector(absOffset)
			if bsErr != nil {
				continue
			}

			// 估算分区大小
			partSize := bootSector.TotalSectors * int64(bootSector.BytesPerSector)
			if partSize <= 0 {
				partSize = diskSize - absOffset
			}

			partitions = append(partitions, Partition{
				Offset:     absOffset,
				Size:       partSize,
				Type:       "bruteforce",
				BootSector: bootSector,
			})
		}

		if onProgress != nil && time.Since(lastEmit) >= progressEmitInterval {
			onProgress(blockOffset+readSize, diskSize)
			lastEmit = time.Now()
		}
	}
	if onProgress != nil {
		onProgress(diskSize, diskSize)
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
