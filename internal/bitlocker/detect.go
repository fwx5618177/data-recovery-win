// Package bitlocker 检测 Windows BitLocker 加密卷的存在与元数据。
//
// **重要：本实现只检测、不解密**。
//
// BitLocker 完整解密涉及：
//   - VMK (Volume Master Key) 的多种 protector：TPM、recovery password (48 位数字)、
//     password、smart card、startup key、auto-unlock 等
//   - VMK → FVEK (Full Volume Encryption Key) 的密钥链
//   - AES-XTS-128（Win 10+）/ AES-CBC + diffuser（旧版）解密
//   - sector-by-sector 解密（每扇区独立）
//
// 这是 dislocker（C，约 10k 行）/ R-Studio / DMDE 商业版才有的功能，纯 Go 实现需要
// 数周专门工程。本工具的合理定位：
//   - 帮用户**看见** BitLocker 卷的存在（避免"我盘上明明有数据但工具说没东西"的迷惑）
//   - 解析卷头元数据（version、sector size、recovery key GUID 等）让用户/取证人员有判断依据
//   - 明确指引用户用专门工具继续：dislocker / R-Studio / Windows Recovery 工具
//
// 后续要补完整解密，参考 dislocker 的实现是最稳的路径。
package bitlocker

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// BitLocker 卷头特征：jump (3 bytes) + OEM ID。
// OEM ID 在偏移 3-10，固定 "-FVE-FS-"（含两个连字符），8 字节。
//
// Windows 8 之后的 BitLocker To Go (FAT32 上的 BitLocker) 也用相同 OEM ID。
const fveOEMID = "-FVE-FS-"

// Volume 表示一个被识别为 BitLocker 加密的卷
type Volume struct {
	Offset           int64  // 卷在磁盘上的起始字节偏移
	OEMID            string // 应为 "-FVE-FS-"
	BytesPerSector   uint16
	SectorsPerCluster uint8
	TotalSectors     int64
	// FVE 特定字段（从 boot sector 偏移 176-183 处读取，BitLocker 自定义区）
	FVEMetaBlockOffset1 int64 // 第一个 FVE metadata 块偏移（按字节）
	FVEMetaBlockOffset2 int64 // 第二个备份
	FVEMetaBlockOffset3 int64 // 第三个备份
}

// Detect 在给定 offset 处尝试识别 BitLocker 卷。
// 不是 BitLocker 时返回 nil + nil error；其他错误（IO 失败）返回 nil + error。
func Detect(reader disk.DiskReader, offset int64) (*Volume, error) {
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取扇区失败: %w", err)
	}
	if n < 512 {
		return nil, nil // 数据不足
	}

	// 校验 boot signature
	if binary.LittleEndian.Uint16(buf[510:512]) != 0xAA55 {
		return nil, nil
	}

	// 校验 OEM ID
	if string(buf[3:11]) != fveOEMID {
		return nil, nil
	}

	v := &Volume{
		Offset:            offset,
		OEMID:             fveOEMID,
		BytesPerSector:    binary.LittleEndian.Uint16(buf[11:13]),
		SectorsPerCluster: buf[13],
		TotalSectors:      int64(binary.LittleEndian.Uint64(buf[40:48])),
	}

	// 合理性校验
	if v.BytesPerSector == 0 || v.BytesPerSector > 4096 {
		return nil, nil // 异常，不是合法 BitLocker
	}

	// FVE metadata block 偏移（boot sector 偏移 176/184/192，每个 8 字节，sector 单位）
	// Win 7+ 的 BitLocker 在这三个位置存有冗余元数据
	if len(buf) >= 200 {
		blk1 := int64(binary.LittleEndian.Uint64(buf[176:184]))
		blk2 := int64(binary.LittleEndian.Uint64(buf[184:192]))
		blk3 := int64(binary.LittleEndian.Uint64(buf[192:200]))
		v.FVEMetaBlockOffset1 = blk1 * int64(v.BytesPerSector)
		v.FVEMetaBlockOffset2 = blk2 * int64(v.BytesPerSector)
		v.FVEMetaBlockOffset3 = blk3 * int64(v.BytesPerSector)
	}

	return v, nil
}

// Scanner 用全盘扫描方式定位所有 BitLocker 卷（支持已删除分区表的场景）
type Scanner struct {
	reader disk.DiskReader
}

func NewScanner(reader disk.DiskReader) *Scanner {
	return &Scanner{reader: reader}
}

// FindVolumesFast 只在"可能位置"做几次 Detect：
//   - offset 0（整盘即一个 BitLocker 卷的最常见情况）
//   - GPT 分区表（如果在，LBA 1）里列出来的每个分区起始
//   - MBR 分区表（LBA 0 最后 64 字节）里列出来的每个分区起始
//
// 复杂度 O(分区数)，通常只读几个扇区；适合 UI 启动时批量扫所有盘。
// 全盘 brute-force（处理已删除分区表场景）应改用 FindVolumes，
// 由用户显式触发（比如"深度扫描"菜单），不放在启动路径里。
func (s *Scanner) FindVolumesFast() ([]*Volume, error) {
	var out []*Volume
	seen := make(map[int64]bool)
	tryOffset := func(off int64) {
		if off < 0 || seen[off] {
			return
		}
		seen[off] = true
		if v, _ := Detect(s.reader, off); v != nil {
			out = append(out, v)
		}
	}

	tryOffset(0)

	// 尝试 GPT
	for _, p := range readGPTPartitionOffsets(s.reader) {
		tryOffset(p)
	}
	// 尝试 MBR
	for _, p := range readMBRPartitionOffsets(s.reader) {
		tryOffset(p)
	}
	return out, nil
}

// readGPTPartitionOffsets 从磁盘 LBA 1（offset 512）读 GPT header 然后读分区表，
// 返回每个分区的起始字节偏移。失败或不是 GPT 返回 nil。
func readGPTPartitionOffsets(reader disk.DiskReader) []int64 {
	// GPT header @ LBA 1
	hdr := make([]byte, 512)
	if n, err := reader.ReadAt(hdr, 512); err != nil && n == 0 {
		return nil
	}
	if string(hdr[0:8]) != "EFI PART" {
		return nil
	}
	partEntryLBA := binary.LittleEndian.Uint64(hdr[72:80])
	numParts := binary.LittleEndian.Uint32(hdr[80:84])
	partSize := binary.LittleEndian.Uint32(hdr[84:88])
	if numParts == 0 || numParts > 256 || partSize < 128 || partSize > 4096 {
		return nil
	}
	totalBytes := int64(numParts) * int64(partSize)
	if totalBytes > 1024*1024 {
		totalBytes = 1024 * 1024
	}
	tbl := make([]byte, totalBytes)
	n, _ := reader.ReadAt(tbl, int64(partEntryLBA)*512)
	if n <= 0 {
		return nil
	}
	var offs []int64
	zeroGUID := [16]byte{}
	for i := 0; i+int(partSize) <= n; i += int(partSize) {
		ent := tbl[i : i+int(partSize)]
		var typeGUID [16]byte
		copy(typeGUID[:], ent[0:16])
		if typeGUID == zeroGUID {
			continue // 空槽
		}
		startLBA := binary.LittleEndian.Uint64(ent[32:40])
		offs = append(offs, int64(startLBA)*512)
	}
	return offs
}

// readMBRPartitionOffsets 解析 LBA 0 的 MBR 分区表（4 个 16 字节表项）
func readMBRPartitionOffsets(reader disk.DiskReader) []int64 {
	mbr := make([]byte, 512)
	if n, err := reader.ReadAt(mbr, 0); err != nil && n == 0 {
		return nil
	}
	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		return nil
	}
	var offs []int64
	for i := 0; i < 4; i++ {
		ent := mbr[446+i*16 : 446+(i+1)*16]
		partType := ent[4]
		if partType == 0 {
			continue
		}
		startLBA := binary.LittleEndian.Uint32(ent[8:12])
		if startLBA == 0 {
			continue
		}
		offs = append(offs, int64(startLBA)*512)
	}
	return offs
}

// FindVolumes 全盘扫描 BitLocker 卷头签名。
// 与 NTFS / exFAT 的 brute-force 同思路：4MB 块 + 512KB 步进。
func (s *Scanner) FindVolumes() ([]*Volume, error) {
	size, err := s.reader.Size()
	if err != nil {
		return nil, err
	}

	// 先在 offset 0 试一下（整盘即一个 BitLocker 卷的常见情况）
	var out []*Volume
	if v, _ := Detect(s.reader, 0); v != nil {
		out = append(out, v)
	}

	// 全盘步进扫描
	const (
		blockSize int64 = 4 * 1024 * 1024
		step      int64 = 512 * 1024
	)
	buf := make([]byte, blockSize)
	seen := make(map[int64]bool, len(out))
	for _, v := range out {
		seen[v.Offset] = true
	}

	for blockOff := int64(0); blockOff < size; blockOff += blockSize {
		read := blockSize
		if blockOff+read > size {
			read = size - blockOff
		}
		n, rerr := s.reader.ReadAt(buf[:read], blockOff)
		if rerr != nil && n == 0 {
			continue
		}
		for in := int64(0); in+512 <= int64(n); in += step {
			if string(buf[in+3:in+11]) != fveOEMID {
				continue
			}
			abs := blockOff + in
			if seen[abs] {
				continue
			}
			if v, _ := Detect(s.reader, abs); v != nil {
				out = append(out, v)
				seen[abs] = true
			}
		}
	}
	return out, nil
}
