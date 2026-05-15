// Package gpt 实现 GPT (GUID Partition Table) 解析 + **备份表恢复**。
//
// 关键场景：用户卷被"清除分区表"（误用 diskpart clean / dd if=/dev/zero count=1）后，
// 主 GPT 头（LBA 1）被破坏。GPT 协议要求**盘尾 LBA -1 有备份头 + LBA -33..-2 有备份分区表**，
// 我们能从备份恢复主表。
//
// 完整 GPT 头部布局（512 字节）：
//
//	+0x00 signature "EFI PART" (8 bytes)
//	+0x08 revision   uint32     (一般 0x00010000)
//	+0x0C header_size uint32    (一般 92)
//	+0x10 crc32      uint32     (header CRC32)
//	+0x14 reserved   uint32
//	+0x18 my_lba     uint64     (这个头自己在哪)
//	+0x20 alt_lba    uint64     (备份头在哪)
//	+0x28 first_usable_lba uint64
//	+0x30 last_usable_lba  uint64
//	+0x38 disk_guid  [16]byte
//	+0x48 part_entry_lba uint64
//	+0x50 num_part_entries uint32
//	+0x54 size_of_part_entry uint32
//	+0x58 part_array_crc32 uint32
package gpt

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	"data-recovery/internal/disk"
)

const (
	GPTSignature                       = "EFI PART"
	PrimaryHeaderLBA             int64 = 1
	BackupHeaderLBAOffsetFromEnd int64 = -1 // 盘倒数第 1 个 LBA
)

// Header 是解析后的 GPT 头
type Header struct {
	Revision        uint32
	HeaderSize      uint32
	HeaderCRC32     uint32
	MyLBA           uint64
	AlternateLBA    uint64
	FirstUsableLBA  uint64
	LastUsableLBA   uint64
	DiskGUID        [16]byte
	PartEntryLBA    uint64
	NumPartEntries  uint32
	SizeOfPartEntry uint32
	PartArrayCRC32  uint32
	IsValidCRC      bool // header CRC 自校验通过
}

// Partition 单个 GPT 分区
type Partition struct {
	TypeGUID   [16]byte
	UniqueGUID [16]byte
	StartLBA   uint64
	EndLBA     uint64
	Attributes uint64
	Name       string // UTF-16 LE
}

// IsEmpty 分区类型 GUID 全 0 = 空槽
func (p *Partition) IsEmpty() bool {
	for _, b := range p.TypeGUID {
		if b != 0 {
			return false
		}
	}
	return true
}

// SizeBytes 分区字节数（按 512 字节扇区计算）
func (p *Partition) SizeBytes() uint64 {
	return (p.EndLBA - p.StartLBA + 1) * 512
}

// ReadPrimaryHeader 读 LBA 1 的主 GPT 头
func ReadPrimaryHeader(reader disk.DiskReader) (*Header, error) {
	return readHeaderAt(reader, PrimaryHeaderLBA*512)
}

// ReadBackupHeader 读盘尾备份头
func ReadBackupHeader(reader disk.DiskReader) (*Header, error) {
	size, err := reader.Size()
	if err != nil {
		return nil, fmt.Errorf("读盘尺寸: %w", err)
	}
	return readHeaderAt(reader, size-512)
}

func readHeaderAt(reader disk.DiskReader, offset int64) (*Header, error) {
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n < 92 {
		return nil, fmt.Errorf("GPT header 太短")
	}
	if string(buf[0:8]) != GPTSignature {
		return nil, fmt.Errorf("非 GPT: signature %q", string(buf[0:8]))
	}
	h := &Header{
		Revision:        binary.LittleEndian.Uint32(buf[8:12]),
		HeaderSize:      binary.LittleEndian.Uint32(buf[12:16]),
		HeaderCRC32:     binary.LittleEndian.Uint32(buf[16:20]),
		MyLBA:           binary.LittleEndian.Uint64(buf[24:32]),
		AlternateLBA:    binary.LittleEndian.Uint64(buf[32:40]),
		FirstUsableLBA:  binary.LittleEndian.Uint64(buf[40:48]),
		LastUsableLBA:   binary.LittleEndian.Uint64(buf[48:56]),
		PartEntryLBA:    binary.LittleEndian.Uint64(buf[72:80]),
		NumPartEntries:  binary.LittleEndian.Uint32(buf[80:84]),
		SizeOfPartEntry: binary.LittleEndian.Uint32(buf[84:88]),
		PartArrayCRC32:  binary.LittleEndian.Uint32(buf[88:92]),
	}
	copy(h.DiskGUID[:], buf[56:72])

	// 校验 header CRC32（CRC 字段本身置零再算）
	hdrBytes := make([]byte, h.HeaderSize)
	copy(hdrBytes, buf[:h.HeaderSize])
	binary.LittleEndian.PutUint32(hdrBytes[16:20], 0)
	calc := crc32.ChecksumIEEE(hdrBytes)
	h.IsValidCRC = calc == h.HeaderCRC32

	return h, nil
}

// ReadPartitions 读分区数组
func ReadPartitions(reader disk.DiskReader, h *Header) ([]Partition, error) {
	if h.NumPartEntries == 0 || h.SizeOfPartEntry < 128 {
		return nil, fmt.Errorf("非法分区表参数")
	}
	totalBytes := int64(h.NumPartEntries) * int64(h.SizeOfPartEntry)
	if totalBytes > 1024*1024 {
		totalBytes = 1024 * 1024
	}
	tbl := make([]byte, totalBytes)
	n, _ := reader.ReadAt(tbl, int64(h.PartEntryLBA)*512)
	if n <= 0 {
		return nil, fmt.Errorf("读分区表失败")
	}
	var out []Partition
	for i := 0; i+int(h.SizeOfPartEntry) <= n; i += int(h.SizeOfPartEntry) {
		ent := tbl[i : i+int(h.SizeOfPartEntry)]
		var p Partition
		copy(p.TypeGUID[:], ent[0:16])
		if p.IsEmpty() {
			continue
		}
		copy(p.UniqueGUID[:], ent[16:32])
		p.StartLBA = binary.LittleEndian.Uint64(ent[32:40])
		p.EndLBA = binary.LittleEndian.Uint64(ent[40:48])
		p.Attributes = binary.LittleEndian.Uint64(ent[48:56])
		// name: UTF-16 LE，最多 72 字节
		nameRaw := ent[56:128]
		p.Name = decodeUTF16LE(nameRaw)
		out = append(out, p)
	}
	return out, nil
}

// RecoverFromBackup 主 GPT 损坏时尝试用备份头/备份表恢复。
// 返回的 Header 来自备份位置；调用方拿到分区表后可写回 LBA 1（破坏盘）— 本工具默认只读，
// 把恢复出来的分区列表展示给用户即可。
func RecoverFromBackup(reader disk.DiskReader) (*Header, []Partition, error) {
	bh, err := ReadBackupHeader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("备份头读取失败: %w", err)
	}
	if !bh.IsValidCRC {
		return nil, nil, fmt.Errorf("备份头 CRC 校验失败 — 备份也损坏")
	}
	parts, err := ReadPartitions(reader, bh)
	if err != nil {
		return bh, nil, err
	}
	return bh, parts, nil
}

// decodeUTF16LE 解 GPT name（含 NUL terminator）
func decodeUTF16LE(b []byte) string {
	codes := []uint16{}
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		codes = append(codes, c)
	}
	out := make([]rune, 0, len(codes))
	for _, c := range codes {
		out = append(out, rune(c))
	}
	return string(out)
}
