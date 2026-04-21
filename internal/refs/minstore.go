package refs

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// ReFS 的"Minstore"是它内部的存储引擎，所有元数据（目录树 / 文件信息 / FSV / object table）
// 都按 16KB 元数据 page（"metadata block"）组织。每个 page 头有一个 4 字节签名 + 64 字节
// header，剩下是 B+ tree 节点 / 容器表项等。
//
// **本文件实现的边界**：
//   ✅ 在容器范围内扫所有 16KB 边界，识别 Minstore page 签名 + 抽出 LSN / type
//   ❌ 完整 B+ tree 解析 + 文件枚举（无公开规范，需要逆向，工作量极大）
//
// 价值：
//   1. 给用户/取证人员 ReFS 卷里"有多少个元数据 page、占盘多大"的整盘统计
//   2. 后续如果要做 ReFS 文件枚举，先有 page 索引就少走弯路
//
// 已知 Minstore page 签名（社区逆向得到，可能不完整）：
//   "MSB+"   B+ tree 内部节点 / 叶节点
//   "FSRS"   也作为 metadata 头里的 fs_signature 出现
//   "CHKP"   checkpoint
//   "OBJT"   object table 节点（极稀有）

const (
	MinstorePageSize int64 = 16 * 1024

	// 主要的 page signature（首 4 字节）
	pageMagicMSBPlus = "MSB+"
	pageMagicCHKP    = "CHKP"
)

// MinstorePage 是单个识别到的 ReFS 元数据 page。
type MinstorePage struct {
	Offset    int64  // 在卷里的字节偏移
	Magic     string // "MSB+" / "CHKP" / ...
	LSN       uint64 // log sequence number（写入序列；越大越新）
}

// IndexMinstorePages 在给定卷范围内扫所有 16KB page，识别 Minstore signature。
//
// volStart / volSize 是卷在底层 reader 上的字节范围。
// 通常 volStart = ReFS VolumeHeader.Offset；volSize 来自 (TotalSectors * BytesPerSector)。
func IndexMinstorePages(reader disk.DiskReader, volStart, volSize int64) ([]MinstorePage, error) {
	if volSize <= 0 {
		return nil, fmt.Errorf("volSize 必须 > 0")
	}
	var out []MinstorePage
	hdr := make([]byte, 64)
	for off := int64(0); off+MinstorePageSize <= volSize; off += MinstorePageSize {
		n, err := reader.ReadAt(hdr, volStart+off)
		if err != nil && err != io.EOF {
			return out, fmt.Errorf("读 page @+%d: %w", off, err)
		}
		if n < 8 {
			continue
		}
		magic := string(hdr[0:4])
		if magic != pageMagicMSBPlus && magic != pageMagicCHKP {
			continue
		}
		var lsn uint64
		if n >= 16 {
			// LSN 在 page header offset 8（社区文档；不同版本可能位置略有差异）
			lsn = binary.LittleEndian.Uint64(hdr[8:16])
		}
		out = append(out, MinstorePage{
			Offset: off,
			Magic:  magic,
			LSN:    lsn,
		})
	}
	return out, nil
}

// MinstoreSummary 给上层一个"这个卷有多少个 ReFS 元数据 page"的概览。
type MinstoreSummary struct {
	TotalPages    int
	MSBPlusCount  int
	CheckpointCnt int
	HighestLSN    uint64
}

// SummarizeMinstore 跑一次完整索引并返回统计。
func SummarizeMinstore(reader disk.DiskReader, volStart, volSize int64) (*MinstoreSummary, error) {
	pages, err := IndexMinstorePages(reader, volStart, volSize)
	if err != nil && len(pages) == 0 {
		return nil, err
	}
	s := &MinstoreSummary{TotalPages: len(pages)}
	for _, p := range pages {
		switch p.Magic {
		case pageMagicMSBPlus:
			s.MSBPlusCount++
		case pageMagicCHKP:
			s.CheckpointCnt++
		}
		if p.LSN > s.HighestLSN {
			s.HighestLSN = p.LSN
		}
	}
	return s, nil
}

// =============================================================
// Minstore B-tree node 解析（社区逆向；ReFS 无公开规范）
//
// ReFS Minstore "MSB+" page 内部结构（社区文档片段，可能不完整）：
//
//   +0x00  signature "MSB+" (4)
//   +0x04  reserved (4)
//   +0x08  LSN (8)
//   +0x10  reserved (16)
//   +0x20  index header:
//      +0x00  uint32 first_entry_offset    (相对 page 起点)
//      +0x04  uint32 free_offset
//      +0x08  uint32 num_entries
//      ... 接 entries
//
// 每个 entry：
//   +0x00  uint16 entry_size (含 self)
//   +0x02  uint16 key_offset (相对 entry 起点)
//   +0x04  uint16 key_size
//   +0x06  uint16 value_offset
//   +0x08  uint16 value_size
//   +0x0A  reserved (4)
//   +0x10  ... key bytes + value bytes
// =============================================================

// MinstoreEntry 是 MSB+ page 里的单条 (key, value) 记录。
type MinstoreEntry struct {
	Key   []byte
	Value []byte
}

// ParseMinstorePage 解析 16KB 的 MSB+ page，返回所有 (key, value)。
//
// 由于 ReFS 无公开规范，本实现按"看起来合理"的字段偏移做最 best-effort 解析。
// 实测对部分版本 ReFS 卷可读出 entry 数和 key/value 字节，但**不**保证语义正确：
// 上层视为"半结构化数据"使用（碎片重组中可作为元数据线索）。
//
// 返回 nil + nil error 表示这不是一个识别得了 entry 表的 MSB+ page。
func ParseMinstorePage(buf []byte) ([]MinstoreEntry, error) {
	if len(buf) < 0x40 {
		return nil, fmt.Errorf("MSB+ page 太短: %d", len(buf))
	}
	if string(buf[0:4]) != pageMagicMSBPlus {
		return nil, nil
	}
	const indexHdrAt = 0x20
	firstEntryOff := int(binary.LittleEndian.Uint32(buf[indexHdrAt : indexHdrAt+4]))
	numEntries := int(binary.LittleEndian.Uint32(buf[indexHdrAt+8 : indexHdrAt+12]))

	// 合理性
	if firstEntryOff < 0x40 || firstEntryOff > len(buf)-16 {
		return nil, nil // 头部不像 entry 表，可能是社区文档不适用的版本
	}
	if numEntries == 0 || numEntries > 4096 {
		return nil, nil
	}

	out := make([]MinstoreEntry, 0, numEntries)
	pos := firstEntryOff
	for i := 0; i < numEntries && pos+16 < len(buf); i++ {
		entrySize := int(binary.LittleEndian.Uint16(buf[pos : pos+2]))
		keyOff := int(binary.LittleEndian.Uint16(buf[pos+2 : pos+4]))
		keyLen := int(binary.LittleEndian.Uint16(buf[pos+4 : pos+6]))
		valOff := int(binary.LittleEndian.Uint16(buf[pos+6 : pos+8]))
		valLen := int(binary.LittleEndian.Uint16(buf[pos+8 : pos+10]))
		if entrySize < 16 || pos+entrySize > len(buf) {
			break
		}
		if keyOff < 16 || valOff < 16 ||
			keyOff+keyLen > entrySize || valOff+valLen > entrySize {
			pos += entrySize
			continue // 跳过损坏 / 不识别的 entry
		}
		key := make([]byte, keyLen)
		val := make([]byte, valLen)
		copy(key, buf[pos+keyOff:pos+keyOff+keyLen])
		copy(val, buf[pos+valOff:pos+valOff+valLen])
		out = append(out, MinstoreEntry{Key: key, Value: val})
		pos += entrySize
	}
	return out, nil
}
