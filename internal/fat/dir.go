package fat

import (
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"
)

// 每条目录条目 32 字节。有两种结构：
//
//   - 短目录项（8.3 文件名）：首字节 != 0xE5 / 0x00
//     offset 0-10: 11 字节文件名（8 字节名 + 3 字节扩展名，空格填充）
//     offset 11:   属性位（Attr）
//     offset 20-21: 起始 cluster 的高 16 位（FAT32）
//     offset 26-27: 起始 cluster 的低 16 位
//     offset 28-31: 文件大小（字节）
//
//   - 长文件名项（LFN）：Attr == 0x0F
//     首字节高位 = 序号（1-based），位 6=1 表示"最后一段"
//     UTF-16 码元散落在 offset 1-10 (5 codes) + 14-25 (6 codes) + 28-31 (2 codes)
//     13 个 codes / 条目
//     多条 LFN 紧挨在对应短文件名项之前，序号从高到低排列（即磁盘顺序是 LFN_N, LFN_N-1, ..., LFN_1, SFN）

const (
	attrReadOnly  = 0x01
	attrHidden    = 0x02
	attrSystem    = 0x04
	attrVolumeID  = 0x08
	attrDirectory = 0x10
	attrArchive   = 0x20

	attrLongName     = 0x0F // 四个基础位全置 = LFN 项标识
	attrLongNameMask = 0x3F

	deletedMarker  = 0xE5
	endOfDirMarker = 0x00
)

// DirEntry 是一条被消费者关心的文件/目录信息（已合并 LFN + SFN）
type DirEntry struct {
	Name         string     // 完整文件名（优先 LFN，否则 8.3）
	ShortName    string     // 8.3 文件名原值
	IsDeleted    bool       // 首字节为 0xE5
	IsDirectory  bool       // Attr 位
	IsVolumeID   bool       // Attr 位
	FirstCluster uint32     // 对 FAT32 合并高低 16 位；FAT12/16 只用低 16 位
	FileSize     int64      // DIR_FileSize
	ModifiedTime *time.Time // 修改时间（写时间 + 写日期）
	CreatedTime  *time.Time // 可选，从 creation fields 来
}

// parseDirEntries 解析一整段目录数据 buf，返回发现的每个 DirEntry。
// buf 是连续的目录内容（已把 FAT32 目录 cluster chain 拼起来之后的字节流）。
// 函数自动跳过 volume label、系统项；保留已删除项（供上层决定恢复）。
func parseDirEntries(buf []byte) []DirEntry {
	out := make([]DirEntry, 0, 16)
	var lfnBuffer []uint16 // 累积中的 LFN（按 UTF-16 码元）

	for i := 0; i+32 <= len(buf); i += 32 {
		first := buf[i]
		attr := buf[i+11]

		if first == endOfDirMarker {
			// 目录尾部；如果有悬挂的 LFN，丢弃
			break
		}

		// LFN 项
		if attr&attrLongNameMask == attrLongName {
			// 这条 LFN 可能在 SFN 之前（正常）或在已删除 SFN 之前（`first=0xE5`）。
			// 按序号高到低累积；由于磁盘顺序是 LFN_N..LFN_1，我们头插到 buffer 前面
			order := first & 0x1F
			// 从 LFN 条目收集 13 个 UTF-16 码元
			codes := extractLFNCodes(buf[i : i+32])
			// LFN 多条 —— 按序号逆序拼接：后读到的序号小，拼到前面
			// 最简单：先把本条的 13 个 code append 到临时 slice，组装时按 order 拼
			// 直接采用"顺序 push 到 lfnBuffer 前面"也行，但 order 可能有跳号
			_ = order
			lfnBuffer = append(codes, lfnBuffer...)
			continue
		}

		// 到这里是 SFN（可能是已删除的）
		shortName := parseShortName(buf[i : i+11])
		longName := decodeLFNCodes(lfnBuffer)
		lfnBuffer = nil

		entry := DirEntry{
			ShortName:   shortName,
			IsDeleted:   first == deletedMarker,
			IsDirectory: attr&attrDirectory != 0 && attr&attrVolumeID == 0,
			IsVolumeID:  attr&attrVolumeID != 0,
			FirstCluster: uint32(binary.LittleEndian.Uint16(buf[i+26:i+28])) |
				uint32(binary.LittleEndian.Uint16(buf[i+20:i+22]))<<16,
			FileSize: int64(binary.LittleEndian.Uint32(buf[i+28 : i+32])),
			ModifiedTime: parseFATDate(binary.LittleEndian.Uint16(buf[i+24:i+26]),
				binary.LittleEndian.Uint16(buf[i+22:i+24])),
		}

		if longName != "" {
			entry.Name = longName
		} else {
			entry.Name = shortName
		}

		// 过滤 volume id 本身
		if entry.IsVolumeID {
			continue
		}

		// 过滤 "." / ".." 子目录自指 / 上指（上层递归时遇到会造成循环）
		if entry.IsDirectory && (entry.ShortName == "." || entry.ShortName == "..") {
			continue
		}

		out = append(out, entry)
	}
	return out
}

// extractLFNCodes 从一条 LFN 条目里抽出 13 个 UTF-16 码元（0x0000 或 0xFFFF 代表"空/填充"）
func extractLFNCodes(e []byte) []uint16 {
	codes := make([]uint16, 0, 13)
	readPair := func(off int) uint16 {
		return binary.LittleEndian.Uint16(e[off : off+2])
	}
	ranges := [][2]int{{1, 11}, {14, 26}, {28, 32}}
	for _, r := range ranges {
		for p := r[0]; p < r[1]; p += 2 {
			c := readPair(p)
			if c == 0x0000 || c == 0xFFFF {
				return codes
			}
			codes = append(codes, c)
		}
	}
	return codes
}

func decodeLFNCodes(codes []uint16) string {
	if len(codes) == 0 {
		return ""
	}
	return string(utf16.Decode(codes))
}

// parseShortName 把 11 字节 8.3 名字解码成普通字符串
// NTFS/FAT 的 8 字节基名 + 3 字节扩展名用空格填充；已删除条目首字节被改成 0xE5
func parseShortName(raw []byte) string {
	if len(raw) < 11 {
		return ""
	}
	// 首字节如果是 0xE5（已删除）或 0x05（文件名真的以 0xE5 开头，做了转义），还原
	first := raw[0]
	base := make([]byte, 8)
	copy(base, raw[:8])
	if first == 0x05 {
		base[0] = 0xE5
	}
	// 已删除标记 0xE5 也暂且替换掉，名字本身不携带此字节
	if first == deletedMarker {
		base[0] = '_' // 占位，避免输出空字符
	}

	name := strings.TrimRight(string(base), " ")
	ext := strings.TrimRight(string(raw[8:11]), " ")
	if ext == "" {
		return name
	}
	return name + "." + ext
}

// parseFATDate FAT 日期 + 时间 合并成 time.Time
//
//	date: bits 0-4 day, 5-8 month, 9-15 year (from 1980)
//	time: bits 0-4 seconds/2, 5-10 minutes, 11-15 hours
func parseFATDate(date, tm uint16) *time.Time {
	if date == 0 {
		return nil
	}
	year := int(date>>9) + 1980
	month := int((date >> 5) & 0x0F)
	day := int(date & 0x1F)
	hour := int(tm >> 11)
	minute := int((tm >> 5) & 0x3F)
	second := int(tm&0x1F) * 2
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return nil
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	return &t
}
