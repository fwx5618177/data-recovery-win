package ntfs

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"data-recovery/internal/disk"
)

// $UsnJrnl ($J 流) 是 NTFS Update Sequence Number Journal —— 系统记录"每个文件
// 发生了什么变化"的日志，含 create / delete / rename / data overwrite 等。
//
// 对数据恢复的关键价值：**找回已删除文件的原始文件名**。即使 MFT entry 已经被覆盖，
// USN journal 里仍保留"文件 X 在 yyyy-mm-dd 被删除，原名 abc.jpg"的事件。
//
// USN_RECORD_V2 字段（Microsoft 文档 winioctl.h）：
//
//	+0x00  RecordLength       uint32  本记录字节数（含 self + 末尾 4 字节对齐填充）
//	+0x04  MajorVersion       uint16  = 2
//	+0x06  MinorVersion       uint16  = 0
//	+0x08  FileReferenceNumber       uint64  目标文件的 MFT 引用
//	+0x10  ParentFileReferenceNumber uint64  父目录的 MFT 引用
//	+0x18  Usn                int64   本记录在 journal 里的偏移
//	+0x20  TimeStamp          int64   Windows FILETIME（100ns 自 1601-01-01 UTC）
//	+0x28  Reason             uint32  USN_REASON_* 位标志（删除 / 重命名 / 数据修改）
//	+0x2C  SourceInfo         uint32
//	+0x30  SecurityId         uint32
//	+0x34  FileAttributes     uint32
//	+0x38  FileNameLength     uint16  字节数（不是 UTF-16 unit 数）
//	+0x3A  FileNameOffset     uint16  从 record 起点算
//	+0x3C  FileName           UTF-16LE 变长

// USN_REASON_* 位标志 — 我们关注的几个
const (
	UsnReasonDataOverwrite     uint32 = 0x00000001
	UsnReasonDataExtend        uint32 = 0x00000002
	UsnReasonDataTruncation    uint32 = 0x00000004
	UsnReasonNamedDataOverwrite uint32 = 0x00000010
	UsnReasonFileCreate        uint32 = 0x00000100
	UsnReasonFileDelete        uint32 = 0x00000200
	UsnReasonRenameOldName     uint32 = 0x00001000
	UsnReasonRenameNewName     uint32 = 0x00002000
	UsnReasonClose             uint32 = 0x80000000
)

// USNRecord 是解析后的单条 journal 记录。
type USNRecord struct {
	RecordLength      uint32
	MajorVersion      uint16
	MinorVersion      uint16
	FileReference     uint64 // MFT 编号 + sequence（低 48 位是编号，高 16 位 sequence）
	ParentFileReference uint64
	Usn               int64
	TimeStamp         time.Time
	Reason            uint32
	FileAttributes    uint32
	FileName          string // UTF-16 解码后的文件名
}

// IsDeletion 该记录是否是"文件最终被删除"事件（CLOSE + DELETE 同时置位时是真删除）
func (r *USNRecord) IsDeletion() bool {
	return r.Reason&UsnReasonFileDelete != 0
}

// IsRename 是否是重命名（旧名 / 新名两条 record 都会有；用 RENAME_OLD_NAME 配合
// 用户找"重命名前的原名"）
func (r *USNRecord) IsRename() bool {
	return r.Reason&(UsnReasonRenameOldName|UsnReasonRenameNewName) != 0
}

// MFTEntryNumber 抽出 FileReference 的低 48 位（MFT entry 编号本身）
func (r *USNRecord) MFTEntryNumber() int64 {
	return int64(r.FileReference & 0x0000FFFFFFFFFFFF)
}

// ParseUSNJournal 解析整个 $UsnJrnl:$J 流的字节内容（可能很大；调用方分块读再 append
// 也行，本函数支持 trailing 0 字节 — journal 头部 sparse 区是合法的，跳过即可）。
//
// 返回的记录按文件出现顺序。同一文件可能有多条事件（create / 修改 / close / delete）。
func ParseUSNJournal(data []byte) ([]USNRecord, error) {
	var out []USNRecord
	pos := 0
	for pos < len(data) {
		// journal 起始通常有大段 0（sparse 文件），跳过
		if pos+4 > len(data) {
			break
		}
		recLen := binary.LittleEndian.Uint32(data[pos : pos+4])
		if recLen == 0 {
			// 8 字节对齐找下一个非零
			pos += 8
			continue
		}
		if recLen < 0x3C || pos+int(recLen) > len(data) {
			// 损坏 / 截断，停止本块
			break
		}
		rec, err := parseUSNRecordV2(data[pos : pos+int(recLen)])
		if err == nil {
			out = append(out, *rec)
		}
		pos += int(recLen)
	}
	return out, nil
}

// parseUSNRecordV2 解一条 V2 record（V3/V4 用的少，本工具暂只解 V2）。
func parseUSNRecordV2(rec []byte) (*USNRecord, error) {
	if len(rec) < 0x3C {
		return nil, fmt.Errorf("USN record 太短: %d", len(rec))
	}
	major := binary.LittleEndian.Uint16(rec[0x04:0x06])
	if major != 2 {
		// V3 record 长度从 0x40 起；本实现只关注 V2
		return nil, fmt.Errorf("不支持 USN V%d", major)
	}
	r := &USNRecord{
		RecordLength:        binary.LittleEndian.Uint32(rec[0x00:0x04]),
		MajorVersion:        major,
		MinorVersion:        binary.LittleEndian.Uint16(rec[0x06:0x08]),
		FileReference:       binary.LittleEndian.Uint64(rec[0x08:0x10]),
		ParentFileReference: binary.LittleEndian.Uint64(rec[0x10:0x18]),
		Usn:                 int64(binary.LittleEndian.Uint64(rec[0x18:0x20])),
		Reason:              binary.LittleEndian.Uint32(rec[0x28:0x2C]),
		FileAttributes:      binary.LittleEndian.Uint32(rec[0x34:0x38]),
	}
	r.TimeStamp = filetimeToTimeUSN(int64(binary.LittleEndian.Uint64(rec[0x20:0x28])))

	nameLen := binary.LittleEndian.Uint16(rec[0x38:0x3A])
	nameOff := binary.LittleEndian.Uint16(rec[0x3A:0x3C])
	if int(nameOff)+int(nameLen) > len(rec) {
		return r, nil // name 越界，但其它字段仍有用
	}
	r.FileName = decodeUTF16LE(rec[nameOff : nameOff+nameLen])
	return r, nil
}

// filetimeToTimeUSN Windows FILETIME (100ns since 1601-01-01) → time.Time
func filetimeToTimeUSN(ft int64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	// 1601-01-01 UTC 到 1970-01-01 UTC 是 11644473600 秒
	const epochDelta = 116444736000000000 // 100ns 单位
	ns := (ft - epochDelta) * 100
	return time.Unix(0, ns).UTC()
}

// DeletedFileEvent 是"找回的已删除文件名"事件，给上层友好展示。
type DeletedFileEvent struct {
	FileName       string    // 文件名（不含路径）
	MFTEntry       int64     // 所在 MFT entry 编号（如果 entry 已被覆盖，提示给用户）
	ParentMFT      int64     // 父目录 MFT entry
	DeletedAt      time.Time // 删除时刻
	WasRenamed     bool      // 在删除前是否被重命名过（重命名前的原名要看更早的 RENAME_OLD_NAME 记录）
}

// FindUSNJournalEntry 在已经枚举过的 MFT entries 里找 $UsnJrnl 文件的主 entry。
//
// $UsnJrnl 文件的 NTFS 路径是 \$Extend\$UsnJrnl，含两个 ADS：
//   - $J     真正的 journal 数据（可能极大，sparse）
//   - $Max   元数据（最大字节数 / next USN 等）
//
// 返回 nil 表示卷上没启用 USN journal 或扫描没枚举到 $Extend 目录。
func FindUSNJournalEntry(entries []*MFTEntry) *MFTEntry {
	for _, e := range entries {
		if e == nil || e.FileName != "$UsnJrnl" {
			continue
		}
		// 父目录应是 $Extend；FullPath 重建后通常含 "/$Extend/$UsnJrnl"
		if strings.Contains(e.FullPath, "$Extend") {
			return e
		}
	}
	return nil
}

// ReadUSNJournalStream 读 $UsnJrnl 的 $J ADS 流字节内容。
//
// 简化实现：直接读 entry.AlternateStreams 里命名 "$J" 的那一条 + 走 DataRuns 拼出
// 完整字节。不做 sparse 优化（journal 头部多半是 sparse 0；ParseUSNJournal 自己跳）。
//
// MaxBytes 参数限制读多少（默认 256MB；journal 可能上 GB，全读太慢）。
// MaxBytes <= 0 时不限制。
func ReadUSNJournalStream(reader disk.DiskReader, boot *BootSector, entry *MFTEntry, maxBytes int64) ([]byte, error) {
	if entry == nil {
		return nil, fmt.Errorf("nil $UsnJrnl entry")
	}
	if boot == nil {
		return nil, fmt.Errorf("nil boot sector")
	}

	var jStream *ADSStream
	for i := range entry.AlternateStreams {
		if entry.AlternateStreams[i].Name == "$J" {
			jStream = &entry.AlternateStreams[i]
			break
		}
	}
	if jStream == nil {
		return nil, fmt.Errorf("$UsnJrnl 没有 $J 流")
	}

	if maxBytes <= 0 {
		maxBytes = 256 * 1024 * 1024
	}

	clusterBytes := int64(boot.BytesPerSector) * int64(boot.SectorsPerCluster)
	out := make([]byte, 0, 1024*1024)
	var totalRead int64
	chunk := make([]byte, 1*1024*1024)
	for _, dr := range jStream.DataRuns {
		if dr.Sparse {
			// sparse 段：在 journal 里就是大段 0；为了节省内存我们只填一段 0 做占位
			// （ParseUSNJournal 会跳过 0 字节）
			if totalRead >= maxBytes {
				break
			}
			zeroLen := dr.ClusterCount * clusterBytes
			if totalRead+zeroLen > maxBytes {
				zeroLen = maxBytes - totalRead
			}
			out = append(out, make([]byte, zeroLen)...)
			totalRead += zeroLen
			continue
		}
		runStart := dr.ClusterOffset * clusterBytes
		runLen := dr.ClusterCount * clusterBytes
		readOff := runStart
		left := runLen
		for left > 0 {
			if totalRead >= maxBytes {
				return out, nil
			}
			w := int64(len(chunk))
			if w > left {
				w = left
			}
			if w > maxBytes-totalRead {
				w = maxBytes - totalRead
			}
			n, err := reader.ReadAt(chunk[:w], readOff)
			if n > 0 {
				out = append(out, chunk[:n]...)
				totalRead += int64(n)
			}
			if err != nil && n == 0 {
				return out, nil // 容错：截断也返回已读部分
			}
			readOff += int64(n)
			left -= int64(n)
		}
	}
	return out, nil
}

// ScanDeletedFileNames 是给上层用的"一键找删除文件名"快捷方法。
//
// 流程：
//   1. 在 entries 里找 $UsnJrnl
//   2. 读它的 $J 流（最多 maxBytes，避免巨大 journal 拖慢）
//   3. ParseUSNJournal → ExtractDeletedFiles
func ScanDeletedFileNames(reader disk.DiskReader, boot *BootSector, entries []*MFTEntry, maxBytes int64) ([]DeletedFileEvent, error) {
	jrnlEntry := FindUSNJournalEntry(entries)
	if jrnlEntry == nil {
		return nil, nil // 没 journal，返回空清单
	}
	data, err := ReadUSNJournalStream(reader, boot, jrnlEntry, maxBytes)
	if err != nil || len(data) == 0 {
		return nil, err
	}
	records, err := ParseUSNJournal(data)
	if err != nil {
		return nil, err
	}
	return ExtractDeletedFiles(records), nil
}

// ExtractDeletedFiles 从一组 USN records 里挑出"删除事件"，按文件名去重保留最早一次删除。
//
// 用户角度：恢复出来一堆无名 carved 文件，再配上这个清单 ——
// "你电脑上 3 月 15 日删过这些文件：IMG_3492.HEIC / 报销单.pdf / ..."，
// 用户能据此判断哪些 carved 文件可能对应它想要的。
func ExtractDeletedFiles(records []USNRecord) []DeletedFileEvent {
	seen := make(map[string]bool)
	var out []DeletedFileEvent
	for _, r := range records {
		if !r.IsDeletion() {
			continue
		}
		if r.FileName == "" {
			continue
		}
		key := fmt.Sprintf("%d|%s", r.MFTEntryNumber(), r.FileName)
		if seen[key] {
			continue
		}
		seen[key] = true
		// "之前是否被重命名过" — 这里仅看本 record；完整推断需要扫整个 journal 的 RENAME 链
		out = append(out, DeletedFileEvent{
			FileName:   r.FileName,
			MFTEntry:   r.MFTEntryNumber(),
			ParentMFT:  int64(r.ParentFileReference & 0x0000FFFFFFFFFFFF),
			DeletedAt:  r.TimeStamp,
			WasRenamed: r.IsRename(),
		})
	}
	return out
}
