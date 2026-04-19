package exfat

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// exFAT 目录条目类型码（每个条目 32 字节）
//
// 高位（bit 7）= 1 表示"正在使用"；bit 7 = 0 表示该条目所在位置已被删除但内容还在
// 例如 0x85 是在用的 File；0x05 是同样结构但已被标记删除。
//
// 一个文件由多条 32 字节条目组成（一个 entry set）：
//   - 1 个 primary: File Directory Entry (0x85)
//   - 1 个 secondary: Stream Extension (0xC0)
//   - N 个 secondary: File Name (0xC1)，N = ceil(NameLen/15)
// primary 的 SecondaryCount 字段告诉我们后面还跟几条 secondary。
const (
	// In-use primary entry types
	entryFile            uint8 = 0x85
	entryAllocationBitmap uint8 = 0x81
	entryUpcaseTable     uint8 = 0x82
	entryVolumeLabel     uint8 = 0x83

	// In-use secondary entry types
	entryStreamExtension uint8 = 0xC0
	entryFileName        uint8 = 0xC1

	// 空条目（未使用）
	entryEndOfDir uint8 = 0x00

	// 删除标记：对应的 in-use entry 去掉高位（如 0x85 → 0x05）
	entryFileDeleted            uint8 = 0x05
	entryStreamExtensionDeleted uint8 = 0x40
	entryFileNameDeleted        uint8 = 0x41
)

// FileAttr exFAT 文件属性位
type FileAttr uint16

const (
	AttrReadOnly  FileAttr = 0x0001
	AttrHidden    FileAttr = 0x0002
	AttrSystem    FileAttr = 0x0004
	AttrDirectory FileAttr = 0x0010
	AttrArchive   FileAttr = 0x0020
)

// DirEntry 是一个 entry set 解析后的完整文件信息。
// 所有 subfield 都已经从 primary / stream / filename 三类条目合并好。
type DirEntry struct {
	Name         string    // UTF-16 解码后的文件名
	FileSize     int64     // Data Length（真实文件大小，字节）
	ValidSize    int64     // Valid Data Length（通常 == FileSize）
	FirstCluster uint32    // 第一个簇号；0 或 ClusterHeapOffset 都代表"无数据"
	NoFatChain   bool      // General Secondary Flags bit 1：1=连续存储、FAT 链不用走
	IsDirectory  bool      // 是否为目录（由 FileAttributes bit 4 决定）
	IsDeleted    bool      // 该 entry set 的 primary type 高位是否被清
	Attr         FileAttr  // 原始属性位
	CreatedTime  *time.Time
	ModifiedTime *time.Time
	AccessedTime *time.Time

	// 调试用：entry set 在磁盘上的起始位置（便于二次核查）
	DirEntryOffset int64
}

// ParseEntrySet 尝试从 data 的 pos 位置开始解析一个完整 entry set。
//
// 返回：
//   - entry 解析出的合并信息（可能为 nil，例如该位置是空 / 坏 / 非文件条目）
//   - consumed 当前 entry set 占用的字节数（= (1 + SecondaryCount) * 32），
//     调用方据此步进。失败时 consumed >= 32 保证前进。
//
// 这里**宽容**对待已删除条目：只要结构能解析，就返回 IsDeleted=true 的 DirEntry。
// 真要不要用它由上层决定。
func ParseEntrySet(data []byte, pos int) (entry *DirEntry, consumed int) {
	// 空 entry = 全零，按 32 字节跳过
	if pos+32 > len(data) {
		return nil, 0
	}

	entryType := data[pos]
	if entryType == entryEndOfDir {
		// EndOfDir：严格按规范应该停止遍历；但磁盘上"删除"会把 type 清零而不是 0x00，
		// 所以我们看到单个 0x00 也继续扫下去；上层根据业务决定何时停
		return nil, 32
	}

	// 仅处理 File 条目（in-use 或已删除）。其他 primary 类型（Bitmap/Upcase/VolumeLabel）
	// 略过；它们也有自己的 secondary 数量，必须正确步进。
	isInUseFile := entryType == entryFile
	isDeletedFile := entryType == entryFileDeleted

	if !isInUseFile && !isDeletedFile {
		// 其它 primary 类型也遵循 SecondaryCount（在 byte 1），跳过整个 entry set
		if entryType&0x80 != 0 || entryType == entryAllocationBitmap ||
			entryType == entryUpcaseTable || entryType == entryVolumeLabel {
			// 读取 SecondaryCount 让步进正确
			secCount := int(data[pos+1])
			return nil, 32 * (1 + secCount)
		}
		return nil, 32
	}

	// primary 的 byte 1: SecondaryCount（后面跟的 secondary 数量）
	secondaryCount := int(data[pos+1])
	if secondaryCount < 1 || secondaryCount > 18 {
		// 合理值 2-18（至少 1 个 stream ext + 1+ filename；上限 255-但 255 会让单个
		// 文件名超过 15*17 字符，不切实际）
		return nil, 32
	}

	totalEntries := 1 + secondaryCount
	totalBytes := totalEntries * 32
	if pos+totalBytes > len(data) {
		return nil, 32
	}

	// primary File Directory Entry 结构（仅列本 MVP 用到的）：
	//   byte 0:       type
	//   byte 1:       secondaryCount
	//   byte 4:       FileAttributes (uint16 LE)
	//   byte 8-11:    CreateTimestamp (uint32 LE, DOS-like)
	//   byte 12-15:   LastModifiedTimestamp
	//   byte 16-19:   LastAccessedTimestamp
	attr := FileAttr(binary.LittleEndian.Uint16(data[pos+4 : pos+6]))
	createdTS := binary.LittleEndian.Uint32(data[pos+8 : pos+12])
	modifiedTS := binary.LittleEndian.Uint32(data[pos+12 : pos+16])
	accessedTS := binary.LittleEndian.Uint32(data[pos+16 : pos+20])

	entry = &DirEntry{
		IsDeleted:    isDeletedFile,
		Attr:         attr,
		IsDirectory:  attr&AttrDirectory != 0,
		CreatedTime:  parseTimestamp(createdTS),
		ModifiedTime: parseTimestamp(modifiedTS),
		AccessedTime: parseTimestamp(accessedTS),
	}

	// Secondary 条目从 pos+32 开始
	// 第一个 secondary 必须是 Stream Extension (0xC0 / 0x40)
	streamPos := pos + 32
	if streamPos+32 > len(data) {
		return entry, totalBytes
	}
	streamType := data[streamPos]
	if streamType != entryStreamExtension && streamType != entryStreamExtensionDeleted {
		return entry, totalBytes
	}

	// Stream Extension 结构：
	//   byte 1:       GeneralSecondaryFlags（bit 0: AllocationPossible, bit 1: NoFatChain）
	//   byte 3:       NameLength（UTF-16 码元数，总共）
	//   byte 4-5:     NameHash
	//   byte 8-15:    ValidDataLength uint64
	//   byte 20-23:   FirstCluster uint32
	//   byte 24-31:   DataLength uint64
	secFlags := data[streamPos+1]
	nameLen := int(data[streamPos+3])
	entry.ValidSize = int64(binary.LittleEndian.Uint64(data[streamPos+8 : streamPos+16]))
	entry.FirstCluster = binary.LittleEndian.Uint32(data[streamPos+20 : streamPos+24])
	entry.FileSize = int64(binary.LittleEndian.Uint64(data[streamPos+24 : streamPos+32]))
	entry.NoFatChain = secFlags&0x02 != 0

	// 剩下 secondaryCount-1 条都是 FileName (0xC1)，每条最多 15 个 UTF-16 码元
	utf16Name := make([]uint16, 0, nameLen)
	for i := 1; i < secondaryCount; i++ {
		fnPos := pos + 32*(1+i)
		if fnPos+32 > len(data) {
			break
		}
		fnType := data[fnPos]
		if fnType != entryFileName && fnType != entryFileNameDeleted {
			break
		}
		// byte 2-31 是 UTF-16 码元（最多 15 个 = 30 字节）
		for j := 0; j < 15; j++ {
			off := fnPos + 2 + j*2
			if off+2 > len(data) {
				break
			}
			if len(utf16Name) >= nameLen {
				break
			}
			code := binary.LittleEndian.Uint16(data[off : off+2])
			if code == 0 {
				break
			}
			utf16Name = append(utf16Name, code)
		}
	}
	entry.Name = string(utf16.Decode(utf16Name))

	return entry, totalBytes
}

// parseTimestamp 解析 exFAT 时间戳（uint32 LE，DOS 格式）
//
//	bits 0-4:    seconds / 2
//	bits 5-10:   minutes
//	bits 11-15:  hours
//	bits 16-20:  day
//	bits 21-24:  month
//	bits 25-31:  year since 1980
//
// 返回 nil 表示时间戳为零或不合理
func parseTimestamp(raw uint32) *time.Time {
	if raw == 0 {
		return nil
	}
	year := int(raw>>25) + 1980
	month := int((raw >> 21) & 0x0F)
	day := int((raw >> 16) & 0x1F)
	hour := int((raw >> 11) & 0x1F)
	minute := int((raw >> 5) & 0x3F)
	second := int(raw&0x1F) * 2

	if month < 1 || month > 12 || day < 1 || day > 31 {
		return nil
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	return &t
}
