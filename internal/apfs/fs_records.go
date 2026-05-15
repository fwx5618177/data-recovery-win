package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// APFS 文件系统树（fs tree）的 record types。每条 leaf record 的 key 前 8 字节是
// j_key_t：obj_id 的低 60 位 + 高 4 位 record type。
//
//	jKey.objIDAndType (uint64 LE):
//	  bits[0..59]  = object ID
//	  bits[60..63] = record type
const (
	JTypeAny          uint8 = 0
	JTypeSnapMetadata uint8 = 1
	JTypeExtent       uint8 = 2
	JTypeInode        uint8 = 3
	JTypeXAttr        uint8 = 4
	JTypeSiblingLink  uint8 = 5
	JTypeDStreamID    uint8 = 6
	JTypeCryptoState  uint8 = 7
	JTypeFileExtent   uint8 = 8
	JTypeDirRec       uint8 = 9
	JTypeDirStats     uint8 = 10
	JTypeSnapName     uint8 = 11
	JTypeSiblingMap   uint8 = 12
)

// JKey 是所有 fs-tree key 的公共头。
type JKey struct {
	ObjID uint64 // bits 0..59
	Type  uint8  // bits 60..63
}

// ParseJKey 解析 j_key_t 头（8 字节）。
func ParseJKey(b []byte) (JKey, error) {
	if len(b) < 8 {
		return JKey{}, fmt.Errorf("j_key 太短")
	}
	v := binary.LittleEndian.Uint64(b[0:8])
	return JKey{
		ObjID: v & ((1 << 60) - 1),
		Type:  uint8(v >> 60),
	}, nil
}

// InodeRecord 解析 j_inode_val_t 的关键字段。
//
// 完整字段含 owner / group / mode / nlink / 各种时间戳 / extended fields；
// 我们只取最常用的几个供文件枚举用。
type InodeRecord struct {
	ObjID       uint64
	ParentID    uint64
	PrivateID   uint64 // 文件数据流的 obj_id（用来查 file extent records）
	CreateTime  uint64 // ns 单位
	ModTime     uint64
	ChangeTime  uint64
	AccessTime  uint64
	Mode        uint16 // POSIX mode；高位含文件类型
	NumChildren uint32 // 目录有效；普通文件 = 0
}

// ParseInodeRecord 在 leaf entry 的 (key, val) 上把 inode 信息抽出来。
// 失败返回 nil（一般是 type 不匹配）。
func ParseInodeRecord(key, val []byte) *InodeRecord {
	jk, err := ParseJKey(key)
	if err != nil || jk.Type != JTypeInode {
		return nil
	}
	if len(val) < 0x5C {
		return nil
	}
	return &InodeRecord{
		ObjID:      jk.ObjID,
		ParentID:   binary.LittleEndian.Uint64(val[0:8]),
		PrivateID:  binary.LittleEndian.Uint64(val[8:16]),
		CreateTime: binary.LittleEndian.Uint64(val[16:24]),
		ModTime:    binary.LittleEndian.Uint64(val[24:32]),
		ChangeTime: binary.LittleEndian.Uint64(val[32:40]),
		AccessTime: binary.LittleEndian.Uint64(val[40:48]),
		// 48..56  internal_flags
		// 56..60  nchildren | nlink
		NumChildren: binary.LittleEndian.Uint32(val[56:60]),
		// 60..76  default_protection_class / write_generation / bsd_flags / owner / group
		Mode: binary.LittleEndian.Uint16(val[88:90]),
	}
}

// DirEntry 是 j_drec_val_t 解析结果（目录项）。
type DirEntry struct {
	ParentID  uint64 // = key 中的 obj_id
	Name      string
	FileID    uint64 // 子节点的 obj_id（即 inode 的 ObjID）
	DateAdded uint64 // ns
	Type      uint16 // DT_REG / DT_DIR / ...
}

// ParseDirEntry 解析目录项 record。
//
// 目录项 key 格式（j_drec_key_t）：j_key + name_len(uint16) + name(UTF-8, NUL-terminated)
// 注意：APFS 还有 hashed dir record (j_drec_hashed_key_t) 多 4 字节 hash —— 这里两种都尽量识别。
//
// 目录项 value（j_drec_val_t）：
//
//	uint64 file_id
//	uint64 date_added
//	uint16 flags  (低 4 bit = file type / DT_*)
func ParseDirEntry(key, val []byte) *DirEntry {
	jk, err := ParseJKey(key)
	if err != nil || jk.Type != JTypeDirRec {
		return nil
	}
	if len(key) < 10 || len(val) < 18 {
		return nil
	}

	// 先按 unhashed 解：name_len 在 key[8:10]
	nameLen := int(binary.LittleEndian.Uint16(key[8:10]))
	nameStart := 10
	// 如果 name_len + 10 不等于 len(key)，可能是 hashed key（多 4 字节 hash）
	if 10+nameLen != len(key) {
		// 试 hashed key：name_len_and_hash 32-bit
		if len(key) >= 12 {
			combined := binary.LittleEndian.Uint32(key[8:12])
			nameLen = int(combined & 0x3FF) // 低 10 位为长度
			nameStart = 12
		}
	}
	if nameStart+nameLen > len(key) {
		return nil
	}
	name := string(bytes.TrimRight(key[nameStart:nameStart+nameLen], "\x00"))

	return &DirEntry{
		ParentID:  jk.ObjID,
		Name:      name,
		FileID:    binary.LittleEndian.Uint64(val[0:8]),
		DateAdded: binary.LittleEndian.Uint64(val[8:16]),
		Type:      binary.LittleEndian.Uint16(val[16:18]),
	}
}

// FileExtentRecord 是 file_extent record（描述文件数据如何映射到容器物理块）。
//
// j_file_extent_val_t:
//
//	uint64 len_and_flags  ( low 56 bits = byte length, high 8 bits = flags )
//	uint64 phys_block_num
//	uint64 crypto_id
type FileExtentRecord struct {
	OwnerObjID    uint64
	LogicalOffset uint64 // 文件内字节偏移（来自 key）
	Length        uint64 // 字节
	PhysicalBlock uint64 // 容器内物理块号；0 = sparse hole
}

// ParseFileExtentRecord 解 j_file_extent_*。
//
// j_file_extent_key_t:
//
//	j_key (8) + logical_addr (uint64 LE)
func ParseFileExtentRecord(key, val []byte) *FileExtentRecord {
	jk, err := ParseJKey(key)
	if err != nil || jk.Type != JTypeFileExtent {
		return nil
	}
	if len(key) < 16 || len(val) < 24 {
		return nil
	}
	lenAndFlags := binary.LittleEndian.Uint64(val[0:8])
	return &FileExtentRecord{
		OwnerObjID:    jk.ObjID,
		LogicalOffset: binary.LittleEndian.Uint64(key[8:16]),
		Length:        lenAndFlags & ((1 << 56) - 1),
		PhysicalBlock: binary.LittleEndian.Uint64(val[8:16]),
	}
}
