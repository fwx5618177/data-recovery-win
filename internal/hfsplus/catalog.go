package hfsplus

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// HFS+ Catalog B-tree 节点解析器。HFS+ 用 B-tree 存目录结构（catalog）+ extent 映射等；
// 我们只关注 catalog tree 用来枚举文件。
//
// B-tree node 通用头（14 字节）：
//
//	+0x00  fLink      uint32  下一个 sibling node 的 nodeID
//	+0x04  bLink      uint32  上一个 sibling node 的 nodeID
//	+0x08  kind       int8    -1=leaf  0=index  1=header  2=map
//	+0x09  height     uint8   叶节点 = 1，向上递增
//	+0x0A  numRecords uint16  本 node 内 records 数
//	+0x0C  reserved   uint16
//
// 节点尾部是 record offset table：从节点末尾倒着排，每项 2 字节，
// 从最后第 2 字节开始：offset[N-1], offset[N-2], ..., offset[0]，
// 每个 offset 是从节点起点算起的 record 起点字节。

const (
	BTNodeKindLeaf   int8 = -1
	BTNodeKindIndex  int8 = 0
	BTNodeKindHeader int8 = 1
	BTNodeKindMap    int8 = 2
)

// Catalog record types
const (
	CatRecordFolder         int16 = 0x0001
	CatRecordFile           int16 = 0x0002
	CatRecordFolderThread   int16 = 0x0003
	CatRecordFileThread     int16 = 0x0004
)

// CatalogKey 是 catalog tree 的 key：
//
//	+0x00 keyLength  uint16  key 总字节数（不含本字段）
//	+0x02 parentID   uint32  父目录的 catalog node ID (CNID)
//	+0x06 nameLen    uint16  名字 UTF-16 单元数（不是字节）
//	+0x08 name       UTF-16BE
type CatalogKey struct {
	ParentID uint32
	Name     string
}

// ParseCatalogKey 从 record 起点的字节切片里解出 key。
// 返回 key 总占用字节数（含 keyLength 字段本身），方便定位 value 起点。
func ParseCatalogKey(buf []byte) (CatalogKey, int, error) {
	if len(buf) < 8 {
		return CatalogKey{}, 0, fmt.Errorf("catalog key 头太短")
	}
	keyLen := int(binary.BigEndian.Uint16(buf[0:2]))
	if 2+keyLen > len(buf) {
		return CatalogKey{}, 0, fmt.Errorf("catalog key 越界: keyLen=%d buf=%d", keyLen, len(buf))
	}
	parentID := binary.BigEndian.Uint32(buf[2:6])
	nameLen := int(binary.BigEndian.Uint16(buf[6:8]))
	if 8+nameLen*2 > 2+keyLen {
		return CatalogKey{}, 0, fmt.Errorf("catalog name 越界")
	}
	codes := make([]uint16, nameLen)
	for i := 0; i < nameLen; i++ {
		codes[i] = binary.BigEndian.Uint16(buf[8+i*2 : 8+i*2+2])
	}
	// keyLength 字段本身 2 字节 + keyLen 字节内容；
	// 但 catalog key 实际还有 padding 到 2 字节对齐——HFS+ tree node 用 padding 让 record 起点 2 对齐。
	totalKeyBytes := 2 + keyLen
	if totalKeyBytes%2 != 0 {
		totalKeyBytes++
	}
	return CatalogKey{
		ParentID: parentID,
		Name:     string(utf16.Decode(codes)),
	}, totalKeyBytes, nil
}

// CatalogFolder 是 kHFSPlusFolderRecord 的关键字段。
type CatalogFolder struct {
	ParentID    uint32 // 来自 key
	Name        string
	FolderID    uint32 // CNID
	Valence     uint32 // 子项数
	CreateDate  uint32 // Mac 1904 epoch
	ModifyDate  uint32
	AccessDate  uint32
}

// CatalogFile 是 kHFSPlusFileRecord 的关键字段。
type CatalogFile struct {
	ParentID   uint32
	Name       string
	FileID     uint32
	CreateDate uint32
	ModifyDate uint32
	LogicalSize uint64 // data fork 字节数
	TotalBlocks uint32
	// data fork extents（最多 8 个；超过的在 extents overflow tree 里）
	Extents [8]ForkExtent
}

// ForkExtent 是单段 (startBlock, blockCount)。
type ForkExtent struct {
	StartBlock uint32
	BlockCount uint32
}

// ParseCatalogFolder 解析 kHFSPlusFolderRecord 的 value 区。
func ParseCatalogFolder(key CatalogKey, val []byte) *CatalogFolder {
	if len(val) < 0x58 {
		return nil
	}
	if int16(binary.BigEndian.Uint16(val[0:2])) != CatRecordFolder {
		return nil
	}
	return &CatalogFolder{
		ParentID:   key.ParentID,
		Name:       key.Name,
		Valence:    binary.BigEndian.Uint32(val[4:8]),
		FolderID:   binary.BigEndian.Uint32(val[8:12]),
		CreateDate: binary.BigEndian.Uint32(val[12:16]),
		ModifyDate: binary.BigEndian.Uint32(val[16:20]),
		AccessDate: binary.BigEndian.Uint32(val[24:28]),
	}
}

// ParseCatalogFile 解析 kHFSPlusFileRecord（节点偏移见 TN1150）：
//
//	+0x00 recordType (2)        = 0x0002
//	+0x02 flags (2)
//	+0x04 reserved (4)
//	+0x08 fileID (4)
//	+0x0C createDate (4)
//	+0x10 contentModDate (4)
//	+0x14 attributeModDate (4)
//	+0x18 accessDate (4)
//	+0x1C backupDate (4)
//	+0x20 permissions (16)
//	+0x30 userInfo (16) finderInfo
//	+0x40 finderInfo (16)
//	+0x50 textEncoding (4)
//	+0x54 reserved (4)
//	+0x58 dataFork (HFSPlusForkData = 80 字节: logicalSize 8 + clumpSize 4 + totalBlocks 4 + 8*ForkExtent 64)
//	+0xA8 resourceFork (80)
func ParseCatalogFile(key CatalogKey, val []byte) *CatalogFile {
	if len(val) < 0xA8 {
		return nil
	}
	if int16(binary.BigEndian.Uint16(val[0:2])) != CatRecordFile {
		return nil
	}
	f := &CatalogFile{
		ParentID:   key.ParentID,
		Name:       key.Name,
		FileID:     binary.BigEndian.Uint32(val[8:12]),
		CreateDate: binary.BigEndian.Uint32(val[12:16]),
		ModifyDate: binary.BigEndian.Uint32(val[16:20]),
	}
	// data fork @ +0x58
	f.LogicalSize = binary.BigEndian.Uint64(val[0x58 : 0x58+8])
	f.TotalBlocks = binary.BigEndian.Uint32(val[0x58+12 : 0x58+16])
	for i := 0; i < 8; i++ {
		off := 0x58 + 16 + i*8
		f.Extents[i] = ForkExtent{
			StartBlock: binary.BigEndian.Uint32(val[off : off+4]),
			BlockCount: binary.BigEndian.Uint32(val[off+4 : off+8]),
		}
	}
	return f
}

// CatalogNode 是解析后的 catalog B-tree node。
type CatalogNode struct {
	Kind        int8
	Height      uint8
	NumRecords  uint16
	Records     []CatalogRecord // 已按 record 索引顺序排好
}

// CatalogRecord 是节点内的一条 (key, value) 记录。
// kind=Leaf 时 Folder/File 会被填上对应字段；index/header/map 节点的 Folder/File 都为 nil。
type CatalogRecord struct {
	Key    CatalogKey
	// RawKey 是 key 区域原始字节（含 2 byte keyLength 头）；
	// 给 extents overflow / attributes B-tree 等**非** catalog 用途的 key 解析用。
	RawKey []byte
	RawVal []byte
	Folder *CatalogFolder
	File   *CatalogFile
}

// ParseCatalogNode 解析单个 node（按 nodeSize 字节）。
//
// nodeSize 来自 catalog header。
func ParseCatalogNode(buf []byte) (*CatalogNode, error) {
	if len(buf) < 14 {
		return nil, fmt.Errorf("catalog node 太短")
	}
	n := &CatalogNode{
		Kind:       int8(buf[8]),
		Height:     buf[9],
		NumRecords: binary.BigEndian.Uint16(buf[10:12]),
	}

	// record offset table 在节点末尾，从 -2 开始倒着排
	offsetTableStart := len(buf) - 2*int(n.NumRecords) - 2
	if offsetTableStart < 14 {
		return nil, fmt.Errorf("offset table 越界")
	}

	// 读取 N+1 个 offset：第 N 个是 free space 起点（recordEnd 用）
	offs := make([]int, n.NumRecords+1)
	for i := 0; i <= int(n.NumRecords); i++ {
		// offset[0] 在最后 -2 字节，offset[1] 在 -4，...
		idx := len(buf) - 2*(i+1)
		offs[i] = int(binary.BigEndian.Uint16(buf[idx : idx+2]))
	}

	for i := 0; i < int(n.NumRecords); i++ {
		recStart := offs[i]
		recEnd := offs[i+1]
		if recStart < 14 || recEnd > offsetTableStart || recEnd < recStart {
			continue
		}
		rec := buf[recStart:recEnd]
		// catalog record: key + value
		key, keyBytes, err := ParseCatalogKey(rec)
		if err != nil {
			continue
		}
		if keyBytes >= len(rec) {
			continue
		}
		val := rec[keyBytes:]

		rawKey := make([]byte, keyBytes)
		copy(rawKey, rec[:keyBytes])
		cr := CatalogRecord{Key: key, RawKey: rawKey, RawVal: val}
		if n.Kind == BTNodeKindLeaf && len(val) >= 2 {
			rt := int16(binary.BigEndian.Uint16(val[0:2]))
			switch rt {
			case CatRecordFolder:
				cr.Folder = ParseCatalogFolder(key, val)
			case CatRecordFile:
				cr.File = ParseCatalogFile(key, val)
			}
		}
		n.Records = append(n.Records, cr)
	}
	return n, nil
}
