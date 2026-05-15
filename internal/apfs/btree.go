package apfs

import (
	"encoding/binary"
	"fmt"
)

// APFS B-tree 节点的通用 parser。规范来自 Apple File System Reference 第 13 章
// （"B-Trees"）。节点结构（block_size 字节）：
//
//	+0x00  obj_phys (32 bytes)         通用对象头：cksum / oid / xid / type / subtype
//	+0x20  btn_flags         uint16    BTNODE_ROOT(0x1) / LEAF(0x2) / FIXED_KV_SIZE(0x4) ...
//	+0x22  btn_level         uint16    0 = leaf；>0 = 分支
//	+0x24  btn_nkeys         uint32    本节点 entries 数
//	+0x28  btn_table_space.off  uint16  TOC 在 entries area 里的字节偏移
//	+0x2A  btn_table_space.len  uint16  TOC 字节长度
//	+0x2C  btn_free_space.off / .len
//	+0x30  btn_key_free_list.off / .len
//	+0x34  btn_val_free_list.off / .len
//	+0x38  data[]                       —— TOC + keys + values + 可选 footer（root only）
//
// TOC 项有两种格式：
//   - FIXED_KV_SIZE：每项 4 字节（key_offset uint16 + val_offset uint16）
//   - VARIABLE：每项 8 字节（key_offset, key_len, val_offset, val_len 各 uint16）
//
// 偏移基准点：
//   - key_offset 是从 entries area 起点（btn_data 起点 + key_area_start）算起
//   - val_offset 是从 entries area 末尾**反向**算起（向左走 val_offset 字节才是值首字节）

const (
	BTNodeFlagRoot        uint16 = 0x0001
	BTNodeFlagLeaf        uint16 = 0x0002
	BTNodeFlagFixedKVSize uint16 = 0x0004
	BTNodeFlagHashed      uint16 = 0x0008
	BTNodeFlagNoHeader    uint16 = 0x0010
)

// BTreeEntry 是节点里一条 (key, value) 记录的原始字节。
// 上层按 record_type 自行解析（INODE / DIR_REC / FILE_EXTENT 等）。
type BTreeEntry struct {
	Key   []byte
	Value []byte
}

// BTreeNode 是单个节点的解析结果。Entries 已经按节点内顺序排好。
type BTreeNode struct {
	Flags     uint16
	Level     uint16 // 0=leaf
	NumKeys   uint32
	IsLeaf    bool
	IsRoot    bool
	IsFixedKV bool
	Entries   []BTreeEntry
	// 当 IsRoot=true 时这两段才有意义（footer 在节点尾部 40 字节）
	NodeSize uint32 // 节点字节数（一般 = block_size）
	KeySize  uint32 // FixedKV 才填写
	ValSize  uint32 // FixedKV 才填写
}

// ParseBTreeNode 给定一个节点的字节切片解出来；调用方负责按 nx_block_size 整段读入。
func ParseBTreeNode(buf []byte) (*BTreeNode, error) {
	const headerLen = 0x38
	if len(buf) < headerLen {
		return nil, fmt.Errorf("BTreeNode 节点太短: %d", len(buf))
	}

	n := &BTreeNode{
		Flags:   binary.LittleEndian.Uint16(buf[0x20:0x22]),
		Level:   binary.LittleEndian.Uint16(buf[0x22:0x24]),
		NumKeys: binary.LittleEndian.Uint32(buf[0x24:0x28]),
	}
	n.IsLeaf = n.Flags&BTNodeFlagLeaf != 0 || n.Level == 0
	n.IsRoot = n.Flags&BTNodeFlagRoot != 0
	n.IsFixedKV = n.Flags&BTNodeFlagFixedKVSize != 0

	tocOff := binary.LittleEndian.Uint16(buf[0x28:0x2A])
	tocLen := binary.LittleEndian.Uint16(buf[0x2A:0x2C])

	// entries area 起点 = 0x38（紧接节点头）
	const entriesStart = headerLen
	tocAbs := entriesStart + int(tocOff)
	if tocAbs+int(tocLen) > len(buf) {
		return nil, fmt.Errorf("TOC 越界: start=%d len=%d node=%d", tocAbs, tocLen, len(buf))
	}

	// root 节点节尾 40 字节是 btree_info_t footer（含 fixed key/value size 等）
	endOfData := len(buf)
	if n.IsRoot {
		const footerLen = 40
		if len(buf) >= footerLen {
			endOfData = len(buf) - footerLen
			n.NodeSize = binary.LittleEndian.Uint32(buf[len(buf)-footerLen+8 : len(buf)-footerLen+12])
			n.KeySize = binary.LittleEndian.Uint32(buf[len(buf)-footerLen+12 : len(buf)-footerLen+16])
			n.ValSize = binary.LittleEndian.Uint32(buf[len(buf)-footerLen+16 : len(buf)-footerLen+20])
		}
	}

	// values area 末尾 = endOfData；值偏移从这里反向算
	valsEnd := endOfData

	// 解析 TOC
	for i := uint32(0); i < n.NumKeys; i++ {
		var keyOff, keyLen, valOff, valLen uint16
		if n.IsFixedKV {
			// 4 字节项
			itemOff := tocAbs + int(i)*4
			if itemOff+4 > tocAbs+int(tocLen) {
				break
			}
			keyOff = binary.LittleEndian.Uint16(buf[itemOff : itemOff+2])
			valOff = binary.LittleEndian.Uint16(buf[itemOff+2 : itemOff+4])
			keyLen = uint16(n.KeySize)
			valLen = uint16(n.ValSize)
		} else {
			// 8 字节项
			itemOff := tocAbs + int(i)*8
			if itemOff+8 > tocAbs+int(tocLen) {
				break
			}
			keyOff = binary.LittleEndian.Uint16(buf[itemOff : itemOff+2])
			keyLen = binary.LittleEndian.Uint16(buf[itemOff+2 : itemOff+4])
			valOff = binary.LittleEndian.Uint16(buf[itemOff+4 : itemOff+6])
			valLen = binary.LittleEndian.Uint16(buf[itemOff+6 : itemOff+8])
		}

		// keys area 起点 = tocAbs + tocLen
		keyArea := tocAbs + int(tocLen)
		keyStart := keyArea + int(keyOff)
		keyEnd := keyStart + int(keyLen)
		if keyStart < 0 || keyEnd > endOfData || keyEnd < keyStart {
			continue
		}

		// value: 从 valsEnd 反向算 valOff 个字节再走 valLen
		valStart := valsEnd - int(valOff)
		valEnd := valStart + int(valLen)
		if valStart < keyEnd || valEnd > endOfData {
			continue
		}

		key := make([]byte, keyEnd-keyStart)
		copy(key, buf[keyStart:keyEnd])
		val := make([]byte, valEnd-valStart)
		copy(val, buf[valStart:valEnd])
		n.Entries = append(n.Entries, BTreeEntry{Key: key, Value: val})
	}

	return n, nil
}
