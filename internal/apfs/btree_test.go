package apfs

import (
	"encoding/binary"
	"testing"
)

// 合成一个最小可解的 leaf BTreeNode，验证 ParseBTreeNode 能枚举出 entries 且不越界。
//
// 节点布局（按 entries area 偏移，从节点头 0x38 起）：
//
//	TOC（变长项，每项 8 字节）：
//	    item0: keyOff=0   keyLen=K  valOff=V   valLen=V
//	    item1: keyOff=K   keyLen=K  valOff=2V  valLen=V
//	keys area:
//	    K bytes for key0, K bytes for key1
//	... 中间 free space ...
//	values area (从节点尾部反向)：
//	    val1 (V bytes), val0 (V bytes)
func TestParseBTreeNode_Leaf_VariableKV(t *testing.T) {
	const (
		keyLen = 8
		valLen = 4
		nodeSz = 256
	)
	buf := make([]byte, nodeSz)

	// 节点头
	binary.LittleEndian.PutUint16(buf[0x20:0x22], BTNodeFlagLeaf) // flags
	binary.LittleEndian.PutUint16(buf[0x22:0x24], 0)              // level = 0
	binary.LittleEndian.PutUint32(buf[0x24:0x28], 2)              // 2 entries
	tocOff := uint16(0)                                           // entries area 起点偏移
	tocLen := uint16(2 * 8)                                       // 2 项 × 8 字节
	binary.LittleEndian.PutUint16(buf[0x28:0x2A], tocOff)
	binary.LittleEndian.PutUint16(buf[0x2A:0x2C], tocLen)

	// TOC 在 entries area + tocOff = 0x38 + 0
	tocAt := 0x38 + int(tocOff)
	// item0: keyOff=0, keyLen=8, valOff=valLen, valLen=4
	binary.LittleEndian.PutUint16(buf[tocAt+0:tocAt+2], 0)
	binary.LittleEndian.PutUint16(buf[tocAt+2:tocAt+4], keyLen)
	binary.LittleEndian.PutUint16(buf[tocAt+4:tocAt+6], valLen) // valOff = 4 -> 反向 4 字节定位
	binary.LittleEndian.PutUint16(buf[tocAt+6:tocAt+8], valLen)
	// item1: keyOff=8, keyLen=8, valOff=2*valLen=8, valLen=4
	binary.LittleEndian.PutUint16(buf[tocAt+8:tocAt+10], keyLen)
	binary.LittleEndian.PutUint16(buf[tocAt+10:tocAt+12], keyLen)
	binary.LittleEndian.PutUint16(buf[tocAt+12:tocAt+14], 2*valLen)
	binary.LittleEndian.PutUint16(buf[tocAt+14:tocAt+16], valLen)

	// keys area 起点 = tocAt + tocLen = 0x38 + 16
	keyArea := tocAt + int(tocLen)
	for i := 0; i < keyLen; i++ {
		buf[keyArea+i] = byte(0xA0 + i)         // key0
		buf[keyArea+keyLen+i] = byte(0xB0 + i)  // key1
	}

	// values area 末尾在节点尾（无 root footer，因为不是 root）
	valsEnd := nodeSz
	// val0：从 valsEnd 反向 valLen
	for i := 0; i < valLen; i++ {
		buf[valsEnd-valLen+i] = byte(0xC0 + i) // val0
	}
	// val1：从 valsEnd 反向 2*valLen
	for i := 0; i < valLen; i++ {
		buf[valsEnd-2*valLen+i] = byte(0xD0 + i) // val1
	}

	n, err := ParseBTreeNode(buf)
	if err != nil {
		t.Fatalf("ParseBTreeNode: %v", err)
	}
	if !n.IsLeaf {
		t.Error("应识别为 leaf")
	}
	if n.NumKeys != 2 || len(n.Entries) != 2 {
		t.Fatalf("entries 数量错: nkeys=%d entries=%d", n.NumKeys, len(n.Entries))
	}

	// 验证 key0
	for i := 0; i < keyLen; i++ {
		if n.Entries[0].Key[i] != byte(0xA0+i) {
			t.Errorf("key0[%d]=0x%X want 0x%X", i, n.Entries[0].Key[i], 0xA0+i)
		}
	}
	// 验证 val0
	for i := 0; i < valLen; i++ {
		if n.Entries[0].Value[i] != byte(0xC0+i) {
			t.Errorf("val0[%d]=0x%X want 0x%X", i, n.Entries[0].Value[i], 0xC0+i)
		}
	}
}

// 解析一个手工合成的 j_drec_val_t / DirEntry
func TestParseDirEntry_Unhashed(t *testing.T) {
	// key: 8 字节 j_key + 2 字节 name_len + name
	name := "Photos.app"
	key := make([]byte, 10+len(name))
	binary.LittleEndian.PutUint64(key[0:8], (uint64(JTypeDirRec)<<60)|0x1234)
	binary.LittleEndian.PutUint16(key[8:10], uint16(len(name)))
	copy(key[10:], name)

	val := make([]byte, 18)
	binary.LittleEndian.PutUint64(val[0:8], 0x9999)        // file_id
	binary.LittleEndian.PutUint64(val[8:16], 0x1700000000) // date_added
	binary.LittleEndian.PutUint16(val[16:18], 4)           // DT_DIR

	d := ParseDirEntry(key, val)
	if d == nil {
		t.Fatal("ParseDirEntry 返回 nil")
	}
	if d.ParentID != 0x1234 {
		t.Errorf("ParentID=%x want 0x1234", d.ParentID)
	}
	if d.FileID != 0x9999 {
		t.Errorf("FileID=%x want 0x9999", d.FileID)
	}
	if d.Name != name {
		t.Errorf("Name=%q want %q", d.Name, name)
	}
	if d.Type != 4 {
		t.Errorf("Type=%d want 4", d.Type)
	}
}

func TestParseInodeRecord_BasicFields(t *testing.T) {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key[0:8], (uint64(JTypeInode)<<60)|0xABCD)

	val := make([]byte, 0x5C)
	binary.LittleEndian.PutUint64(val[0:8], 0x1)    // ParentID = root
	binary.LittleEndian.PutUint64(val[8:16], 0x42)  // PrivateID
	binary.LittleEndian.PutUint64(val[16:24], 100)  // CreateTime
	binary.LittleEndian.PutUint64(val[24:32], 200)  // ModTime
	binary.LittleEndian.PutUint32(val[56:60], 7)    // NumChildren
	binary.LittleEndian.PutUint16(val[88:90], 0o755)// Mode

	in := ParseInodeRecord(key, val)
	if in == nil {
		t.Fatal("ParseInodeRecord 返回 nil")
	}
	if in.ObjID != 0xABCD {
		t.Errorf("ObjID=%x want 0xABCD", in.ObjID)
	}
	if in.ParentID != 1 || in.PrivateID != 0x42 {
		t.Errorf("Parent/Private 错: %x %x", in.ParentID, in.PrivateID)
	}
	if in.NumChildren != 7 {
		t.Errorf("NumChildren=%d want 7", in.NumChildren)
	}
	if in.Mode != 0o755 {
		t.Errorf("Mode=0o%o want 0o755", in.Mode)
	}
}

func TestParseFileExtentRecord(t *testing.T) {
	key := make([]byte, 16)
	binary.LittleEndian.PutUint64(key[0:8], (uint64(JTypeFileExtent)<<60)|0x42)
	binary.LittleEndian.PutUint64(key[8:16], 0x10000) // logical offset = 64KB

	val := make([]byte, 24)
	// length = 4096, flags = 0x80
	binary.LittleEndian.PutUint64(val[0:8], (uint64(0x80)<<56)|4096)
	binary.LittleEndian.PutUint64(val[8:16], 0xDEAD)  // physical block

	ex := ParseFileExtentRecord(key, val)
	if ex == nil {
		t.Fatal("ParseFileExtentRecord 返回 nil")
	}
	if ex.OwnerObjID != 0x42 {
		t.Errorf("OwnerObjID=%x", ex.OwnerObjID)
	}
	if ex.LogicalOffset != 0x10000 {
		t.Errorf("LogicalOffset=%x", ex.LogicalOffset)
	}
	if ex.Length != 4096 {
		t.Errorf("Length=%d", ex.Length)
	}
	if ex.PhysicalBlock != 0xDEAD {
		t.Errorf("PhysicalBlock=%x", ex.PhysicalBlock)
	}
}
