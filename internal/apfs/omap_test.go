package apfs

import (
	"encoding/binary"
	"testing"
)

// 合成一个最小 omap leaf 节点（variable-KV）：3 个 (oid, xid) → (paddr) 映射。
func makeOmapLeafNode(t *testing.T, blockSize int, entries []OmapEntry) []byte {
	t.Helper()
	buf := make([]byte, blockSize)
	binary.LittleEndian.PutUint16(buf[0x20:0x22], BTNodeFlagLeaf)
	binary.LittleEndian.PutUint16(buf[0x22:0x24], 0) // level
	binary.LittleEndian.PutUint32(buf[0x24:0x28], uint32(len(entries)))
	tocLen := uint16(len(entries) * 8)
	binary.LittleEndian.PutUint16(buf[0x28:0x2A], 0)
	binary.LittleEndian.PutUint16(buf[0x2A:0x2C], tocLen)

	tocAt := 0x38
	keyArea := tocAt + int(tocLen)

	const keyLen = 16
	const valLen = 16

	for i, e := range entries {
		// TOC 项
		itm := tocAt + i*8
		binary.LittleEndian.PutUint16(buf[itm:itm+2], uint16(i*keyLen))
		binary.LittleEndian.PutUint16(buf[itm+2:itm+4], keyLen)
		binary.LittleEndian.PutUint16(buf[itm+4:itm+6], uint16((i+1)*valLen))
		binary.LittleEndian.PutUint16(buf[itm+6:itm+8], valLen)
		// key (oid + xid)
		ks := keyArea + i*keyLen
		binary.LittleEndian.PutUint64(buf[ks:ks+8], e.OID)
		binary.LittleEndian.PutUint64(buf[ks+8:ks+16], e.XID)
		// value (flags + size + paddr)
		vs := blockSize - (i+1)*valLen
		binary.LittleEndian.PutUint32(buf[vs:vs+4], 0)
		binary.LittleEndian.PutUint32(buf[vs+4:vs+8], e.Size)
		binary.LittleEndian.PutUint64(buf[vs+8:vs+16], e.PAddr)
	}
	return buf
}

func TestParseOmapLeaf_AndResolve(t *testing.T) {
	const blockSize = 256
	entries := []OmapEntry{
		{OID: 100, XID: 1, PAddr: 0xAAA, Size: blockSize},
		{OID: 100, XID: 5, PAddr: 0xBBB, Size: blockSize}, // 同 OID 不同 xid，应取大的
		{OID: 200, XID: 3, PAddr: 0xCCC, Size: blockSize},
	}
	buf := makeOmapLeafNode(t, blockSize, entries)
	node, err := ParseBTreeNode(buf)
	if err != nil {
		t.Fatalf("ParseBTreeNode: %v", err)
	}
	if !node.IsLeaf {
		t.Fatal("应是 leaf")
	}
	if len(node.Entries) != 3 {
		t.Fatalf("entries 数: %d want 3", len(node.Entries))
	}

	// 模拟 walkOmapTree 的"取最高 xid"逻辑
	out := make(map[uint64]OmapEntry)
	for _, ent := range node.Entries {
		oid := binary.LittleEndian.Uint64(ent.Key[0:8])
		xid := binary.LittleEndian.Uint64(ent.Key[8:16])
		paddr := binary.LittleEndian.Uint64(ent.Value[8:16])
		size := binary.LittleEndian.Uint32(ent.Value[4:8])
		if prev, ok := out[oid]; !ok || xid > prev.XID {
			out[oid] = OmapEntry{OID: oid, XID: xid, PAddr: paddr, Size: size}
		}
	}

	if p, ok := ResolveVirtual(out, 100); !ok || p != 0xBBB {
		t.Errorf("OID 100 应解到 0xBBB（大 xid），实际 0x%x ok=%v", p, ok)
	}
	if p, ok := ResolveVirtual(out, 200); !ok || p != 0xCCC {
		t.Errorf("OID 200 应解到 0xCCC，实际 0x%x ok=%v", p, ok)
	}
	if _, ok := ResolveVirtual(out, 999); ok {
		t.Error("未知 OID 应返回 ok=false")
	}
}

func TestParseOmapPhys(t *testing.T) {
	buf := make([]byte, 64)
	binary.LittleEndian.PutUint64(buf[0x30:0x38], 0xABCDEF)
	op, err := ParseOmapPhys(buf)
	if err != nil {
		t.Fatalf("ParseOmapPhys: %v", err)
	}
	if op.TreeOID != 0xABCDEF {
		t.Errorf("TreeOID=%x want 0xABCDEF", op.TreeOID)
	}
}
