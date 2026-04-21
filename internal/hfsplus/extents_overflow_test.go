package hfsplus

import (
	"encoding/binary"
	"testing"
)

// 合成一个 leaf node，里面放 1 条 extents overflow record（fileID=42, fork=0, 3 个 extent）
func TestScanLeafForExtentsOverflow_FindsRecord(t *testing.T) {
	const nodeSize = 256
	buf := make([]byte, nodeSize)

	leafKind := BTNodeKindLeaf
	buf[8] = byte(leafKind)
	buf[9] = 1                                          // height
	binary.BigEndian.PutUint16(buf[10:12], 1)            // 1 record

	// record 内容：12 byte key + 8*8 byte extents = 76 字节
	rec := make([]byte, 12+8*8)
	binary.BigEndian.PutUint16(rec[0:2], 10) // keyLength
	rec[2] = ForkTypeData
	rec[3] = 0
	binary.BigEndian.PutUint32(rec[4:8], 42)    // fileID
	binary.BigEndian.PutUint32(rec[8:12], 8)    // startBlock（catalog 里前 8 个之后）
	// 3 个 extent
	binary.BigEndian.PutUint32(rec[12:16], 100)
	binary.BigEndian.PutUint32(rec[16:20], 5)
	binary.BigEndian.PutUint32(rec[20:24], 200)
	binary.BigEndian.PutUint32(rec[24:28], 7)
	binary.BigEndian.PutUint32(rec[28:32], 350)
	binary.BigEndian.PutUint32(rec[32:36], 3)
	// 第 4 个 BlockCount=0 表示终止

	recStart := 14
	copy(buf[recStart:], rec)
	// offset table 倒排：offset[0] = recStart, offset[1] = recStart + len(rec)
	binary.BigEndian.PutUint16(buf[nodeSize-2:nodeSize], uint16(recStart))
	binary.BigEndian.PutUint16(buf[nodeSize-4:nodeSize-2], uint16(recStart+len(rec)))

	got := scanLeafForExtentsOverflow(buf, 42, ForkTypeData)
	if len(got) != 3 {
		t.Fatalf("找到 %d 个 extent want 3", len(got))
	}
	want := []ForkExtent{
		{StartBlock: 100, BlockCount: 5},
		{StartBlock: 200, BlockCount: 7},
		{StartBlock: 350, BlockCount: 3},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("extent[%d]=%+v want %+v", i, got[i], w)
		}
	}
}

// fileID 不匹配应返回空
func TestScanLeafForExtentsOverflow_NoMatchReturnsEmpty(t *testing.T) {
	const nodeSize = 256
	buf := make([]byte, nodeSize)
	leafKind := BTNodeKindLeaf
	buf[8] = byte(leafKind)
	binary.BigEndian.PutUint16(buf[10:12], 1)

	rec := make([]byte, 12+8*8)
	binary.BigEndian.PutUint16(rec[0:2], 10)
	rec[2] = ForkTypeData
	binary.BigEndian.PutUint32(rec[4:8], 99) // 不是 42
	binary.BigEndian.PutUint32(rec[12:16], 1)
	binary.BigEndian.PutUint32(rec[16:20], 1)
	copy(buf[14:], rec)
	binary.BigEndian.PutUint16(buf[nodeSize-2:nodeSize], 14)
	binary.BigEndian.PutUint16(buf[nodeSize-4:nodeSize-2], uint16(14+len(rec)))

	got := scanLeafForExtentsOverflow(buf, 42, ForkTypeData)
	if len(got) != 0 {
		t.Errorf("不匹配 fileID 应返回空，得到 %d 个", len(got))
	}
}

func TestSortForkExtents_Ascending(t *testing.T) {
	in := []ForkExtent{
		{StartBlock: 300},
		{StartBlock: 100},
		{StartBlock: 200},
	}
	sortForkExtents(in)
	if in[0].StartBlock != 100 || in[1].StartBlock != 200 || in[2].StartBlock != 300 {
		t.Errorf("排序错: %+v", in)
	}
}
