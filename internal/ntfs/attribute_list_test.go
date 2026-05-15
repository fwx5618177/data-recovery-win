package ntfs

import (
	"encoding/binary"
	"testing"
)

// 验证 parseAttributeListContent 能解出嵌入式 list entry 序列。
//
// 每条 list entry 24 字节最小（无 name），关键字段：
//
//	+4  recordLen (uint16)
//	+16 mftRef    (uint64) — 低 48 bit = entry number
func TestParseAttributeListContent_BasicRefs(t *testing.T) {
	// 造 3 条 list entry，引用 entry #50, #100, #200
	want := []int64{50, 100, 200}
	buf := make([]byte, 0, 24*3)
	for _, ref := range want {
		entry := make([]byte, 24)
		// recordLen = 24
		binary.LittleEndian.PutUint16(entry[4:6], 24)
		// mftRef 低 48 bit = ref
		binary.LittleEndian.PutUint64(entry[16:24], uint64(ref))
		buf = append(buf, entry...)
	}

	e := &MFTEntry{EntryNumber: 5} // 主条目自身 #5
	parseAttributeListContent(buf, e)

	if len(e.attributeListRefs) != len(want) {
		t.Fatalf("解到 %d refs, want %d", len(e.attributeListRefs), len(want))
	}
	for i, w := range want {
		if e.attributeListRefs[i] != w {
			t.Errorf("ref[%d] = %d, want %d", i, e.attributeListRefs[i], w)
		}
	}
}

// 跳过自引用 + 系统条目（< 24）
func TestParseAttributeListContent_SkipsSelfAndSystem(t *testing.T) {
	refs := []int64{5, 12, 24, 100} // 5=self, 12=system, 24/100 应保留
	buf := make([]byte, 0, 24*len(refs))
	for _, ref := range refs {
		entry := make([]byte, 24)
		binary.LittleEndian.PutUint16(entry[4:6], 24)
		binary.LittleEndian.PutUint64(entry[16:24], uint64(ref))
		buf = append(buf, entry...)
	}
	e := &MFTEntry{EntryNumber: 5}
	parseAttributeListContent(buf, e)

	if len(e.attributeListRefs) != 2 {
		t.Fatalf("应只保留 2 个 (skip self + system), got %d: %v",
			len(e.attributeListRefs), e.attributeListRefs)
	}
	if e.attributeListRefs[0] != 24 || e.attributeListRefs[1] != 100 {
		t.Errorf("结果不对: %v", e.attributeListRefs)
	}
}

// 重复引用应去重
func TestParseAttributeListContent_DedupesRefs(t *testing.T) {
	refs := []int64{100, 200, 100, 300, 200}
	buf := make([]byte, 0, 24*len(refs))
	for _, ref := range refs {
		entry := make([]byte, 24)
		binary.LittleEndian.PutUint16(entry[4:6], 24)
		binary.LittleEndian.PutUint64(entry[16:24], uint64(ref))
		buf = append(buf, entry...)
	}
	e := &MFTEntry{EntryNumber: 5}
	parseAttributeListContent(buf, e)

	if len(e.attributeListRefs) != 3 {
		t.Errorf("应去重为 3, got %v", e.attributeListRefs)
	}
}

// 损坏的 recordLen 应优雅停止而不是越界
func TestParseAttributeListContent_CorruptRecordLen(t *testing.T) {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint16(buf[4:6], 9999) // 远大于剩余字节
	binary.LittleEndian.PutUint64(buf[16:24], 100)

	e := &MFTEntry{EntryNumber: 5}
	parseAttributeListContent(buf, e) // 不应 panic
	// 损坏的 recordLen 应该让循环立即跳出，不收任何 ref
	if len(e.attributeListRefs) != 0 {
		t.Errorf("损坏的 recordLen 不应解出 ref")
	}
}
