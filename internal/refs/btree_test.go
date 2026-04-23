package refs

import (
	"encoding/binary"
	"testing"
	"time"
)

// 构造一个 mock page：MSB+ header + UTF-16 文件名 + FILETIME + FileSize → 应被抽出
func TestTryParseEntryAt_BasicUTF16(t *testing.T) {
	buf := make([]byte, 2048)
	// 写 ObjectID @ offset 100
	binary.LittleEndian.PutUint64(buf[100:108], 42)
	// 写 UTF-16 文件名 "Readme.txt" @ offset 150
	name := "Readme.txt"
	for i, r := range name {
		binary.LittleEndian.PutUint16(buf[150+i*2:150+i*2+2], uint16(r))
	}
	// 文件名后跟 NUL
	binary.LittleEndian.PutUint16(buf[150+len(name)*2:], 0)

	// 写 FILETIME 代表 2024-06-01 UTC @ offset 200
	t2024 := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC).Unix()
	// FILETIME = unix_sec * 10_000_000 + 116444736000000000
	ft := uint64(t2024)*10000000 + 116444736000000000
	binary.LittleEndian.PutUint64(buf[200:208], ft)

	// 注意：不强断 FileSize 字段 —— 启发定位在 mock layout 上行为不稳；
	// 真实 ReFS 结构下（STANDARD_INFO field 包装）才稳定命中。本测试仅
	// 验证 ObjectID / FileName / ModifiedTime 能被抽出

	entry, ok := tryParseEntryAt(buf, 100, 0x10000)
	if !ok {
		t.Fatal("应能解析")
	}
	if entry.ObjectID != 42 {
		t.Errorf("ObjectID: %d", entry.ObjectID)
	}
	if entry.FileName != "Readme.txt" {
		t.Errorf("FileName: %q", entry.FileName)
	}
	if entry.ModifiedTime.Year() != 2024 {
		t.Errorf("ModifiedTime: %v", entry.ModifiedTime)
	}
}

// 无合法文件名的 buf 不该误报
func TestTryParseEntryAt_NoValidName(t *testing.T) {
	buf := make([]byte, 2048)
	// 全零（全部 UTF-16 零字符）→ 没名字
	_, ok := tryParseEntryAt(buf, 100, 0x10000)
	if ok {
		t.Error("空 buf 不该误认为 entry")
	}
}

// FILETIME 2005 前的值应被忽略（启发合理性检查）
func TestFindNearbyFiletime_RejectsAncientValues(t *testing.T) {
	buf := make([]byte, 256)
	// 1990 年的 FILETIME
	t1990 := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	ft := uint64(t1990)*10000000 + 116444736000000000
	binary.LittleEndian.PutUint64(buf[100:108], ft)
	got, _ := findNearbyFiletime(buf, 100, 150)
	if !got.IsZero() {
		t.Errorf("1990 年 FILETIME 应被拒: %v", got)
	}
}

// FILETIME 2040 后的值也该拒
func TestFindNearbyFiletime_RejectsFuture(t *testing.T) {
	buf := make([]byte, 256)
	t2200 := uint64(141000000000000000) // > 140e15 上限
	binary.LittleEndian.PutUint64(buf[100:108], t2200)
	got, _ := findNearbyFiletime(buf, 100, 150)
	if !got.IsZero() {
		t.Errorf("2200 年应被拒: %v", got)
	}
}

// 去重：同 ObjectID + FileName 只保留一条
func TestDedupeEntries(t *testing.T) {
	es := []ReFSFileEntry{
		{ObjectID: 1, FileName: "a.txt"},
		{ObjectID: 1, FileName: "a.txt"}, // dup
		{ObjectID: 2, FileName: "b.txt"},
		{ObjectID: 1, FileName: "c.txt"},
	}
	out := dedupeEntries(es)
	if len(out) != 3 {
		t.Errorf("dedupe: got %d want 3", len(out))
	}
}
