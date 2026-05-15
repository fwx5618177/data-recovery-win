package forensics

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"data-recovery/internal/types"
)

func TestBuildTimeline_SortedByTime(t *testing.T) {
	t1 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 6, 1, 10, 0, 0, 0, time.UTC)
	files := []*types.RecoveredFile{
		{FileName: "b.jpg", ModifiedTime: &t2, Size: 100},
		{FileName: "a.jpg", ModifiedTime: &t1, Size: 200},
	}
	events := BuildTimeline(files)
	if len(events) != 2 {
		t.Fatalf("events=%d", len(events))
	}
	if events[0].FileName != "a.jpg" {
		t.Errorf("应按时间排序，第一条应是 a.jpg")
	}
}

// TestBuildTimeline_CarverFilesWithoutTimestamps 回归 v2.8.32 修复的 issue 10：
//
// 用户报"导出时间线文件是空的"。根因：BuildTimeline 之前严格要求 mtime/ctime
// 非空，深度扫描的 carver 文件没 FS 时间戳 → 0 events → 0 字节文件。
//
// v2.8.32: carver 文件兜底写一条 "found" 事件，至少让用户看见有恢复结果。
// 这个测试模拟"只有 carver 文件"的输入（mtime/ctime 全 nil），断言：
//  1. events 数 == 文件数（不是 0）
//  2. 所有 event 的 Action == "found"
//  3. 用 WriteTimelineMACTime 写出来不是空文件
func TestBuildTimeline_CarverFilesWithoutTimestamps(t *testing.T) {
	files := []*types.RecoveredFile{
		{FileName: "carve_0x12345.jpg", Source: "carver", Size: 1024 * 1024},
		{FileName: "carve_0x67890.pdf", Source: "carver", Size: 512 * 1024},
		{FileName: "carve_0xABCDE.png", Source: "carver", Size: 256 * 1024},
	}
	events := BuildTimeline(files)
	if len(events) != 3 {
		t.Fatalf("应生成 3 条 found 事件（不能丢失任何 carver 文件），实际 %d 条", len(events))
	}
	for i, e := range events {
		if e.Action != "found" {
			t.Errorf("event[%d].Action=%q，期望 \"found\"", i, e.Action)
		}
		if e.Time.IsZero() {
			t.Errorf("event[%d].Time 不应为零", i)
		}
	}

	// 写到 mactime body 文件检查不是空的
	var buf bytes.Buffer
	if err := WriteTimelineMACTime(&buf, events); err != nil {
		t.Fatalf("WriteTimelineMACTime: %v", err)
	}
	out := buf.String()
	if len(out) == 0 {
		t.Fatal("mactime 输出是空字符串 —— v2.8.32 修复前的 bug 复发！")
	}
	if !strings.Contains(out, "carve_0x12345.jpg") {
		t.Errorf("mactime 输出应含文件名，实际：%s", out)
	}
}

// TestBuildTimeline_MixedFSAndCarver 验证混合场景（部分文件有时间戳、部分没）
// 都不丢失，且每个文件都产生至少一条事件。
func TestBuildTimeline_MixedFSAndCarver(t *testing.T) {
	tm := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	files := []*types.RecoveredFile{
		// NTFS 文件，有 mtime + ctime → 2 个事件
		{FileName: "doc.docx", Source: "ntfs", ModifiedTime: &tm, CreatedTime: &tm},
		// carver 文件，没时间戳 → 1 个 found 事件
		{FileName: "carved.jpg", Source: "carver"},
	}
	events := BuildTimeline(files)
	if len(events) != 3 {
		t.Errorf("ntfs 文件 2 事件 + carver 文件 1 found = 3，实际 %d", len(events))
	}
}

func TestWriteTimelineMACTime(t *testing.T) {
	tm := time.Date(2024, 1, 15, 14, 30, 0, 0, time.UTC)
	events := []TimelineEvent{
		{Time: tm, Action: "modified", FileName: "x.txt", Size: 99},
	}
	var buf bytes.Buffer
	WriteTimelineMACTime(&buf, events)
	out := buf.String()
	if !strings.Contains(out, "2024-01-15T14:30:00Z|99|m..|") {
		t.Errorf("mactime 格式不对: %q", out)
	}
}

func TestWriteDFXML_ContainsHashAndFile(t *testing.T) {
	tm := time.Date(2024, 1, 15, 14, 30, 0, 0, time.UTC)
	files := []*types.RecoveredFile{
		{
			ID:           "x",
			FileName:     "evidence.jpg",
			OriginalPath: "/Users/x/Desktop/evidence.jpg",
			Size:         12345,
			Offset:       65536,
			ModifiedTime: &tm,
			SHA256:       "abc123",
			Source:       "ntfs",
			IsDeleted:    true,
		},
	}
	var buf bytes.Buffer
	if err := WriteDFXML(&buf, "DataRecovery", "1.0", files); err != nil {
		t.Fatalf("WriteDFXML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`xmlns="http://www.forensicswiki.org/wiki/Category:DFXML"`,
		`xmlns:dc="http://purl.org/dc/elements/1.1/"`,
		`version="1.0"`,
		"<filename>/Users/x/Desktop/evidence.jpg</filename>",
		"<filesize>12345</filesize>",
		`<byte_run img_offset="65536" len="12345"></byte_run>`,
		`<unalloc>1</unalloc>`,
		`type="sha256"`,
		"abc123",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("DFXML 输出缺 %q", want)
		}
	}
}

// 含 source 的输出验证：image_filename / image_size 都得在
func TestWriteDFXMLWithSource_IncludesSource(t *testing.T) {
	files := []*types.RecoveredFile{
		{ID: "y", FileName: "x.txt", Size: 100, Offset: 1024},
	}
	src := &SourceInfo{
		ImageFilename: "/dev/sda",
		ImageSize:     1024 * 1024 * 1024,
		SectorSize:    512,
	}
	var buf bytes.Buffer
	if err := WriteDFXMLWithSource(&buf, "DataRecovery", "v2", src, files); err != nil {
		t.Fatalf("WriteDFXMLWithSource: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<source>",
		"<image_filename>/dev/sda</image_filename>",
		"<image_size>1073741824</image_size>",
		"<sectorsize>512</sectorsize>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("source 区块缺 %q", want)
		}
	}
}
