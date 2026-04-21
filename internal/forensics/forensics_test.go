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
			ModifiedTime: &tm,
			SHA256:       "abc123",
			Source:       "ntfs",
		},
	}
	var buf bytes.Buffer
	if err := WriteDFXML(&buf, "DataRecovery", "1.0", files); err != nil {
		t.Fatalf("WriteDFXML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<dfxml version=\"1.0\"",
		"<filename>/Users/x/Desktop/evidence.jpg</filename>",
		"<filesize>12345</filesize>",
		"sha256",
		"abc123",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("DFXML 输出缺 %q", want)
		}
	}
}
