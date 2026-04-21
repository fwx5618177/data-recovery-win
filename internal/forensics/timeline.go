// Package forensics 提供"取证模式"功能 —— 给安全 / IR 调查员用，不是给普通用户。
//
//   - Timeline 时间线：把所有 RecoveredFile 的时间戳（mtime/ctime/atime）拍平成
//     按时间排序的事件流，文本格式（mactime 兼容）+ JSON 双输出
//   - DFXML：业界取证报告标准（http://forensicswiki.org/wiki/Category:DFXML）
//   - HashCompare：把恢复的文件 hash 列表导出，让用户自己拿去 NSRL / VirusTotal 比对
package forensics

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"data-recovery/internal/types"
)

// TimelineEvent 是单个时间点的事件
type TimelineEvent struct {
	Time      time.Time `json:"time"`
	Action    string    `json:"action"`   // "modified" / "created" / "deleted"
	FileName  string    `json:"fileName"`
	FilePath  string    `json:"filePath"`
	Size      int64     `json:"size"`
	Source    string    `json:"source"`   // ntfs / apfs / carver / ...
	IsDeleted bool      `json:"isDeleted"`
}

// BuildTimeline 把 files 拍平成时间排序的事件列表。
//
// 每个文件可能产生多达 3 个事件（mtime/ctime/atime 不为空时各算一个）。
func BuildTimeline(files []*types.RecoveredFile) []TimelineEvent {
	var events []TimelineEvent
	for _, f := range files {
		if f == nil {
			continue
		}
		base := TimelineEvent{
			FileName:  f.FileName,
			FilePath:  f.OriginalPath,
			Size:      f.Size,
			Source:    f.Source,
			IsDeleted: f.IsDeleted,
		}
		if f.ModifiedTime != nil && !f.ModifiedTime.IsZero() {
			e := base
			e.Time = *f.ModifiedTime
			e.Action = "modified"
			events = append(events, e)
		}
		if f.CreatedTime != nil && !f.CreatedTime.IsZero() {
			e := base
			e.Time = *f.CreatedTime
			e.Action = "created"
			events = append(events, e)
		}
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].Time.Before(events[j].Time)
	})
	return events
}

// WriteTimelineMACTime 输出 Sleuthkit mactime 兼容的"|分隔"文本：
//
//	Date|Size|Type|Mode|UID|GID|Meta|FileName
//
// 示例：
//   2024-01-15T14:30:00Z|12345|m..|0|0|0|0|/Users/x/photo.jpg
func WriteTimelineMACTime(w io.Writer, events []TimelineEvent) error {
	for _, e := range events {
		actionFlag := "..."
		switch e.Action {
		case "modified":
			actionFlag = "m.."
		case "created":
			actionFlag = "..b"
		case "accessed":
			actionFlag = ".a."
		}
		path := e.FilePath
		if path == "" {
			path = e.FileName
		}
		if e.IsDeleted {
			path += " (deleted)"
		}
		_, err := fmt.Fprintf(w, "%s|%d|%s|0|0|0|0|%s\n",
			e.Time.UTC().Format(time.RFC3339), e.Size, actionFlag, path)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteTimelineJSON 输出 JSON 数组（NDJSON 友好）
func WriteTimelineJSON(w io.Writer, events []TimelineEvent) error {
	enc := json.NewEncoder(w)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}
