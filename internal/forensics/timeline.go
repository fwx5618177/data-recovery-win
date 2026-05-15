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
	Action    string    `json:"action"` // "modified" / "created" / "deleted"
	FileName  string    `json:"fileName"`
	FilePath  string    `json:"filePath"`
	Size      int64     `json:"size"`
	Source    string    `json:"source"` // ntfs / apfs / carver / ...
	IsDeleted bool      `json:"isDeleted"`
}

// BuildTimeline 把 files 拍平成时间排序的事件列表。
//
// 每个文件最多产生 2 个时间戳事件（mtime / ctime 非空时各算一个）。
//
// v2.8.32: 之前如果 mtime/ctime 都为 nil（深度扫描 carver 结果就是这样 —— 雕刻
// 不知道原 FS 时间戳），整个文件被忽略 → timeline 文件 0 字节。用户报"导出的
// 文件是空的"的真正成因。
//
// 现在退路：mtime/ctime 都没有时，仍然生成一条 "found" 事件（time=now()）。
// mactime 输出里这些 "found" 集中在同一时刻不影响 ctime/mtime 类的时间序分析；
// 至少**让用户看见有恢复结果**而不是空文件。
//
// 同时 carver 文件标 `Source="carver"` → 报告里 grep "carver" 一目了然。
func BuildTimeline(files []*types.RecoveredFile) []TimelineEvent {
	var events []TimelineEvent
	scanTime := time.Now().UTC()
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
		had := false
		if f.ModifiedTime != nil && !f.ModifiedTime.IsZero() {
			e := base
			e.Time = *f.ModifiedTime
			e.Action = "modified"
			events = append(events, e)
			had = true
		}
		if f.CreatedTime != nil && !f.CreatedTime.IsZero() {
			e := base
			e.Time = *f.CreatedTime
			e.Action = "created"
			events = append(events, e)
			had = true
		}
		if !had {
			// v2.8.32: 没 FS 时间戳（carver 文件）→ 仍写一条 found 事件
			e := base
			e.Time = scanTime
			e.Action = "found"
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
//
//	2024-01-15T14:30:00Z|12345|m..|0|0|0|0|/Users/x/photo.jpg
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
		case "found":
			// v2.8.32: 我们新增的 carver "found" 标记。复用 mactime 的"自定义"位
			// — 4 个点位都置 "X" 让 mactime 分析工具仍能解析行但区分出来。
			actionFlag = "X..X"
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
