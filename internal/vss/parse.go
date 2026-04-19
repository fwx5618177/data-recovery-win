package vss

import (
	"regexp"
	"strings"
	"time"
)

// parseVssadminOutput 从 `vssadmin list shadows` 的 stdout 中解析 shadow 列表。
//
// 典型一段（中英文字段名都要兼容，Windows 本地化会改变字段名）：
//
//   Contents of shadow copy set ID: {xxx}
//      Contained 1 shadow copies at creation time: 4/19/2026 10:00:00 AM
//      Shadow Copy ID: {GUID}
//         Original Volume: (C:)\\?\Volume{...}\
//         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
//         Originating Machine: DESKTOP-ABC
//         Service Machine: DESKTOP-ABC
//         Provider: 'Microsoft Software Shadow Copy provider 1.0'
//         Type: ClientAccessibleWriters
//         Attributes: Persistent, Client-accessible, No auto release, Differential, Auto recovered
//
// 我们只关心 ID / Device Path / Original Volume / CreatedAt / Machine。
// 解析失败的单条会被跳过，不会让整个列表扑街。
func parseVssadminOutput(raw string) []Shadow {
	var out []Shadow
	// 以 "Shadow Copy ID:" 为分块标记切一刀
	blocks := splitByShadowID(raw)
	for _, b := range blocks {
		if sh, ok := parseShadowBlock(b); ok {
			out = append(out, sh)
		}
	}
	return out
}

// 兼容中英文 "Shadow Copy ID:" / "卷影复制 ID:"
var reShadowIDHeader = regexp.MustCompile(`(?m)^\s*(?:Shadow Copy ID|卷影复制\s*ID)\s*:\s*(\{[0-9A-Fa-f\-]+\})`)

func splitByShadowID(raw string) []string {
	// 找到所有 "Shadow Copy ID" 的起点，把中间内容切开。
	idx := reShadowIDHeader.FindAllStringIndex(raw, -1)
	if len(idx) == 0 {
		return nil
	}
	blocks := make([]string, 0, len(idx))
	for i, pair := range idx {
		start := pair[0]
		end := len(raw)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		blocks = append(blocks, raw[start:end])
	}
	return blocks
}

// 字段级 regex：允许冒号前后空格 + 值里的任意非换行字符
func fieldRegex(keys ...string) *regexp.Regexp {
	// (?m) 多行；(?i) 忽略大小写
	joined := strings.Join(keys, "|")
	return regexp.MustCompile(`(?mi)^\s*(?:` + joined + `)\s*:\s*(.+?)\s*$`)
}

var (
	reFieldID          = fieldRegex("Shadow Copy ID", "卷影复制\\s*ID")
	reFieldDevice      = fieldRegex("Shadow Copy Volume", "卷影复制\\s*卷")
	reFieldOriginal    = fieldRegex("Original Volume", "原始卷")
	reFieldOrigMachine = fieldRegex("Originating Machine", "原始计算机")
	reFieldSvcMachine  = fieldRegex("Service Machine", "服务计算机")
)

func parseShadowBlock(block string) (Shadow, bool) {
	var sh Shadow
	if m := reFieldID.FindStringSubmatch(block); len(m) >= 2 {
		sh.ID = strings.TrimSpace(m[1])
	} else {
		return sh, false
	}
	if m := reFieldDevice.FindStringSubmatch(block); len(m) >= 2 {
		sh.DevicePath = strings.TrimSpace(m[1])
	}
	if sh.DevicePath == "" {
		return sh, false // 没 device 就没法读，扔掉
	}
	if m := reFieldOriginal.FindStringSubmatch(block); len(m) >= 2 {
		sh.OriginalVolume = strings.TrimSpace(m[1])
	}
	if m := reFieldOrigMachine.FindStringSubmatch(block); len(m) >= 2 {
		sh.OriginatingMachine = strings.TrimSpace(m[1])
	}
	if m := reFieldSvcMachine.FindStringSubmatch(block); len(m) >= 2 {
		sh.ServiceMachine = strings.TrimSpace(m[1])
	}
	// 创建时间：从 "Contained N shadow copies at creation time: ..." 这一行抓
	// 该行在"块"之前，可能跨块共享——这里我们宽容处理，找不到就留零值
	sh.CreatedAt = parseCreationTime(block)
	return sh, true
}

// 创建时间这行的格式本地化很凶：中文是"在创建时间"，英文是 "at creation time"。
// 我们能匹配的几种常见格式：
//   - "4/19/2026 10:00:00 AM"
//   - "2026/4/19 10:00:00"
//   - "Fri Apr 19 10:00:00 2026"
var reCreationTime = regexp.MustCompile(`(?mi)(?:at creation time|在创建时间)\s*:?\s*(.+?)\s*$`)

func parseCreationTime(block string) time.Time {
	m := reCreationTime.FindStringSubmatch(block)
	if len(m) < 2 {
		return time.Time{}
	}
	candidate := strings.TrimSpace(m[1])
	layouts := []string{
		"1/2/2006 3:04:05 PM",
		"01/02/2006 3:04:05 PM",
		"2006/1/2 15:04:05",
		"2006/01/02 15:04:05",
		"2006-01-02 15:04:05",
		time.ANSIC,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, candidate); err == nil {
			return t
		}
	}
	return time.Time{}
}
