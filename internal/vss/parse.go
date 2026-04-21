package vss

import (
	"regexp"
	"strings"
	"time"
)

// parseVssadminOutput 从 `vssadmin list shadows` 的 stdout 中解析 shadow 列表。
//
// 真实输出的两层结构（中英文字段名都要兼容）：
//
//   Contents of shadow copy set ID: {SET-GUID}
//      Contained N shadow copies at creation time: 4/19/2026 10:00:00 AM
//      Shadow Copy ID: {SHADOW-GUID-1}
//         Original Volume: ...
//         Shadow Copy Volume: \\?\GLOBALROOT\...
//         Originating Machine: ...
//      Shadow Copy ID: {SHADOW-GUID-2}    <-- 一个 set 可有多个 shadow，共享 creation time
//         ...
//   Contents of shadow copy set ID: {SET-GUID-2}
//      Contained 1 shadow copies at creation time: 4/20/2026 11:00:00 AM
//      Shadow Copy ID: ...
//
// 解析两遍：先按 "Contents of shadow copy set ID" 切 SET 块（拿到 creation time），
// 再在每个 SET 内切 "Shadow Copy ID" 块（拿到每个 shadow 的字段）。
// 这样确保多 set 多 shadow 时 creation time 不会串味。
func parseVssadminOutput(raw string) []Shadow {
	var out []Shadow
	setBlocks := splitBySetID(raw)
	for _, setBlock := range setBlocks {
		setCreatedAt := parseCreationTime(setBlock)
		shadowBlocks := splitByShadowID(setBlock)
		for _, b := range shadowBlocks {
			if sh, ok := parseShadowBlock(b); ok {
				if sh.CreatedAt.IsZero() {
					sh.CreatedAt = setCreatedAt
				}
				out = append(out, sh)
			}
		}
	}
	return out
}

// 兼容中英文头
var reSetHeader = regexp.MustCompile(`(?mi)^\s*(?:Contents of shadow copy set ID|卷影复制集 ID)\s*[:：]?`)
var reShadowIDHeader = regexp.MustCompile(`(?mi)^\s*(?:Shadow Copy ID|卷影复制\s*ID)\s*:\s*(\{[0-9A-Fa-f\-]+\})`)

// splitBySetID 把 raw 按 "Contents of shadow copy set ID" 切成多个 SET 块
func splitBySetID(raw string) []string {
	idx := reSetHeader.FindAllStringIndex(raw, -1)
	if len(idx) == 0 {
		// 找不到 set 头：把整个 raw 当一个 block 让下游 splitByShadowID 处理
		// （某些精简输出可能没 set 头）
		return []string{raw}
	}
	out := make([]string, 0, len(idx))
	for i, pair := range idx {
		start := pair[0]
		end := len(raw)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		out = append(out, raw[start:end])
	}
	return out
}

func splitByShadowID(raw string) []string {
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
	// 多行的话只取第一行（regex (?m) 已经按行；保险）
	if nl := strings.IndexAny(candidate, "\r\n"); nl >= 0 {
		candidate = strings.TrimSpace(candidate[:nl])
	}
	layouts := []string{
		// 美式 12 小时（最常见）
		"1/2/2006 3:04:05 PM",
		"1/2/2006 03:04:05 PM",
		"01/02/2006 3:04:05 PM",
		"01/02/2006 03:04:05 PM",
		// 美式 24 小时
		"1/2/2006 15:04:05",
		"01/02/2006 15:04:05",
		// ISO / 中文系统
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
