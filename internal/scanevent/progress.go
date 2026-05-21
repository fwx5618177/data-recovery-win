// Package scanevent 提供 scan 阶段共用的事件 / 进度 helper。
//
// 抽到独立包的目的：
//   - 单元测试不再被锁死在 `package main`（无法在外部目录测试）
//   - Helper 函数职责清晰，可被其它 binary / 测试复用
//   - app.go 减负
package scanevent

import "data-recovery/internal/types"

// MergeProgress 把新的 ScanProgress 合并进既有快照。
//
// 关键：dispatcher 创建新的 ScanProgress 时只设置自己关心的字段（Phase / Percent /
// CurrentFile），其余字段是 zero value。如果直接覆盖快照，已经从底层拿到的
// TotalBytes / FilesFound / Speed 会被重置为 0。
//
// 合并策略：incoming 设了非零 → 用 incoming（最新值）；incoming 为零 → 保留 prev。
//
// 例外：Percent 必须用 incoming（即使是 0，可能是有意从某 phase 重置进度的开头）。
// 但前端 App.tsx 已有单调 guard 兜底，所以这里直接用 incoming 安全。
//
// 历史：v2.8.12 修复"0 B / 0 B / 速度 0"显示 bug 的核心逻辑。
// v2.8.46 抽到 internal/scanevent 包，方便在外部测试目录验证。
func MergeProgress(prev, incoming types.ScanProgress) types.ScanProgress {
	out := incoming
	if out.TotalBytes == 0 && prev.TotalBytes > 0 {
		out.TotalBytes = prev.TotalBytes
	}
	if out.BytesScanned == 0 && prev.BytesScanned > 0 {
		out.BytesScanned = prev.BytesScanned
	}
	if out.FilesFound == 0 && prev.FilesFound > 0 {
		out.FilesFound = prev.FilesFound
	}
	if out.Speed == 0 && prev.Speed > 0 {
		out.Speed = prev.Speed
	}
	return out
}
