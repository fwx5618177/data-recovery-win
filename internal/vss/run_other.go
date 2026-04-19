//go:build !windows

package vss

import "context"

// listShadowsPlatform 在非 Windows 平台上直接返回 ErrNotSupported。
// 这样上层 UI 在 macOS / Linux 能礼貌地隐藏"VSS 扫描"按钮，不硬坏。
func listShadowsPlatform(ctx context.Context) ([]Shadow, error) {
	_ = ctx
	return nil, ErrNotSupported
}
