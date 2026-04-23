//go:build windows

package disk

import (
	"path/filepath"
	"strings"
)

// EnsureLongPath 给超长路径加 \\?\ 前缀（Windows 专属）。
//
// Windows MAX_PATH 历史限制 260 字符；`\\?\` 前缀告诉 Win32 API 跳过路径解析，
// 直接把 Unicode 字符串传给 NT 原生 API，支持最多 32767 字符。
//
// Go 1.20+ 的 os 包在内部自动加前缀；但我们这层显式 ensure 是为了：
//   1. 对 Go < 1.20 的编译兼容
//   2. 在 disk.imager / 自定义 syscall / cgo 调用里一致
//   3. 给第三方库（例如 SMB 写）提供统一转换函数
//
// 规则：
//   - 路径 < 240 字符且不含 "?" → 不改动（兼容老代码）
//   - 已以 \\?\ 或 \\?\UNC\ 开头 → 不改动
//   - UNC 路径 \\server\share\... → 转为 \\?\UNC\server\share\...
//   - 普通路径 C:\foo → 转为 \\?\C:\foo
//
// 注意：\\?\ 前缀后 API 不做 . / .. 规范化，所以传入前必须 filepath.Clean。
func EnsureLongPath(p string) string {
	if len(p) < 240 {
		return p // 留 20 字符余量；多数情况无需修改
	}
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	// 先规范化（去掉 . / ..）；\\?\ 前缀下 Win32 不再做这个
	cleaned := filepath.Clean(p)

	if strings.HasPrefix(cleaned, `\\`) {
		// UNC 路径
		return `\\?\UNC\` + cleaned[2:]
	}
	// 本地盘符路径
	return `\\?\` + cleaned
}
