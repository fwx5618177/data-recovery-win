//go:build !windows

package disk

// EnsureLongPath 在非 Windows 平台是 no-op —— Linux / macOS 不限制路径长度。
// 保持 API 对上层统一，写入代码不需要 build tag。
func EnsureLongPath(p string) string { return p }
