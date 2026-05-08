//go:build !windows

package diag

// resolveRealDesktopPath 非 Windows 平台空实现 —— Linux / macOS 用 ~/Desktop 即可
// （xdg-user-dirs / Finder 都把 ~/Desktop 当真桌面，没有 Windows 那套 redirect 逻辑）。
func resolveRealDesktopPath() string {
	return ""
}
