//go:build !windows

package disk

// ResolveToPhysicalDriveWindows 在非 Windows 平台是 no-op。
// 提供这个空实现是为了让上层（SMART / GPT 等）能跨平台调用而无需 build tag 切换。
func ResolveToPhysicalDriveWindows(devicePath string) string { return devicePath }
