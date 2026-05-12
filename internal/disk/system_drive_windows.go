//go:build windows

package disk

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// IsSystemDrive 判断给定 device path 是不是 Windows 系统盘。
//
// 用 GetWindowsDirectoryW 拿到 Windows 安装目录（一般是 C:\Windows），取盘符 C，
// 然后跟传入的 devicePath 提取的盘符比较。
//
// 支持识别：
//   - "\\.\C:"        / "C:"        / "C:\\..."        → 系统盘
//   - "\\.\PhysicalDrive0" → 通过 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 解析
//     （复杂，目前不实现 —— 物理盘路径返回 false，让上层决定要不要警告）
//
// 用于：扫描启动前提示用户"目标是系统盘，可能导致系统假死"。
//
// v2.8.20 加 —— 用户报"扫描系统盘 IO 占满，系统卡死"。
func IsSystemDrive(devicePath string) bool {
	sysDir := getWindowsDirectory()
	if sysDir == "" {
		return false
	}
	sysLetter := strings.ToUpper(string(sysDir[0])) // 比如 "C"

	// 提取 devicePath 的盘符
	clean := strings.ToUpper(devicePath)
	// 形式 1: "C:" / "C:\..."
	if len(clean) >= 2 && clean[1] == ':' {
		return string(clean[0]) == sysLetter
	}
	// 形式 2: "\\.\C:"（Windows raw 盘符路径）
	if strings.HasPrefix(clean, `\\.\`) && len(clean) >= 6 && clean[5] == ':' {
		return string(clean[4]) == sysLetter
	}
	// 形式 3: "\\.\PHYSICALDRIVE0" 等 —— 物理盘需要 IOCTL 才能映射到盘符，暂不支持
	// 让 caller 自行判断（一般物理盘 0 就是系统所在物理盘，但不绝对）
	return false
}

// getWindowsDirectory 拿 Windows 安装目录（通常 C:\Windows）
func getWindowsDirectory() string {
	var modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	var procGetWindowsDirectory = modKernel32.NewProc("GetWindowsDirectoryW")

	buf := make([]uint16, syscall.MAX_PATH)
	n, _, _ := procGetWindowsDirectory.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if n == 0 || int(n) > len(buf) {
		return ""
	}
	return filepath.Clean(syscall.UTF16ToString(buf[:n]))
}
