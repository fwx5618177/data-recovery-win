//go:build !windows

package disk

import "strings"

// IsSystemDrive 非 Windows 平台简单判定：
//   - macOS: 设备路径含 "/dev/disk0"（startup disk）
//   - Linux: 路径含 "/dev/sda" 或 "/dev/nvme0n1"（约定俗成，不绝对）
//
// 简化版（够用）：扫描 "/" 挂载点对应设备应警告，否则返回 false 让 caller 决定。
func IsSystemDrive(devicePath string) bool {
	// 简单启发：macOS 的 disk0 / Linux 的 sda / nvme0n1 大多是系统盘
	lc := strings.ToLower(devicePath)
	for _, hint := range []string{"/dev/disk0", "/dev/sda", "/dev/nvme0n1"} {
		if strings.HasPrefix(lc, hint) {
			return true
		}
	}
	return false
}
