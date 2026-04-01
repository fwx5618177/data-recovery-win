//go:build !windows

package main

import "os"

// isWindowsAdmin 在非 Windows 平台上始终返回 false
func isWindowsAdmin() bool {
	return false
}

// isUnixRoot 检查当前进程是否以 root 权限运行
func isUnixRoot() bool {
	return os.Geteuid() == 0
}

func ensureAdminPrivileges() (bool, error) {
	return false, nil
}
