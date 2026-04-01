//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modShell32        = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteW = modShell32.NewProc("ShellExecuteW")
)

// isWindowsAdmin 检查当前进程是否以管理员权限运行
func isWindowsAdmin() bool {
	var sid *windows.SID

	// 创建 BUILTIN\Administrators 组的 SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		log.Printf("无法分配 SID: %v", err)
		return false
	}
	defer windows.FreeSid(sid)

	// 检查当前进程的 token 是否属于管理员组
	token := windows.Token(0)
	isMember, err := token.IsMember(sid)
	if err != nil {
		log.Printf("检查管理员权限失败: %v", err)
		return false
	}

	return isMember
}

// isUnixRoot 在 Windows 平台上不适用，始终返回 false
func isUnixRoot() bool {
	return false
}

// ensureAdminPrivileges 在 Windows 上默认请求 UAC 提权。
// 返回 true 表示已成功拉起新的管理员进程，当前进程应立即退出。
func ensureAdminPrivileges() (bool, error) {
	if isWindowsAdmin() {
		return false, nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("获取当前程序路径失败: %w", err)
	}

	workDir := filepath.Dir(exePath)
	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return false, fmt.Errorf("构建 UAC 动作失败: %w", err)
	}
	exePtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return false, fmt.Errorf("构建可执行文件路径失败: %w", err)
	}
	argsPtr, err := windows.UTF16PtrFromString(joinWindowsArgs(os.Args[1:]))
	if err != nil {
		return false, fmt.Errorf("构建启动参数失败: %w", err)
	}
	dirPtr, err := windows.UTF16PtrFromString(workDir)
	if err != nil {
		return false, fmt.Errorf("构建工作目录失败: %w", err)
	}

	result, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argsPtr)),
		uintptr(unsafe.Pointer(dirPtr)),
		uintptr(windows.SW_NORMAL),
	)
	if result <= 32 {
		if callErr != windows.Errno(0) {
			return false, fmt.Errorf("请求管理员权限失败: %w", callErr)
		}
		return false, fmt.Errorf("请求管理员权限失败，ShellExecuteW 返回码: %d", result)
	}

	return true, nil
}

func joinWindowsArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}

	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "" {
			quoted = append(quoted, `""`)
			continue
		}

		escaped := strings.ReplaceAll(arg, `"`, `\"`)
		if strings.ContainsAny(escaped, " \t\n\"") {
			escaped = `"` + escaped + `"`
		}
		quoted = append(quoted, escaped)
	}

	return strings.Join(quoted, " ")
}
