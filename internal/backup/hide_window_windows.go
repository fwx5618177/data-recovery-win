//go:build windows

package backup

import (
	"os/exec"
	"syscall"
)

// hideWindow 在 Windows 上启动 PowerShell / cmd 子进程时不弹出可见窗口。
//
// v2.8.31 加 —— 用户报"安装定时备份任务时弹出一个类似 cmd 脚本的东西，运行结束之后
// 不知道有没有装上"。本工具调 powershell.exe Register-ScheduledTask 安装任务，
// Windows 默认会为 GUI 程序的子进程也弹一个控制台窗口（哪怕一闪而过）。
// 加 HideWindow + CREATE_NO_WINDOW，让操作完全静默 —— 成功/失败由上层 toast 反馈。
//
// 参考：https://learn.microsoft.com/zh-cn/windows/win32/procthread/process-creation-flags
const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
