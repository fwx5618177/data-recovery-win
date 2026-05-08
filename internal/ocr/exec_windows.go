//go:build windows

package ocr

import (
	"os/exec"
	"syscall"
)

// hideCmdWindow 在 Windows 下设置 SysProcAttr 防止 tesseract / 其他 CLI 弹出黑色 cmd.exe 窗口。
//
// CREATE_NO_WINDOW = 0x08000000：让 CLI 子进程不分配 console。
// HideWindow = true：兜底，万一 console 还是被分配也不显示。
//
// 在 Wails GUI 应用里 spawn CLI 子进程时必须设这个，否则用户每秒看到一次黑窗一闪 →
// 桌面焦点被抢走 → 用户体验灾难。
//
// v2.8.16 加的（用户报 "OCR 工具扫描时不停弹出 CMD 运行窗口"）。
func hideCmdWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}
