//go:build !windows

package ocr

import "os/exec"

// hideCmdWindow non-Windows 平台 no-op —— Linux / macOS 的子进程默认不会弹任何窗口。
func hideCmdWindow(cmd *exec.Cmd) {
	// no-op
}
