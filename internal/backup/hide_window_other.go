//go:build !windows

package backup

import "os/exec"

// hideWindow non-Windows no-op —— Unix sh / crontab 不会弹 GUI 窗口。
func hideWindow(_ *exec.Cmd) {}
