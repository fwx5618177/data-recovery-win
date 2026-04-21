// Package backup 提供"找回数据后帮你定期备份"的极简监控器。
//
// 用户视角：扫完 + 恢复后，工具说"要不要我每天凌晨 2 点 把恢复目录 rsync 到这块外接盘？"
// 同意后我们就生成一个跨平台的 cron / launchd / 任务计划程序定时任务（不在主进程里跑）。
//
// **本包只生成"配置脚本 + 安装命令"**，不真在主进程里跑长驻 daemon — 那种事让 OS
// 的原生 scheduler 做更稳。
package backup

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Schedule 定时备份配置
type Schedule struct {
	SourceDir string // 例 /Users/x/RecoveredData
	DestDir   string // 例 /Volumes/Backup/RecoveredData
	HourOfDay int    // 0..23，本地时间
	Frequency string // "daily" / "weekly"
}

// GenerateInstallCommand 按 OS 返回安装命令字符串（用户可手动跑或我们 exec.Command 跑）
func (s Schedule) GenerateInstallCommand() (string, error) {
	if s.SourceDir == "" || s.DestDir == "" {
		return "", fmt.Errorf("source/dest 不能为空")
	}
	hour := s.HourOfDay
	if hour < 0 || hour > 23 {
		hour = 2 // 默认凌晨 2 点
	}
	switch runtime.GOOS {
	case "linux", "darwin":
		// crontab：分 时 日 月 周  command
		min := "0"
		// rsync -a --delete 复制 source → dest，--delete 让 dest 与 source 完全一致
		cmd := fmt.Sprintf("rsync -a --delete %q/ %q/", s.SourceDir, s.DestDir)
		cron := fmt.Sprintf("%s %d * * * %s", min, hour, cmd)
		// "把这一行加到 crontab"的安装命令
		return fmt.Sprintf(`echo '%s' | crontab -`, cron), nil
	case "windows":
		// schtasks /Create
		return fmt.Sprintf(
			`schtasks /Create /SC DAILY /TN "DataRecoveryBackup" /TR "robocopy \"%s\" \"%s\" /MIR" /ST %02d:00 /F`,
			s.SourceDir, s.DestDir, hour), nil
	}
	return "", fmt.Errorf("不支持的 OS: %s", runtime.GOOS)
}

// Install 真的执行安装命令（需要用户确认 — 调用方应弹 confirm）
func (s Schedule) Install() error {
	cmdStr, err := s.GenerateInstallCommand()
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.Command("sh", "-c", cmdStr)
	case "windows":
		cmd = exec.Command("cmd", "/C", cmdStr)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Uninstall 卸载（删 cron 行 / schtasks /Delete）
func (s Schedule) Uninstall() error {
	switch runtime.GOOS {
	case "linux", "darwin":
		return exec.Command("sh", "-c", `crontab -l 2>/dev/null | grep -v 'DataRecoveryBackup' | crontab -`).Run()
	case "windows":
		return exec.Command("cmd", "/C", `schtasks /Delete /TN "DataRecoveryBackup" /F`).Run()
	}
	return fmt.Errorf("unsupported OS")
}
