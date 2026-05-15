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

// GenerateInstallCommand 按 OS 返回安装命令字符串（用户可手动跑或我们 exec.Command 跑）。
//
// v2.8.29 Windows 重写：之前用 `schtasks /Create /TR "robocopy \"%s\" \"%s\" /MIR"`，
// 嵌套引号在 cmd.exe 里解析后变成 schtasks 的 /TR 参数包含未转义的双引号 ——
// 中文 Windows 上 schtasks 返回 0x80004005 + GBK 编码的报错（Go 抓到的是 mojibake）。
// 改用 PowerShell Register-ScheduledTask，参数走 New-ScheduledTaskAction -Argument
// 数组形式，不存在引号嵌套问题；PowerShell 自己负责量化路径。
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
		// PowerShell + Register-ScheduledTask —— 比 schtasks 命令行字符串安全得多
		return buildWindowsRegisterTaskPS(s.SourceDir, s.DestDir, hour), nil
	}
	return "", fmt.Errorf("不支持的 OS: %s", runtime.GOOS)
}

// buildWindowsRegisterTaskPS 构造一段 PowerShell 脚本注册定时任务。
// 路径里的单引号要双写成 ''（PowerShell 单引号字符串转义规则）。
//
// 暴露成包级函数方便单元测试（runtime 在测试机上可能不是 Windows）。
func buildWindowsRegisterTaskPS(srcDir, dstDir string, hour int) string {
	escSrc := strings.ReplaceAll(srcDir, "'", "''")
	escDst := strings.ReplaceAll(dstDir, "'", "''")
	return fmt.Sprintf(
		`$Action = New-ScheduledTaskAction -Execute 'robocopy.exe' -Argument '"%s" "%s" /MIR';`+
			`$Trigger = New-ScheduledTaskTrigger -Daily -At %02d:00;`+
			`$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries;`+
			`Register-ScheduledTask -TaskName 'DataRecoveryBackup' -Action $Action -Trigger $Trigger -Settings $Settings -Force | Out-Null`,
		escSrc, escDst, hour)
}

// Install 真的执行安装命令（需要用户确认 — 调用方应弹 confirm）
func (s Schedule) Install() error {
	if s.SourceDir == "" || s.DestDir == "" {
		return fmt.Errorf("source/dest 不能为空")
	}
	hour := s.HourOfDay
	if hour < 0 || hour > 23 {
		hour = 2
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin":
		cmdStr, err := s.GenerateInstallCommand()
		if err != nil {
			return err
		}
		cmd = exec.Command("sh", "-c", cmdStr)
	case "windows":
		// 直接调 powershell.exe，不经 cmd.exe —— 避免双层引号嵌套
		// -NoProfile 让脚本启动更快；-ExecutionPolicy Bypass 防被组策略阻止
		// -Command 直接传脚本（不需要写临时 .ps1 文件）
		script := buildWindowsRegisterTaskPS(s.SourceDir, s.DestDir, hour)
		cmd = exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	default:
		return fmt.Errorf("不支持的 OS: %s", runtime.GOOS)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Uninstall 卸载（删 cron 行 / Unregister-ScheduledTask）
func (s Schedule) Uninstall() error {
	switch runtime.GOOS {
	case "linux", "darwin":
		return exec.Command("sh", "-c", `crontab -l 2>/dev/null | grep -v 'DataRecoveryBackup' | crontab -`).Run()
	case "windows":
		// v2.8.29: 改 PowerShell 卸载，跟 Install 路径一致
		script := `Unregister-ScheduledTask -TaskName 'DataRecoveryBackup' -Confirm:$false -ErrorAction SilentlyContinue`
		return exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).Run()
	}
	return fmt.Errorf("unsupported OS")
}
