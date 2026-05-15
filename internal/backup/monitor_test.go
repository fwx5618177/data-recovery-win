package backup

import (
	"runtime"
	"strings"
	"testing"
)

func TestGenerateInstallCommand_PerOS(t *testing.T) {
	s := Schedule{
		SourceDir: "/tmp/src",
		DestDir:   "/tmp/dst",
		HourOfDay: 3,
		Frequency: "daily",
	}
	cmd, err := s.GenerateInstallCommand()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	switch runtime.GOOS {
	case "linux", "darwin":
		if !strings.Contains(cmd, "rsync") || !strings.Contains(cmd, "crontab") {
			t.Errorf("Unix cmd 应含 rsync + crontab: %q", cmd)
		}
	case "windows":
		// v2.8.29: 切到 PowerShell Register-ScheduledTask 之后，cmd 里不该再有 schtasks
		// （schtasks 的引号嵌套是 0x80004005 的成因）
		if strings.Contains(cmd, "schtasks") {
			t.Errorf("v2.8.29 Win cmd 不该再含 schtasks（引号嵌套坑），实际 %q", cmd)
		}
		if !strings.Contains(cmd, "Register-ScheduledTask") {
			t.Errorf("Win cmd 应含 Register-ScheduledTask: %q", cmd)
		}
	}
}

func TestGenerateInstallCommand_RejectsEmpty(t *testing.T) {
	if _, err := (Schedule{}).GenerateInstallCommand(); err == nil {
		t.Error("空 source/dest 应报错")
	}
}

// TestBuildWindowsRegisterTaskPS_QuoteSafety 回归 v2.8.29 的本质修复：
// 用户报 "schtasks /TR ..." 安装失败 0x80004005 + GBK mojibake。根因是
// cmd.exe 解析 schtasks /TR "robocopy \"X\" \"Y\" /MIR" 时引号嵌套出错。
// 改用 PowerShell Register-ScheduledTask 后参数走数组，不存在嵌套问题。
//
// 这个测试在所有 OS 上都能跑（不调用 PowerShell，只断言生成的脚本字符串）。
func TestBuildWindowsRegisterTaskPS_QuoteSafety(t *testing.T) {
	// 含空格的路径（最常见的实战场景，"C:\Program Files" 等）
	script := buildWindowsRegisterTaskPS(`C:\Program Files\My Data`, `D:\Backup Disk`, 2)

	// 1. 必须含 Register-ScheduledTask，不能是 schtasks
	if !strings.Contains(script, "Register-ScheduledTask") {
		t.Errorf("脚本应用 PowerShell cmdlet，实际：%s", script)
	}
	if strings.Contains(script, "schtasks") {
		t.Errorf("脚本不该回归到 schtasks（v2.8.29 之前的坑），实际：%s", script)
	}

	// 2. robocopy 路径必须正确出现在 -Argument 里
	if !strings.Contains(script, `"C:\Program Files\My Data"`) {
		t.Errorf("源路径没正确放进 PowerShell 脚本：%s", script)
	}
	if !strings.Contains(script, `"D:\Backup Disk"`) {
		t.Errorf("目标路径没正确放进 PowerShell 脚本：%s", script)
	}

	// 3. 时间 2 必须以 02:00 出现
	if !strings.Contains(script, "02:00") {
		t.Errorf("时间格式应为 02:00，实际：%s", script)
	}

	// 4. 任务名必须明确
	if !strings.Contains(script, `'DataRecoveryBackup'`) {
		t.Errorf("任务名 DataRecoveryBackup 应出现，实际：%s", script)
	}
}

// TestBuildWindowsRegisterTaskPS_PathWithSingleQuote 用户路径带单引号
// （macOS 文件常见，Windows 罕见但可能）—— PowerShell 单引号字符串里 ' 必须双写成 ''。
func TestBuildWindowsRegisterTaskPS_PathWithSingleQuote(t *testing.T) {
	script := buildWindowsRegisterTaskPS(`C:\It's Mine`, `D:\Backup`, 2)
	// PowerShell 单引号字符串里 ' → ''
	if !strings.Contains(script, `'"C:\It''s Mine"`) {
		t.Errorf("路径里的单引号必须双写成 ''，实际：%s", script)
	}
}
