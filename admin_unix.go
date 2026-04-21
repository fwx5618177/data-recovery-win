//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

// isWindowsAdmin 在非 Windows 平台上始终返回 false
func isWindowsAdmin() bool {
	return false
}

// isUnixRoot 检查当前进程是否以 root 权限运行
func isUnixRoot() bool {
	return os.Geteuid() == 0
}

// ensureAdminPrivileges 在非 Windows 平台尝试自动提权 + 重启自身。
//
// macOS：用 osascript "do shell script ... with administrator privileges" 弹原生
//        Touch ID / 密码对话框，新进程 root 启动；本进程退出。
// Linux：探测 pkexec / sudo -A（需 SUDO_ASKPASS 提供 GUI 密码框），都不可用则
//        打印指南后退出。
//
// 返回 (relaunched=true, nil) 时主进程必须立即返回（新进程已起）；
// (false, nil) 表示已经是 root / 无须重启。
func ensureAdminPrivileges() (bool, error) {
	if isUnixRoot() {
		return false, nil
	}
	// 防止"提权失败 → 重启 → 又失败 → 死循环"
	if os.Getenv("DATA_RECOVERY_NO_AUTO_SUDO") == "1" {
		return false, nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("无法定位本进程可执行文件: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		return relaunchMacWithAdmin(exePath)
	case "linux":
		return relaunchLinuxWithSudo(exePath)
	}
	return false, nil
}

// relaunchMacWithAdmin 用 AppleScript 让 Finder 弹原生密码 / Touch ID 对话框。
//
// 关键约束：
//   - GUI .app bundle 的实际可执行文件路径包含空格（"/Applications/Data Recovery.app/..."）
//     必须把路径用单引号包起来；二次转义里的单引号
//   - 设置 DATA_RECOVERY_NO_AUTO_SUDO=1 防止子进程权限不足时再次循环 relaunch
//   - 把当前命令行参数原样传过去
func relaunchMacWithAdmin(exePath string) (bool, error) {
	args := []string{exePath}
	args = append(args, os.Args[1:]...)

	// 把所有参数 shell-quote 后拼成 osascript 里的字符串
	var quoted strings.Builder
	for i, a := range args {
		if i > 0 {
			quoted.WriteByte(' ')
		}
		quoted.WriteString(shellQuote(a))
	}

	script := fmt.Sprintf(
		`do shell script %s with administrator privileges`,
		appleQuote("DATA_RECOVERY_NO_AUTO_SUDO=1 "+quoted.String()+" >/tmp/data-recovery.stdout 2>/tmp/data-recovery.stderr &"),
	)
	cmd := exec.Command("osascript", "-e", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// 用户取消密码框 (osascript 退出 1) 不当 fatal；告诉用户怎么办
		fmt.Fprintln(os.Stderr,
			"未获得管理员权限。可以手动用 sudo 启动，或重启程序按 Touch ID/密码授权：")
		fmt.Fprintf(os.Stderr, "  sudo %s\n", exePath)
		return false, nil // 让主进程继续以普通用户身份跑，IsAdmin() 会返回 false 让 UI 提示
	}
	return true, nil // 子进程已起，主进程退出
}

// relaunchLinuxWithSudo 优先 pkexec（PolicyKit GUI），退化到 sudo -A（需 SUDO_ASKPASS）。
// 都不可用就打印手动 sudo 指南后让主进程继续（UI 会显示"需要 root"提示）。
func relaunchLinuxWithSudo(exePath string) (bool, error) {
	args := []string{exePath}
	args = append(args, os.Args[1:]...)
	envPair := "DATA_RECOVERY_NO_AUTO_SUDO=1"

	if pk, err := exec.LookPath("pkexec"); err == nil {
		full := append([]string{"env", envPair}, args...)
		cmd := exec.Command(pk, full...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err == nil {
			// 让子进程脱离父，主进程立即退出
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
			return true, nil
		}
	}
	if os.Getenv("SUDO_ASKPASS") != "" {
		if su, err := exec.LookPath("sudo"); err == nil {
			full := append([]string{"-A", "env", envPair}, args...)
			cmd := exec.Command(su, full...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err == nil {
				_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
				return true, nil
			}
		}
	}
	fmt.Fprintln(os.Stderr,
		"未找到 pkexec 或 SUDO_ASKPASS，请手动 sudo 启动：")
	fmt.Fprintf(os.Stderr, "  sudo %s\n", exePath)
	return false, nil
}

// shellQuote 单引号包裹 + 转义内嵌单引号（标准 POSIX shell quoting）
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// appleQuote AppleScript 字符串字面量：双引号包裹 + 反斜杠转义 \\ 和 "
func appleQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
