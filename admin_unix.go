//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
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

	// 非交互场景一律跳过 auto-sudo，否则会出现：
	//   - Wails build 期间生成 bindings 跑临时二进制 → 我们调 syscall.Kill 杀自己 →
	//     Wails 看到 "dead parent" → bindings 失败 → CI 红
	//   - GitHub Actions / 任何 CI 环境弹出 GUI 密码框毫无意义
	//   - 通过 ssh -t 之外的方式跑（cron / systemd unit / pipe 输入）也不该弹框
	if isNonInteractiveContext() {
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

// isNonInteractiveContext 判断当前进程是否处于"不该弹 GUI / 不该自动重启"的环境。
//
// 三个独立信号任一满足即返回 true：
//
//	1. 经典 CI env vars（GitHub Actions / GitLab / CircleCI / Jenkins 等）
//	2. Wails 自身在 build 阶段跑 bindings 临时二进制时设置的环境变量
//	3. stdin 不是 char device（被管道 / 重定向接管 = 非交互）
func isNonInteractiveContext() bool {
	for _, k := range []string{
		"CI",                      // 通用 (GitHub Actions / GitLab / CircleCI 等)
		"GITHUB_ACTIONS",          // GitHub Actions
		"BUILDKITE",
		"JENKINS_URL",
		"GITLAB_CI",
		"CIRCLECI",
		"TF_BUILD",                // Azure Pipelines
		"WAILS_BIND",              // Wails 内部约定（如有）
		"WAILS_BUILD",
		"WAILS_NO_AUTO_RUN",
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	// stdin 非 TTY → 极大概率是 Wails build / pipe / cron / systemd
	if fi, err := os.Stdin.Stat(); err == nil {
		if fi.Mode()&os.ModeCharDevice == 0 {
			return true
		}
	}
	return false
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
		// #nosec G702 G204 — re-exec 自身提权：args = os.Args[1:] 来自程序 CLI 不是外部输入
		cmd := exec.Command(pk, full...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err == nil {
			// 子进程已起，主进程让 main 收到 (true, nil) 后正常 return
			// （绝不在这里发 SIGTERM 杀自己 — 会让父进程退出码 = 143，让 wails / CI
			//  之类的工具误以为 build 失败）
			return true, nil
		}
	}
	if os.Getenv("SUDO_ASKPASS") != "" {
		if su, err := exec.LookPath("sudo"); err == nil {
			full := append([]string{"-A", "env", envPair}, args...)
			// #nosec G702 — re-exec 自身提权：args 源于 os.Args 不是外部输入
			cmd := exec.Command(su, full...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err == nil {
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
