package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

// computeFileSHA256 整文件 SHA256；返回 hex lowercase
// apply helper 在替换 exe 前用此验证 binary 未被篡改
func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ApplyFlag 是主程序检测到的"进入 helper 模式"的命令行开关。
// main.go 在 os.Args 里看到这个 flag 就走 RunApplyHelper() 而非正常启动。
const ApplyFlag = "--apply-update"

// ApplyHelperArgs 构造 helper 命令行参数。
// format: --apply-update --parent-pid=N --old-exe=X --new-exe=Y
func ApplyHelperArgs(parentPID int, oldExe, newExe string) []string {
	return []string{
		ApplyFlag,
		"--parent-pid=" + strconv.Itoa(parentPID),
		"--old-exe=" + oldExe,
		"--new-exe=" + newExe,
	}
}

// IsApplyMode 判断当前进程是否应该进入 helper 模式
func IsApplyMode(args []string) bool {
	for _, a := range args {
		if a == ApplyFlag {
			return true
		}
	}
	return false
}

// ParseApplyArgs 从 args 里解析 helper 需要的 (parentPID, oldExe, newExe)
func ParseApplyArgs(args []string) (parentPID int, oldExe, newExe string) {
	for _, a := range args {
		switch {
		case len(a) > len("--parent-pid=") && a[:len("--parent-pid=")] == "--parent-pid=":
			parentPID, _ = strconv.Atoi(a[len("--parent-pid="):])
		case len(a) > len("--old-exe=") && a[:len("--old-exe=")] == "--old-exe=":
			oldExe = a[len("--old-exe="):]
		case len(a) > len("--new-exe=") && a[:len("--new-exe=")] == "--new-exe=":
			newExe = a[len("--new-exe="):]
		}
	}
	return
}

// RunApplyHelper 在 helper 模式下被调用：
//  1. 固定先 sleep 2 秒给父进程清理时间（Wails shutdown + OS 释放文件锁）
//  2. 带重试地把 newExe 复制覆盖到 oldExe（Windows 上运行中的 exe 刚退出时锁可能还在）
//  3. 启动新版 + 清理 pending
//
// 为什么不精确等 pid：os.Process.Signal 在 Windows 上对任意 signal 的行为是平台特定，
// 用 FindProcess + Signal 做 liveness 检查在 Windows 上不可靠；syscall.Kill 又只在 Unix 有。
// 写可移植的正确代码需要分 platform 文件 + cgo，工程代价大。
// 实用简化：固定等 2 秒 + 复制失败时指数退避重试 10 次（最坏 ~25 秒），
// 足够覆盖 Wails shutdown 的常见路径。
func RunApplyHelper(parentPID int, oldExe, newExe string) error {
	if oldExe == "" || newExe == "" {
		return fmt.Errorf("old/new exe path 不能为空")
	}

	// 1. 固定等待父进程退出（参数 parentPID 目前仅做日志记录）
	_ = parentPID
	time.Sleep(2 * time.Second)

	// ★ 安全：应用前对 newExe 验 SHA256 vs pending manifest 记录
	// 防御下载后到 apply 之间 binary 被篡改（磁盘错误 / 恶意进程）
	// 如果 pending 不可用或 hash 字段为空 → skip（向后兼容）
	if pending, err := LoadPending(); err == nil && pending != nil && pending.SHA256 != "" {
		if pending.BinaryPath == newExe {
			actualSHA, sErr := computeFileSHA256(newExe)
			if sErr != nil {
				return fmt.Errorf("计算新版 exe hash 失败: %w", sErr)
			}
			if actualSHA != pending.SHA256 {
				_ = ClearPending() // 清理可能被篡改的 pending
				return fmt.Errorf("新版 exe hash 不匹配 pending manifest：期望 %s 实际 %s（拒绝应用）",
					pending.SHA256, actualSHA)
			}
		}
	}

	// 2. 带重试的复制 —— Windows 上运行中的 exe 刚退出仍可能持锁几百毫秒
	var lastErr error
	for attempt := 1; attempt <= 10; attempt++ {
		if err := copyFile(newExe, oldExe); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
	}
	if lastErr != nil {
		return fmt.Errorf("替换 exe 失败（10 次重试仍不行）: %w", lastErr)
	}

	// 3. 保留可执行权限（Unix 有用）
	if runtime.GOOS != "windows" {
		_ = os.Chmod(oldExe, 0o755)
	}

	// 4. 启动新版（detached）
	newCmd := exec.Command(oldExe)
	newCmd.Stdin = nil
	newCmd.Stdout = nil
	newCmd.Stderr = nil
	if err := newCmd.Start(); err != nil {
		return fmt.Errorf("启动新版失败: %w", err)
	}
	_ = newCmd.Process.Release()

	// 5. 清理 pending 目录
	_ = ClearPending()

	return nil
}

// copyFile 把 src 覆盖写到 dst。
// dst 已存在时先试 rename（同卷原子），失败再退到"拷贝内容"。
func copyFile(src, dst string) error {
	// 先读源
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开新版 exe 失败: %w", err)
	}
	defer in.Close()

	// 目标先写到 .new 再 rename 以避免中间状态
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("写目标 exe 失败: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("复制数据失败: %w", err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	// 在 Windows 上，如果 dst 还被锁着，Rename 会失败；上面已经 wait 过父进程 + 额外 sleep
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s 失败: %w", tmp, dst, err)
	}
	return nil
}

// SpawnApplyHelper 从主程序调用：派生一个分离的自身进程进入 helper 模式，
// 然后主程序**自己退出**，helper 会等主程序退出完毕再替换 exe。
//
// 调用方典型用法：
//
//	if err := updater.SpawnApplyHelper(currentExe, newExe); err != nil { ... }
//	// ...UI 显示"正在重启"... 然后调 wails.Quit() 或 os.Exit(0)
func SpawnApplyHelper(oldExe, newExe string) error {
	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法定位自身路径: %w", err)
	}
	parentPID := os.Getpid()
	args := ApplyHelperArgs(parentPID, oldExe, newExe)

	cmd := exec.Command(selfExe, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("派生 helper 失败: %w", err)
	}
	_ = cmd.Process.Release() // 让 helper 脱离主进程生命周期
	return nil
}
