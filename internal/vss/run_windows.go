//go:build windows

package vss

import (
	"context"
	"fmt"
	"os/exec"
)

// listShadowsPlatform 在 Windows 上调用 vssadmin 并解析输出。
// 需要 Administrator 权限；本应用主进程通常已申请管理员。
func listShadowsPlatform(ctx context.Context) ([]Shadow, error) {
	cmd := exec.CommandContext(ctx, "vssadmin", "list", "shadows")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// vssadmin 在"没有快照"时会以 non-zero 退出。stdout 仍有提示文字。
		// 我们 tolerant 处理：只要能解析出 Shadow 就不视作错误。
		shadows := parseVssadminOutput(string(out))
		if len(shadows) > 0 {
			return shadows, nil
		}
		return nil, fmt.Errorf("vssadmin 执行失败 / 无快照: %w (stdout: %s)", err, string(out))
	}
	return parseVssadminOutput(string(out)), nil
}
