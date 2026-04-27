package disk

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// querySmartViaSmartctl 是 OS 原生路径都不通时的退路 —— 如果用户碰巧装了
// smartmontools 就用它。装不装由用户决定，主流程不依赖。
func querySmartViaSmartctl(ctx context.Context, devicePath string) *SmartHealth {
	bin := findSmartctl()
	if bin == "" {
		return nil // 没装就直接 nil，让 QuerySmart 知道 fallback 也没货
	}

	subCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(subCtx, bin, "-H", "-A", "-i", devicePath)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return &SmartHealth{Available: false, Notes: fmt.Sprintf("smartctl 调用失败: %v", err)}
	}
	return parseSmartctlOutput(string(out))
}

// findSmartctl 找 smartctl 二进制路径
func findSmartctl() string {
	if p, err := exec.LookPath("smartctl"); err == nil {
		return p
	}
	candidates := []string{}
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/opt/homebrew/sbin/smartctl",
			"/opt/homebrew/bin/smartctl",
			"/usr/local/sbin/smartctl",
			"/usr/local/bin/smartctl",
		}
	case "linux":
		candidates = []string{"/usr/sbin/smartctl", "/sbin/smartctl"}
	case "windows":
		candidates = []string{
			`C:\Program Files\smartmontools\bin\smartctl.exe`,
			`C:\Program Files (x86)\smartmontools\bin\smartctl.exe`,
		}
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	return ""
}

// parseSmartctlOutput 解 smartctl -H -A -i 的人类可读输出。
// 故意不用 -j JSON 因为旧版 smartctl 不一定支持。
func parseSmartctlOutput(text string) *SmartHealth {
	h := &SmartHealth{Available: true, Healthy: true}
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "Device Model:") || strings.HasPrefix(l, "Model Number:"):
			h.Model = strings.TrimSpace(l[strings.Index(l, ":")+1:])
		case strings.HasPrefix(l, "Serial Number:") || strings.HasPrefix(l, "Serial:"):
			h.Serial = strings.TrimSpace(l[strings.Index(l, ":")+1:])
		case strings.Contains(l, "SMART overall-health"):
			h.Healthy = strings.Contains(strings.ToUpper(l), "PASS")
		case strings.Contains(l, "Power_On_Hours") || strings.Contains(l, "Power On Hours"):
			h.PowerOnHours = lastUintField(l)
		case strings.Contains(l, "Reallocated_Sector_Ct") || strings.Contains(l, "Reallocated Sector"):
			h.Reallocated = lastUintField(l)
		case strings.Contains(l, "Current_Pending_Sector") || strings.Contains(l, "Current Pending Sector"):
			h.PendingSectors = lastUintField(l)
		case strings.Contains(l, "Offline_Uncorrectable") || strings.Contains(l, "Uncorrectable"):
			h.UncorrectableErrors = lastUintField(l)
		case strings.Contains(l, "Temperature_Celsius") || strings.Contains(l, "Current Temperature"):
			if n := int(lastUintField(l)); n > 0 && n < 200 {
				h.Temperature = n
			}
		}
	}
	return h
}

// lastUintField 抽出一行里最后一个整数（smartctl 表格行的 RAW_VALUE 通常在最末列）
func lastUintField(line string) uint64 {
	fields := strings.Fields(line)
	for i := len(fields) - 1; i >= 0; i-- {
		f := strings.TrimRight(strings.TrimLeft(fields[i], "("), ")")
		if v, err := strconv.ParseUint(f, 10, 64); err == nil {
			return v
		}
	}
	return 0
}
