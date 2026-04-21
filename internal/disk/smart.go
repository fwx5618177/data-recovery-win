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

// SMART 是磁盘的 Self-Monitoring, Analysis and Reporting Technology —— 现代盘自带
// 健康状态汇报。我们用它在用户开始扫描前，告诉他"这盘是不是要崩了"，避免
// 在垂死的盘上跑几小时扫描结果中途死掉。
//
// 实现策略：调用本机的 smartctl（smartmontools 项目）—— 不引 cgo / OS-specific 调用。
//   - macOS: brew install smartmontools 后 /opt/homebrew/bin/smartctl
//   - Linux: apt install smartmontools
//   - Windows: smartmontools 安装包 + 默认装到 C:\Program Files\smartmontools\bin\
//
// 找不到 smartctl 不 fail —— 直接返回 ErrSmartCtlNotInstalled，UI 显示一条"装一下能看健康状态"提示即可。

// SmartHealth 是用户视角的健康摘要，避免暴露原始 SMART 属性 ID（用户看不懂）。
type SmartHealth struct {
	Available bool      `json:"available"`         // smartctl 装了没 + 跑成功了没
	Healthy   bool      `json:"healthy"`           // 总体 PASS / FAIL（smartctl -H 输出）
	Model     string    `json:"model"`
	Serial    string    `json:"serial"`
	PowerOnHours uint64 `json:"powerOnHours"`      // 累计通电小时数；超过 4-5 万小时盘风险高
	Reallocated  uint64 `json:"reallocated"`       // 已重映射坏扇区数；>0 都该警惕
	PendingSectors uint64 `json:"pendingSectors"`  // 等待重映射的"摇摆扇区"
	UncorrectableErrors uint64 `json:"uncorrectableErrors"` // 不可纠正错误次数
	Temperature  int    `json:"temperature"`       // °C
	Notes        string `json:"notes"`             // 给用户友好的话
}

// HasCriticalIssue 任意一项不可恢复错误存在就返回 true，UI 应弹"立刻 ddrescue 镜像"警告
func (h *SmartHealth) HasCriticalIssue() bool {
	if !h.Available {
		return false
	}
	return !h.Healthy ||
		h.Reallocated > 0 ||
		h.PendingSectors > 0 ||
		h.UncorrectableErrors > 0
}

// QuerySmart 调用 smartctl 拿健康信息。
// devicePath 例：/dev/sda、\\.\PhysicalDrive0、disk2
// 默认 5s 超时（smartctl 在某些 USB 桥上会卡）
func QuerySmart(ctx context.Context, devicePath string) (*SmartHealth, error) {
	if devicePath == "" {
		return nil, fmt.Errorf("devicePath 为空")
	}
	bin := findSmartctl()
	if bin == "" {
		return &SmartHealth{Available: false, Notes: "smartctl 未安装；装 smartmontools 可看磁盘健康"}, nil
	}

	subCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(subCtx, bin, "-H", "-A", "-i", devicePath)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return &SmartHealth{Available: false, Notes: fmt.Sprintf("smartctl 调用失败: %v", err)}, nil
	}
	return parseSmartctlOutput(string(out)), nil
}

// findSmartctl 找 smartctl 二进制路径
func findSmartctl() string {
	// 优先 PATH 里
	if p, err := exec.LookPath("smartctl"); err == nil {
		return p
	}
	// 退化到几个常见安装位置
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
//
// 我们故意不用 -j JSON 格式，因为旧版本 smartctl 不一定支持。
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
			// "SMART overall-health self-assessment test result: PASSED"
			h.Healthy = strings.Contains(strings.ToUpper(l), "PASS")
		// 注意：行首通常有 SMART ID 数字（"  9 Power_On_Hours ..."），用 Contains 匹配字段名
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
	// 写一句给用户的话
	switch {
	case !h.Healthy:
		h.Notes = "⚠️ SMART 报告盘已经处于失败状态。立刻用 ddrescue 抢救成镜像，再扫镜像。"
	case h.Reallocated > 100 || h.PendingSectors > 50:
		h.Notes = fmt.Sprintf("⚠️ 已重映射 %d 个坏扇区 + %d 个摇摆扇区。建议先做镜像。",
			h.Reallocated, h.PendingSectors)
	case h.PowerOnHours > 50000:
		h.Notes = fmt.Sprintf("⚠️ 通电时间 %d 小时（约 %d 年），机械盘已经超过设计寿命。建议先做镜像。",
			h.PowerOnHours, h.PowerOnHours/24/365)
	case h.Temperature > 60:
		h.Notes = fmt.Sprintf("⚠️ 当前温度 %d°C 偏高，长时间扫描风险大。", h.Temperature)
	default:
		h.Notes = "✅ SMART 健康检查通过。"
	}
	return h
}

// lastUintField 抽出一行里最后一个整数（smartctl 表格行的 RAW_VALUE 通常在最末列）
func lastUintField(line string) uint64 {
	fields := strings.Fields(line)
	for i := len(fields) - 1; i >= 0; i-- {
		// 去掉 "(0)" 这种括号注释
		f := strings.TrimRight(strings.TrimLeft(fields[i], "("), ")")
		if v, err := strconv.ParseUint(f, 10, 64); err == nil {
			return v
		}
	}
	return 0
}
