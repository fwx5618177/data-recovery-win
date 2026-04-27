//go:build darwin

package disk

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// macOS 原生 SMART：走 OS 自带的 `diskutil info` —— 不需要装 smartmontools。
// diskutil 输出里有 "SMART Status: Verified / Failing / Not Supported" 一项。
//
// 进一步细节（SMART 属性、温度、Power-On Hours）：用 `system_profiler
// SPSerialATADataType` —— 也是 macOS 自带，输出含 SMART 字段。
//
// 这两个工具都是 / usr / sbin / 下的 macOS 标配，**不需要用户额外装东西**。
// 真要 SMART 全属性还是得 IOKit cgo，那是 v2.9 的活；当前方案已经能告诉用户
// "盘是不是要崩了"，对扫描决策足够。

func querySmartNative(ctx context.Context, devicePath string) *SmartHealth {
	// devicePath 可能是 "/dev/disk0" 或 "disk0"。diskutil info 都能吃。
	subCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(subCtx, "/usr/sbin/diskutil", "info", devicePath).CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil
	}
	h := parseDiskutilInfo(string(out))
	if h == nil {
		return nil
	}
	h.Source = "diskutil"

	// 用 system_profiler 补 SMART 属性（如果是 SATA）
	enrichDarwinSP(subCtx, h)
	return h
}

// parseDiskutilInfo 解 `diskutil info <device>` 的人类可读输出。
// 关键字段：
//   Device / Media Name:    Apple SSD AP1024Z
//   Device Identifier:      disk0
//   SMART Status:           Verified | Failing | Not Supported | Unknown
func parseDiskutilInfo(text string) *SmartHealth {
	h := &SmartHealth{Available: false}
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		key, val := splitDiskutilLine(l)
		switch {
		case key == "device / media name", key == "media name", key == "device / model":
			h.Model = val
		case key == "smart status":
			switch strings.ToLower(val) {
			case "verified":
				h.Available = true
				h.Healthy = true
			case "failing":
				h.Available = true
				h.Healthy = false
			case "not supported", "unknown", "":
				// USB 桥 / 虚拟盘常见 —— 不算可用
			}
		}
	}
	if !h.Available {
		return nil
	}
	return h
}

// splitDiskutilLine 把 "  Key: Value" 拆成 (lower(key), value)
func splitDiskutilLine(l string) (string, string) {
	idx := strings.Index(l, ":")
	if idx < 0 {
		return "", ""
	}
	return strings.ToLower(strings.TrimSpace(l[:idx])), strings.TrimSpace(l[idx+1:])
}

// enrichDarwinSP 跑 system_profiler 补 Power-On Hours / Temperature / Reallocated
// 等细节。失败不致命，只是 H 里这几个字段保持 0。
//
// system_profiler SPSerialATADataType 文本输出里关键行：
//   Power On Hours:                       12345
//   Temperature:                          35
//   Reallocated Sector Count:             0
//   Pending Sector Count:                 0
func enrichDarwinSP(ctx context.Context, h *SmartHealth) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/system_profiler", "SPSerialATADataType").Output()
	if err != nil || len(out) == 0 {
		return
	}
	reSerial := regexp.MustCompile(`(?i)Serial Number:\s+(\S+)`)
	if h.Serial == "" {
		if m := reSerial.FindStringSubmatch(string(out)); len(m) == 2 {
			h.Serial = m[1]
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		idx := strings.Index(l, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(l[:idx]))
		val := strings.TrimSpace(l[idx+1:])
		switch {
		case strings.Contains(key, "power on hours"):
			if n, err := strconv.ParseUint(val, 10, 64); err == nil {
				h.PowerOnHours = n
			}
		case key == "temperature", strings.Contains(key, "temperature"):
			// 可能是 "35" 或 "35 °C"
			val = strings.TrimSuffix(val, "°C")
			val = strings.TrimSpace(val)
			if n, err := strconv.Atoi(val); err == nil && n > 0 && n < 200 {
				h.Temperature = n
			}
		case strings.Contains(key, "reallocated sector"):
			if n, err := strconv.ParseUint(val, 10, 64); err == nil {
				h.Reallocated = n
			}
		case strings.Contains(key, "pending sector"):
			if n, err := strconv.ParseUint(val, 10, 64); err == nil {
				h.PendingSectors = n
			}
		}
	}
	// 反推：如果 SMART Status 说 Verified 但属性里有坏扇区，仍然标 Healthy=false
	if h.Reallocated > 0 || h.PendingSectors > 0 {
		h.Healthy = false
	}
}
