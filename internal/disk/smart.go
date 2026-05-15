package disk

import (
	"context"
	"encoding/binary"
	"fmt"
)

// SMART 是磁盘的 Self-Monitoring, Analysis and Reporting Technology —— 现代盘自带
// 健康状态汇报。我们用它在用户开始扫描前，告诉他"这盘是不是要崩了"，避免在垂死的
// 盘上跑几小时扫描结果中途死掉。
//
// **v2.8.2 重构**：之前只调用本机 smartctl，没装就报"smartctl 未安装"白底框。
// 现在三平台都做原生集成，零外部依赖：
//
//   - Linux:   HDIO_DRIVE_CMD ioctl 直接拿 ATA SMART 512 字节数据
//   - Windows: IOCTL_STORAGE_PREDICT_FAILURE + IOCTL_ATA_PASS_THROUGH
//   - macOS:   `diskutil info -plist` + `system_profiler SPSerialATADataType`
//             （都是 OS 自带，不需要装东西）
//
// 找不到原生路径时退化到 smartctl —— 但用户不会再因为没装 smartctl 就完全看不到健康。

// SmartHealth 是用户视角的健康摘要，避免暴露原始 SMART 属性 ID（用户看不懂）。
type SmartHealth struct {
	Available           bool   `json:"available"` // 数据是否成功拿到
	Healthy             bool   `json:"healthy"`   // 总体 PASS / FAIL
	Model               string `json:"model"`
	Serial              string `json:"serial"`
	PowerOnHours        uint64 `json:"powerOnHours"`        // 累计通电小时数
	Reallocated         uint64 `json:"reallocated"`         // 已重映射坏扇区数
	PendingSectors      uint64 `json:"pendingSectors"`      // 等待重映射的"摇摆扇区"
	UncorrectableErrors uint64 `json:"uncorrectableErrors"` // 不可纠正错误次数
	Temperature         int    `json:"temperature"`         // °C
	Notes               string `json:"notes"`               // 给用户友好的话
	Source              string `json:"source"`              // "native" / "smartctl" / "diskutil" / "unavailable"
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

// QuerySmart 是对外唯一入口。先尝试 OS 原生路径，失败再退化到 smartctl，
// 都失败时返回 Available=false + Notes 解释为什么。永远不抛错（除非 path 空）。
func QuerySmart(ctx context.Context, devicePath string) (*SmartHealth, error) {
	if devicePath == "" {
		return nil, fmt.Errorf("devicePath 为空")
	}

	// 1. OS 原生（platform-specific 文件实现的 querySmartNative）
	if h := querySmartNative(ctx, devicePath); h != nil && h.Available {
		writeNotes(h)
		return h, nil
	}

	// 2. smartctl 退路（如果用户碰巧装了）
	if h := querySmartViaSmartctl(ctx, devicePath); h != nil && h.Available {
		h.Source = "smartctl"
		writeNotes(h)
		return h, nil
	}

	// 3. 都不行 —— 给一条解释清楚的提示，不再说"装个 smartmontools"
	return &SmartHealth{
		Available: false,
		Source:    "unavailable",
		Notes:     unavailableHint(),
	}, nil
}

// writeNotes 把 SmartHealth 各项数据合成一句给用户看的话。
// 各 OS 实现都调它，保证文案一致。
func writeNotes(h *SmartHealth) {
	if h == nil || !h.Available {
		return
	}
	switch {
	case !h.Healthy:
		h.Notes = "SMART 报告盘已经处于失败状态。立刻用 ddrescue 抢救成镜像，再扫镜像。"
	case h.Reallocated > 100 || h.PendingSectors > 50:
		h.Notes = fmt.Sprintf("已重映射 %d 个坏扇区 + %d 个摇摆扇区。建议先做镜像。",
			h.Reallocated, h.PendingSectors)
	case h.UncorrectableErrors > 0:
		h.Notes = fmt.Sprintf("发现 %d 次不可纠正错误。建议先做镜像。", h.UncorrectableErrors)
	case h.PowerOnHours > 50000:
		h.Notes = fmt.Sprintf("通电时间 %d 小时（约 %d 年），机械盘已超过设计寿命。建议先做镜像。",
			h.PowerOnHours, h.PowerOnHours/24/365)
	case h.Temperature > 60:
		h.Notes = fmt.Sprintf("当前温度 %d°C 偏高，长时间扫描风险大。", h.Temperature)
	default:
		h.Notes = "SMART 健康检查通过。"
	}
}

// parseATASmartData 解析标准 ATA SMART READ DATA 返回的 512 字节数据。
//
// 结构（ATA8-ACS spec）：
//
//	offset 0-1: SMART revision number
//	offset 2-361: 30 个 vendor attribute（每个 12 字节）
//	  byte 0: attribute ID
//	  byte 1-2: status flags
//	  byte 3: current value (1-253，通常 100/200 起算)
//	  byte 4: worst value
//	  byte 5-10: raw value (6 字节小端，意义因 ID 而异)
//	  byte 11: reserved
//
// 本函数只挑用户最关心的几个 ID 出来。Linux / Windows 拿到 512 字节后都调这个。
func parseATASmartData(data []byte) *SmartHealth {
	if len(data) < 362 {
		return &SmartHealth{Available: false}
	}
	h := &SmartHealth{Available: true, Healthy: true}
	for i := 0; i < 30; i++ {
		off := 2 + i*12
		if off+12 > len(data) {
			break
		}
		id := data[off]
		if id == 0 {
			continue // 空 slot
		}
		// raw value 是 6 字节小端
		raw := uint64(data[off+5]) |
			uint64(data[off+6])<<8 |
			uint64(data[off+7])<<16 |
			uint64(data[off+8])<<24 |
			uint64(data[off+9])<<32 |
			uint64(data[off+10])<<40
		switch id {
		case 5: // Reallocated_Sector_Ct
			h.Reallocated = raw
		case 9: // Power_On_Hours —— 取低 16 位（高位常是噪声 / vendor flag）
			h.PowerOnHours = raw & 0xFFFFFFFF
		case 194: // Temperature_Celsius —— 低字节是当前温度
			t := int(raw & 0xFF)
			if t > 0 && t < 200 {
				h.Temperature = t
			}
		case 197: // Current_Pending_Sector
			h.PendingSectors = raw
		case 198: // Offline_Uncorrectable
			h.UncorrectableErrors = raw
		}
	}
	// 没有 SMART RETURN STATUS 时从属性反推 health：任何"重映射 / 摇摆 / 不可纠错" > 0 即不健康
	if h.Reallocated > 0 || h.PendingSectors > 0 || h.UncorrectableErrors > 0 {
		h.Healthy = false
	}
	return h
}

// 让 binary 不报 unused（部分 OS 实现里用到，统一导入）
var _ = binary.LittleEndian

// unavailableHint 返回"SMART 不可用"时给用户的解释。各平台不同：
//   - macOS：可能是 USB 桥不透传 SMART
//   - Linux：可能是 USB 设备 / nvme / 没有 root
//   - Windows：可能是没有管理员 / 虚拟盘 / USB 桥
func unavailableHint() string {
	return "无法读取 SMART —— 多见于 U 盘 / SD 卡（USB 桥不透传 SMART 命令），" +
		"以及虚拟盘、镜像文件、网络盘。对扫描没影响，可以继续。"
}
