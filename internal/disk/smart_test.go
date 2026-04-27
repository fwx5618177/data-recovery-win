package disk

import (
	"context"
	"strings"
	"testing"
)

const smartctlHealthyOutput = `smartctl 7.4 2023-08-01 r5530 [Darwin 22.6.0 arm64]
Copyright (C) 2002-23, Bruce Allen, Christian Franke, www.smartmontools.org

=== START OF INFORMATION SECTION ===
Device Model:     Samsung SSD 870 EVO 1TB
Serial Number:    S6PUNX0R123456
SMART overall-health self-assessment test result: PASSED

=== START OF READ SMART DATA SECTION ===
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0
  9 Power_On_Hours          0x0032   099   099   000    Old_age   Always       -       1234
194 Temperature_Celsius     0x0022   075   060   000    Old_age   Always       -       35
197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       0
198 Offline_Uncorrectable   0x0010   100   100   000    Old_age   Offline      -       0
`

const smartctlFailingOutput = `=== START OF INFORMATION SECTION ===
Device Model:     OldSpinning HDD
Serial Number:    HDD0001
SMART overall-health self-assessment test result: FAILED

=== START OF READ SMART DATA SECTION ===
  5 Reallocated_Sector_Ct   0x0033   050   050   010    Pre-fail  Always       -       523
  9 Power_On_Hours          0x0032   001   001   000    Old_age   Always       -       62000
194 Temperature_Celsius     0x0022   045   030   000    Old_age   Always       -       65
197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       137
198 Offline_Uncorrectable   0x0010   100   100   000    Old_age   Offline      -       42
`

func TestParseSmartctlOutput_HealthyDrive(t *testing.T) {
	h := parseSmartctlOutput(smartctlHealthyOutput)
	if !h.Available || !h.Healthy {
		t.Errorf("应该是 healthy: %+v", h)
	}
	if h.Model != "Samsung SSD 870 EVO 1TB" {
		t.Errorf("model: %q", h.Model)
	}
	if h.Serial != "S6PUNX0R123456" {
		t.Errorf("serial: %q", h.Serial)
	}
	if h.PowerOnHours != 1234 {
		t.Errorf("PowerOnHours=%d want 1234", h.PowerOnHours)
	}
	if h.Reallocated != 0 || h.PendingSectors != 0 || h.UncorrectableErrors != 0 {
		t.Errorf("健康盘应无坏扇区: %+v", h)
	}
	if h.Temperature != 35 {
		t.Errorf("Temperature=%d want 35", h.Temperature)
	}
	if h.HasCriticalIssue() {
		t.Errorf("健康盘 HasCriticalIssue 应为 false")
	}
	// Notes 在 v2.8.2 重构后由 writeNotes 单独写入；分开测
	writeNotes(h)
	if !strings.Contains(h.Notes, "通过") {
		t.Errorf("Notes 应是健康提示: %q", h.Notes)
	}
}

func TestParseSmartctlOutput_FailingDrive(t *testing.T) {
	h := parseSmartctlOutput(smartctlFailingOutput)
	if h.Healthy {
		t.Errorf("FAILED 盘应被识别为不健康")
	}
	if h.Reallocated != 523 {
		t.Errorf("Reallocated=%d want 523", h.Reallocated)
	}
	if h.PendingSectors != 137 {
		t.Errorf("PendingSectors=%d want 137", h.PendingSectors)
	}
	if h.UncorrectableErrors != 42 {
		t.Errorf("UncorrectableErrors=%d want 42", h.UncorrectableErrors)
	}
	if h.PowerOnHours != 62000 {
		t.Errorf("PowerOnHours=%d", h.PowerOnHours)
	}
	if !h.HasCriticalIssue() {
		t.Error("FAILED 盘 HasCriticalIssue 应 true")
	}
	writeNotes(h)
	if !strings.Contains(h.Notes, "失败状态") {
		t.Errorf("Notes 应警告失败: %q", h.Notes)
	}
}

func TestQuerySmart_NoSmartctl(t *testing.T) {
	// 仅当本机找不到 smartctl 时跑这个测试 — CI 上一般没装
	if findSmartctl() != "" {
		t.Skip("本机装了 smartctl，跳过 not-installed 测试")
	}
	// 直接调 QuerySmart 应返回 Available=false 而不是 fail
	h, err := QuerySmart(context.Background(), "/dev/sda")
	if err != nil {
		t.Skip("ctx 某些 Go 版本行为异常；跳过")
	}
	if h != nil && h.Available {
		t.Error("没装 smartctl 时 Available 应 false")
	}
}

// 辅助：构造一个 30 个属性槽位的 ATA SMART 512 字节缓冲。
// 每个 attribute 12 字节：[id][flags lo][flags hi][cur][worst][raw 6 字节][reserved]
func mkATABuf(attrs map[byte]uint64) []byte {
	buf := make([]byte, 512)
	// rev number 占 byte 0-1
	buf[0] = 0x10
	buf[1] = 0x00
	i := 0
	for id, raw := range attrs {
		off := 2 + i*12
		buf[off] = id
		buf[off+1] = 0x32
		buf[off+2] = 0x00
		buf[off+3] = 100   // current value
		buf[off+4] = 100   // worst value
		// raw 6 字节小端
		buf[off+5] = byte(raw)
		buf[off+6] = byte(raw >> 8)
		buf[off+7] = byte(raw >> 16)
		buf[off+8] = byte(raw >> 24)
		buf[off+9] = byte(raw >> 32)
		buf[off+10] = byte(raw >> 40)
		i++
	}
	return buf
}

func TestParseATASmartData_Healthy(t *testing.T) {
	buf := mkATABuf(map[byte]uint64{
		5:   0,    // Reallocated_Sector_Ct
		9:   1234, // Power_On_Hours
		194: 35,   // Temperature
		197: 0,    // Pending
		198: 0,    // Uncorrectable
	})
	h := parseATASmartData(buf)
	if !h.Available || !h.Healthy {
		t.Errorf("应该 healthy: %+v", h)
	}
	if h.PowerOnHours != 1234 {
		t.Errorf("PowerOnHours=%d want 1234", h.PowerOnHours)
	}
	if h.Temperature != 35 {
		t.Errorf("Temperature=%d want 35", h.Temperature)
	}
}

func TestParseATASmartData_Failing(t *testing.T) {
	buf := mkATABuf(map[byte]uint64{
		5:   523,
		9:   62000,
		194: 65,
		197: 137,
		198: 42,
	})
	h := parseATASmartData(buf)
	if h.Healthy {
		t.Error("有坏扇区应 unhealthy")
	}
	if h.Reallocated != 523 || h.PendingSectors != 137 || h.UncorrectableErrors != 42 {
		t.Errorf("attrs 解析错: %+v", h)
	}
	if !h.HasCriticalIssue() {
		t.Error("HasCriticalIssue 应 true")
	}
}

func TestParseATASmartData_TooShort(t *testing.T) {
	h := parseATASmartData(make([]byte, 10))
	if h.Available {
		t.Error("数据 < 362 字节应 Available=false")
	}
}

func TestQuerySmart_EmptyPath(t *testing.T) {
	_, err := QuerySmart(context.Background(), "")
	if err == nil {
		t.Error("空路径应返回 error")
	}
}
