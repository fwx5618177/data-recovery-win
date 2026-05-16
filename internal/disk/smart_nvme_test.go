package disk

import (
	"encoding/binary"
	"testing"
)

// TestParseNVMeSmartHealthLog_Healthy 构造一份"全绿"的 NVMe SMART Log，
// 验证解析后所有字段映射正确。
func TestParseNVMeSmartHealthLog_Healthy(t *testing.T) {
	log := make([]byte, 512)
	// Critical Warning = 0 (健康)
	log[0] = 0
	// Composite Temperature = 318K (45°C，典型 SSD 工作温度)
	binary.LittleEndian.PutUint16(log[1:3], 318)
	log[3] = 100 // Available Spare = 100%
	log[4] = 10  // Available Spare Threshold = 10%
	log[5] = 2   // Percentage Used = 2% (基本全新)
	// Power On Hours = 19467 hours (低 64 bit)
	binary.LittleEndian.PutUint64(log[128:136], 19467)
	// Media Errors = 0
	// Unsafe Shutdowns = 51 (低 64 bit)
	binary.LittleEndian.PutUint64(log[144:152], 51)

	h := parseNVMeSmartHealthLog(log)
	if h == nil {
		t.Fatal("parseNVMeSmartHealthLog 返回 nil")
	}
	if !h.Available {
		t.Error("Available 应为 true")
	}
	if !h.Healthy {
		t.Error("Healthy 应为 true (CW=0, PercentUsed<100, MediaErrors=0)")
	}
	if h.Temperature != 45 {
		t.Errorf("Temperature: 期望 45°C, 得到 %d", h.Temperature)
	}
	if h.PowerOnHours != 19467 {
		t.Errorf("PowerOnHours: 期望 19467, 得到 %d", h.PowerOnHours)
	}
	if h.UncorrectableErrors != 0 {
		t.Errorf("UncorrectableErrors: 期望 0, 得到 %d", h.UncorrectableErrors)
	}
	if h.Reallocated != 51 {
		t.Errorf("Reallocated (= Unsafe Shutdowns): 期望 51, 得到 %d", h.Reallocated)
	}
}

// TestParseNVMeSmartHealthLog_CriticalWarning 任何 critical warning bit
// 都应该让 Healthy=false。
func TestParseNVMeSmartHealthLog_CriticalWarning(t *testing.T) {
	for _, bit := range []byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20} {
		log := make([]byte, 512)
		log[0] = bit
		log[3] = 100
		binary.LittleEndian.PutUint16(log[1:3], 318)
		h := parseNVMeSmartHealthLog(log)
		if h == nil || h.Healthy {
			t.Errorf("CriticalWarning bit 0x%02X 应让 Healthy=false, 得到 %+v", bit, h)
		}
	}
}

// TestParseNVMeSmartHealthLog_WornOutSSD 写满寿命（PercentageUsed >= 100）应不健康。
func TestParseNVMeSmartHealthLog_WornOutSSD(t *testing.T) {
	log := make([]byte, 512)
	log[0] = 0
	log[5] = 105 // 写超 100%
	h := parseNVMeSmartHealthLog(log)
	if h.Healthy {
		t.Error("PercentageUsed=105 应让 Healthy=false")
	}
}

// TestParseNVMeSmartHealthLog_LowSpare 备用空间低于阈值应不健康。
func TestParseNVMeSmartHealthLog_LowSpare(t *testing.T) {
	log := make([]byte, 512)
	log[3] = 5  // Available Spare = 5%
	log[4] = 10 // Threshold = 10%  → spare 已掉到阈值以下
	h := parseNVMeSmartHealthLog(log)
	if h.Healthy {
		t.Error("Available Spare(5%) < Threshold(10%) 应让 Healthy=false")
	}
}

// TestParseNVMeSmartHealthLog_MediaErrors media errors > 0 应不健康。
func TestParseNVMeSmartHealthLog_MediaErrors(t *testing.T) {
	log := make([]byte, 512)
	binary.LittleEndian.PutUint64(log[160:168], 7)
	h := parseNVMeSmartHealthLog(log)
	if h.Healthy {
		t.Error("MediaErrors=7 应让 Healthy=false")
	}
	if h.UncorrectableErrors != 7 {
		t.Errorf("UncorrectableErrors: 期望 7, 得到 %d", h.UncorrectableErrors)
	}
}

// TestParseNVMeSmartHealthLog_TruncatedLog 不到 192 字节应返回 nil。
func TestParseNVMeSmartHealthLog_TruncatedLog(t *testing.T) {
	short := make([]byte, 100)
	if h := parseNVMeSmartHealthLog(short); h != nil {
		t.Errorf("100B log 应返回 nil, 得到 %+v", h)
	}
}
