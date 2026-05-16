package disk

import (
	"encoding/binary"
	"fmt"
)

// parseNVMeSmartHealthLog 解析 NVM Express 1.4 spec 5.14.1.2 定义的
// SMART/Health Information Log（512 字节）。
//
// 字段布局（offset 单位为字节，128-bit 字段都是小端）：
//
//	[0]       Critical Warning (8 个 bit 标志)
//	[1..2]    Composite Temperature (Kelvin, u16 LE)
//	[3]       Available Spare (%)
//	[4]       Available Spare Threshold (%)
//	[5]       Percentage Used (%)
//	[32..47]  Data Units Read (128-bit LE; 1 unit = 1000 × 512 字节)
//	[48..63]  Data Units Written
//	[128..143] Power On Hours (128-bit LE, hours)
//	[144..159] Unsafe Shutdowns
//	[160..175] Media and Data Integrity Errors
//	[176..191] Number of Error Information Log Entries
//
// 我们只读 SmartHealth 关心的几个字段。返回的结构里：
//   - Healthy: CriticalWarning==0 && PercentageUsed<100 && MediaErrors==0
//   - PowerOnHours: 取 Power On Hours 的低 64 bit（NVMe 实际写满 16 字节几乎不可能）
//   - UncorrectableErrors: Media and Data Integrity Errors 低 64 bit
//   - Temperature: Composite Temperature (kelvin) - 273
//   - Reallocated: NVMe 无直接对应字段 —— 用 Unsafe Shutdowns 代替（同样表征"非正常运行"），
//     但语义不一样，所以注释清楚
func parseNVMeSmartHealthLog(log []byte) *SmartHealth {
	if len(log) < 192 {
		return nil
	}
	h := &SmartHealth{Available: true, Healthy: true}

	criticalWarning := log[0]
	tempKelvin := binary.LittleEndian.Uint16(log[1:3])
	availableSpare := log[3]
	availableSpareThreshold := log[4]
	percentageUsed := log[5]

	powerOnHoursLo := binary.LittleEndian.Uint64(log[128:136])
	mediaErrorsLo := binary.LittleEndian.Uint64(log[160:168])
	unsafeShutdownsLo := binary.LittleEndian.Uint64(log[144:152])

	// Healthy 判定：任一异常都算不健康
	if criticalWarning != 0 {
		h.Healthy = false
	}
	if percentageUsed >= 100 {
		h.Healthy = false
	}
	if mediaErrorsLo > 0 {
		h.Healthy = false
	}
	if availableSpareThreshold > 0 && availableSpare < availableSpareThreshold {
		h.Healthy = false
	}

	h.PowerOnHours = powerOnHoursLo
	h.UncorrectableErrors = mediaErrorsLo
	h.Reallocated = unsafeShutdownsLo // NVMe 无 "重映射坏扇区"，用 Unsafe Shutdowns 占位
	if tempKelvin > 273 && tempKelvin < 573 {
		h.Temperature = int(tempKelvin) - 273
	}

	// Notes 加 NVMe 专属信息让用户能看懂
	if h.Healthy {
		h.Notes = fmt.Sprintf("NVMe SSD 健康 | 已用寿命 %d%% | 通电 %d 小时",
			percentageUsed, h.PowerOnHours)
	}

	return h
}
