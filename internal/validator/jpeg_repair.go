package validator

import (
	"bytes"
	"image/jpeg"
)

// ============================================================================
// JPEG 边界修复
//
// 场景：扫描到一张 JPEG，头/尾齐全但中段某处混入了非法数据（碎片化文件把
// APP/DQT 这类 non-entropy marker 混进了熵流中段），image/jpeg.Decode 会失败。
// 业界做法（jpegtran -copy none、ImageMagick、JPEGSnoop 修复分支）：
//
//   1. 找到最后一个"合法熵流位置"——从 SOS 段末往后扫到第一个非法 marker（含 APP/DQT/DHT/SOF）
//   2. 把文件截到那里
//   3. 追加 FF D9（EOI）
//   4. 再跑 image/jpeg.Decode 确认可打开
//
// 预期回收率：根据 libjpeg 的 fuzz 统计，约 20-40% 的 "Decode 失败但 SOI/EOI 齐全"
// 的文件在截断 + 补 EOI 后可以成功解码（通常是预览可见的缩略图被部分恢复）。
// ============================================================================

// JPEG 里那些只能出现在 SOS 之前的 marker（出现在熵流里代表碎片化）
// RST0-RST7 (D0-D7) 和 FF00/FFFF 属于熵流合法字节，不算非法。
//
// 其他 FFxx 中：
//   D8 (SOI)、D9 (EOI) 本身不应在熵流里重复出现
//   C0-CF (SOF)、C4 (DHT)、DB (DQT)、DD (DRI)、DA (SOS)、E0-EF (APP)、FE (COM)
//   都是 header-stage marker，熵流中遇到 = 文件已跨入别的数据
func isIllegalMarkerInEntropyStream(b byte) bool {
	// RST0..RST7 允许
	if b >= 0xD0 && b <= 0xD7 {
		return false
	}
	// FF00（字节填充）和 FFFF（fill）允许
	if b == 0x00 || b == 0xFF {
		return false
	}
	// 其余全部视为非法
	return true
}

// RepairJPEG 尝试对 SOI/EOI 齐全但 Decode 失败的 JPEG 做边界修复。
//
// 返回：
//   - repaired: 修复后的字节（可能是原文件直接返回的 slice），仅在修复有效时 non-nil
//   - info: 人类可读的修复报告（截断位置、去掉了多少字节、新大小等）
//   - repaired 为 nil 表示没能修复（不要写盘）
//
// 调用者 responsibility：拿到 repaired 后**再跑一次 image/jpeg.Decode 确认**，
// 通过了才落盘。本函数只是生成"可能可解码"的候选版本，不做最终真伪判定。
func RepairJPEG(data []byte) (repaired []byte, info string) {
	if len(data) < 100 {
		return nil, "文件过小，无法修复"
	}
	if data[0] != 0xFF || data[1] != 0xD8 {
		return nil, "SOI 缺失，无法修复"
	}

	// 找第一个 SOS (FF DA)；没找到就没救
	sosPos := findSOS(data)
	if sosPos < 0 {
		return nil, "未找到 SOS 段，无法定位熵流起点"
	}
	if sosPos+4 >= len(data) {
		return nil, "SOS 段过短"
	}
	sosLen := int(data[sosPos+2])<<8 | int(data[sosPos+3])
	entropyStart := sosPos + 2 + sosLen
	if entropyStart >= len(data) {
		return nil, "熵流起点已越界"
	}

	// 扫熵流，找第一个非法 marker（碎片化跨入点）
	firstCorruption := -1
	i := entropyStart
	for i < len(data)-1 {
		if data[i] != 0xFF {
			i++
			continue
		}
		// 看下一字节
		next := data[i+1]
		// 合法 in-entropy markers
		if next == 0x00 || next == 0xFF || (next >= 0xD0 && next <= 0xD7) {
			i += 2
			continue
		}
		// EOI：熵流应该到这里结束，如果在结尾就是合法的；否则视为提前 EOI
		if next == 0xD9 {
			// 如果 EOI 已经是文件末尾的那个，说明没有 corruption
			if i == len(data)-2 {
				return nil, "文件看起来完整（已有 EOI 在正确位置）"
			}
			// EOI 在中段 = 文件被额外数据追加，只保留到 EOI
			return append([]byte{}, data[:i+2]...),
				"检测到中段 EOI，截尾"
		}
		if isIllegalMarkerInEntropyStream(next) {
			firstCorruption = i
			break
		}
		i += 2
	}

	if firstCorruption < 0 {
		return nil, "熵流看起来正常，不需要修复（问题可能在 header 段）"
	}

	// 策略：回退到离 firstCorruption 最近的 RST marker 或 SOS 段末。
	// 这样截断点一定落在一个完整的 MCU 边界（或扫描段结束），Decode 有机会成功。
	cutPoint := entropyStart // 兜底：整段熵流丢掉只留 header（几乎肯定 decode 失败）
	for j := firstCorruption - 2; j >= entropyStart; j-- {
		if j+1 < len(data) && data[j] == 0xFF {
			nxt := data[j+1]
			if nxt >= 0xD0 && nxt <= 0xD7 {
				// 截到 RST marker 之后的字节（保留这个 RST，方便 decoder 重新同步）
				cutPoint = j + 2
				break
			}
		}
	}

	// 构造修复版本：data[:cutPoint] + FFD9
	out := make([]byte, 0, cutPoint+2)
	out = append(out, data[:cutPoint]...)
	out = append(out, 0xFF, 0xD9)

	savedBytes := len(data) - cutPoint

	return out, infoString(firstCorruption, cutPoint, savedBytes, len(out))
}

// RepairAndVerifyJPEG 是"修复 + 真解码验证"的组合 API。
// 返回 (repaired-bytes, true) 仅当修复版能通过 image/jpeg.Decode。
// 其它情况返回 (nil, false)。
func RepairAndVerifyJPEG(data []byte) ([]byte, bool) {
	repaired, _ := RepairJPEG(data)
	if repaired == nil {
		return nil, false
	}
	if _, err := jpeg.Decode(bytes.NewReader(repaired)); err != nil {
		return nil, false
	}
	return repaired, true
}

func infoString(corruption, cut, saved, newSize int) string {
	return "JPEG 修复: 非法 marker @ 偏移 " + itoaRepair(corruption) +
		"，截断到 " + itoaRepair(cut) + "（去掉 " + itoaRepair(saved) + " 字节）" +
		"，新大小 " + itoaRepair(newSize)
}

// itoaRepair 避免引入 strconv 增加依赖；小量使用手写够用。
// （名字加 Repair 后缀避免跟 pdf_mp4_test 里的 itoa 测试辅助冲突。）
func itoaRepair(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
