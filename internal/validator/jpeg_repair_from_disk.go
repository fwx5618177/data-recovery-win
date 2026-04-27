package validator

// 把 partial decoder + DeepRepair 接入 recovery 流程的"从磁盘读 + 修复"入口。
//
// 调用方约定（recovery.Engine.Recover 路径）：
//
//	1. ValidateDeep 判定文件 invalid
//	2. 如果是 JPEG → 调 RepairJPEGFromOffset(file)
//	3. 拿到 RepairOutcome：
//	     - Repaired = true：调用方写 RepairedBytes 到 outputPath，
//	       manifest 记 "部分恢复 X% MCU"
//	     - Repaired = false：跟原 skip 流程一致丢弃
//
// 这是"从源盘抢救最后一份能识别的图像"的兜底路径，业界对照 R-Studio / Photorec
// 的"deep recovery" 模式 —— 用户通常宁可拿到 70% 像素的损坏图也不要 0%。

import (
	"bytes"
	"fmt"
	"image/jpeg"

	"data-recovery/internal/types"
)

// RepairOutcome 描述一次 JPEG 修复尝试的结果
type RepairOutcome struct {
	// Repaired = true 表示得到了能 jpeg.Decode 的修复版本，调用方应写 RepairedBytes 而非原 bytes
	Repaired bool

	// RepairedBytes 修复后的 JPEG bytes（已 stdlib 验证可解）
	// nil 表示没修好，调用方按 skip 处理。
	RepairedBytes []byte

	// Strategy 哪个策略救回的（用户/manifest 可见）
	// "original-decoded" / "boundary-trim" / "dht-injection" / "rst-stitching" /
	// "partial-decode" / "" (失败)
	Strategy string

	// Coverage 估算修复覆盖度（0.0-1.0）
	// 完整修复 = 1.0；partial-decode 路径根据 DecodedMCUs/TotalMCUs 算
	Coverage float64

	// HumanReadable 给 UI 显示的"为什么这文件被标 partial"的说明
	HumanReadable string
}

// RepairJPEGFromOffset 从磁盘读 JPEG 字节 + 跑 DeepRepairJPEG 链 + 包装结果。
//
// 用法（recovery.Engine.Recover）：
//
//	if !verify.IsValid && file.Extension == "jpg" {
//	    out := v.RepairJPEGFromOffset(file)
//	    if out.Repaired {
//	        os.WriteFile(outputPath, out.RepairedBytes, 0644)
//	        // manifest: file.Confidence = out.Coverage * 0.5 (低于 deep-decode-pass 文件)
//	        // file.ValidationMsg = out.HumanReadable
//	    }
//	}
//
// 性能注意：对每个 jpg 失败文件最多跑 4 次 jpeg.Decode（4 种策略），
// 加 in-tree partial decoder 1 次 = ~50-200ms。仅对 ValidateDeep 失败的文件触发，
// 不影响主路径成本。
func (v *Validator) RepairJPEGFromOffset(file *types.RecoveredFile) RepairOutcome {
	if file == nil || file.Size <= 0 {
		return RepairOutcome{}
	}
	// 上限 100MB，防 OOM；实测正常 JPEG < 30MB
	const maxJPEG = 100 * 1024 * 1024
	if file.Size > maxJPEG {
		return RepairOutcome{HumanReadable: "文件过大，跳过 JPEG 修复"}
	}
	data := make([]byte, file.Size)
	n, err := v.reader.ReadAt(data, file.Offset)
	if err != nil || int64(n) < file.Size {
		return RepairOutcome{HumanReadable: fmt.Sprintf("读盘失败: %v", err)}
	}

	// 跑链式策略（DeepRepair 内部已含所有路径）
	repaired, ok := DeepRepairJPEG(data)
	if !ok {
		return RepairOutcome{
			HumanReadable: "JPEG 已严重损坏，所有修复策略失败",
		}
	}

	// 区分策略：判断哪一个救回的（粗粒度，不需要每个策略 fork 路径）
	strategy, coverage, msg := classifyRepair(data, repaired)
	return RepairOutcome{
		Repaired:      true,
		RepairedBytes: repaired,
		Strategy:      strategy,
		Coverage:      coverage,
		HumanReadable: msg,
	}
}

// classifyRepair 通过比较 original vs repaired 来推断走了哪个策略
//
// 启发：
//   - bytes.Equal → 原文件就能解（"original-decoded"，理论不该到这条路径）
//   - len(repaired) < len(original) * 0.5 → 大幅截断，可能是 partial decode 重编码
//   - len(repaired) > len(original) → 注入了什么（DHT 或 RST）
//   - 大致相等 → boundary trim
//
// Coverage 估算：尝试 partial decode 看 DecodedMCUs / TotalMCUs；失败则用启发值。
func classifyRepair(original, repaired []byte) (strategy string, coverage float64, msg string) {
	if bytes.Equal(original, repaired) {
		return "original", 1.0, "原文件可解，无需修复"
	}
	// 跑一次 partial decode 拿精确进度
	pi, err := PartialDecode(original)
	if err == nil && pi.TotalMCUs > 0 {
		mcuRatio := float64(pi.DecodedMCUs) / float64(pi.TotalMCUs)
		if pi.CorruptionMCU >= 0 {
			return "partial-decode", mcuRatio,
				fmt.Sprintf("部分恢复：%d/%d MCUs (%.0f%%)，损坏点 @byte offset %d",
					pi.DecodedMCUs, pi.TotalMCUs, mcuRatio*100, pi.CorruptionByte)
		}
	}
	// 没拿到 partial decode 进度 → 用文件长度比启发
	ratio := float64(len(repaired)) / float64(len(original))
	switch {
	case ratio > 1.05:
		return "header-injection", 0.95, "注入标准 Huffman 表 (DHT) 后可解"
	case ratio < 0.5:
		return "deep-truncation", 0.7, "深度截断后保住前段图像"
	case ratio < 0.95:
		return "boundary-trim", 0.85, "边界修复后可解（截到合法 entropy 流末尾）"
	default:
		// 验证一下确实能解
		if _, err := jpeg.Decode(bytes.NewReader(repaired)); err == nil {
			return "huffman-stitch", 0.8, "Huffman state stitching 后可解"
		}
		return "unknown", 0.6, "经修复后可解（具体策略未知）"
	}
}
