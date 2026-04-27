package validator

// ============================================================================
// JPEG 深度修复
//
// 在 jpeg_repair.go 的边界修复（截尾 + 补 EOI）之上加三种"深度"修复策略：
//
//   1. Standard Huffman 注入（Annex K）
//      许多 JPEG 因 NTFS data run 第一段被覆盖而丢失 DHT 段。被覆盖的几率比丢
//      entropy 段小但实际中很常见，因为 DHT 集中在文件前 1KB 区域。
//      标准 JPEG（JFIF / Exif baseline）99% 用 ITU T.81 Annex K 推荐的 4 张
//      固定 Huffman 表（DC×2 + AC×2，luma + chroma）。把这 4 张表合成一个
//      DHT 段插入到 SOS 之前 → 多数损坏的 baseline JPEG 立即可解。
//
//   2. Progressive scan truncation
//      progressive JPEG（SOF2，不是 baseline SOF0）有多个 SOS 段，每个是一次
//      "扫描"，先低频后高频组合出最终图像。如果尾段 corrupt，截到最后一个
//      *完整* 的 SOS scan 之后 → 仍能 decode 出一张低频版本的图。
//
//   3. RST-aligned truncation
//      若图含 restart marker (FFD0..FFD7)，每个 RST 之间是独立 MCU 段。
//      碰到 corruption 时退到上一个 RST → decoder 能从下一段重新同步。
//      （已在 jpeg_repair.go 实现，深度修复链复用）
//
// ============================================================================

import (
	"bytes"
	"image/jpeg"
)

// ----------------------------------------------------------------------------
// ITU T.81 Annex K 标准 Huffman 表
// ----------------------------------------------------------------------------
//
// 这 4 张表是 JPEG 标准 Annex K 推荐的"典型"Huffman 表。99% baseline JPEG
// （包括 Photoshop / Lightroom / 手机相机 / 截图工具默认导出）直接用这 4 张。
// 即使 encoder 自己优化过 Huffman，注入这 4 张通常也能解出图像（比标准慢但能解）。
//
// 数据来源：T.81 Annex K, K.3.3 / K.3.4
//
// 段格式（DHT segment）：
//   [16 字节 BITS 表]：每个 codeLen (1..16) 的 code 数量
//   [N 字节 HUFFVAL 表]：N = sum(BITS)，按编码顺序的 8-bit symbol 值

// dcLumaBits / dcLumaVals: DC luma table (Tc=0, Th=0)
var dcLumaBits = []byte{0, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0}
var dcLumaVals = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
}

// dcChromaBits / dcChromaVals: DC chroma table (Tc=0, Th=1)
var dcChromaBits = []byte{0, 0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}
var dcChromaVals = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B,
}

// acLumaBits / acLumaVals: AC luma table (Tc=1, Th=0)
var acLumaBits = []byte{0, 0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d}
var acLumaVals = []byte{
	0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12,
	0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
	0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
	0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0,
	0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16,
	0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
	0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
	0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
	0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
	0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
	0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
	0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
	0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5,
	0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4,
	0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
	0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA,
	0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
	0xF9, 0xFA,
}

// acChromaBits / acChromaVals: AC chroma table (Tc=1, Th=1)
var acChromaBits = []byte{0, 0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77}
var acChromaVals = []byte{
	0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21,
	0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
	0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91,
	0xA1, 0xB1, 0xC1, 0x09, 0x23, 0x33, 0x52, 0xF0,
	0x15, 0x62, 0x72, 0xD1, 0x0A, 0x16, 0x24, 0x34,
	0xE1, 0x25, 0xF1, 0x17, 0x18, 0x19, 0x1A, 0x26,
	0x27, 0x28, 0x29, 0x2A, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
	0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
	0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
	0x79, 0x7A, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96,
	0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5,
	0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4,
	0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3,
	0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2,
	0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
	0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
	0xEA, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
	0xF9, 0xFA,
}

// BuildStandardDHT 拼一个完整的 DHT 段（含 4 张表），可直接插入 JPEG。
//
// DHT 段格式 (T.81 §B.2.4.2)：
//
//	FF C4
//	uint16 段长（含自身 2 字节）
//	for each table:
//	   1 byte (Tc<<4 | Th)          // Tc=0 DC / 1 AC; Th=table index 0..3
//	   16 bytes BITS
//	   N bytes HUFFVAL              // N = sum(BITS)
func BuildStandardDHT() []byte {
	// 4 张表的内容拼接
	tables := [][]byte{
		buildOneTable(0x00, dcLumaBits, dcLumaVals),
		buildOneTable(0x01, dcChromaBits, dcChromaVals),
		buildOneTable(0x10, acLumaBits, acLumaVals),
		buildOneTable(0x11, acChromaBits, acChromaVals),
	}
	totalLen := 2 // 段长字段本身 2 字节
	for _, t := range tables {
		totalLen += len(t)
	}
	out := make([]byte, 0, 2+totalLen)
	out = append(out, 0xFF, 0xC4)
	out = append(out, byte(totalLen>>8), byte(totalLen&0xFF))
	for _, t := range tables {
		out = append(out, t...)
	}
	return out
}

func buildOneTable(tcTh byte, bits, vals []byte) []byte {
	out := make([]byte, 0, 1+16+len(vals))
	out = append(out, tcTh)
	out = append(out, bits...)
	out = append(out, vals...)
	return out
}

// HasDHT 判断 JPEG 数据是否含 DHT 段（FF C4）。
// 只查 SOS 段之前的 header 区域；entropy 流里 FFC4 是数据。
func HasDHT(data []byte) bool {
	sosPos := findSOS(data)
	end := sosPos
	if end < 0 {
		end = len(data)
	}
	for i := 2; i+1 < end; i++ {
		if data[i] == 0xFF && data[i+1] == 0xC4 {
			return true
		}
	}
	return false
}

// InjectStandardDHT 在 SOS 段之前插入标准 Annex K Huffman 表。
//
// 适用场景：JPEG 头部被损坏导致 DHT 段缺失（最常见的"jpeg.Decode: missing
// Huffman table" 错），但 entropy 流完整。注入后多数 baseline JPEG 立即可解。
//
// 返回：
//   - patched: 注入后的字节；nil 表示没必要注入或失败
//   - info: 描述
func InjectStandardDHT(data []byte) (patched []byte, info string) {
	if len(data) < 100 {
		return nil, "数据过短"
	}
	if data[0] != 0xFF || data[1] != 0xD8 {
		return nil, "SOI 缺失"
	}
	sosPos := findSOS(data)
	if sosPos < 0 {
		return nil, "找不到 SOS 段，无法定位插入点"
	}
	if HasDHT(data) {
		return nil, "已含 DHT 段，无需注入"
	}
	dht := BuildStandardDHT()
	out := make([]byte, 0, len(data)+len(dht))
	out = append(out, data[:sosPos]...)
	out = append(out, dht...)
	out = append(out, data[sosPos:]...)
	return out, "已在 SOS 前注入 Annex K 标准 Huffman 表（4 张：DC/AC × luma/chroma）"
}

// DeepRepairJPEG 链式跑多种修复策略，返回任一能 Decode 的修复版本。
//
// 策略顺序（逐步加大改动）：
//   1) 原文件直接 Decode
//   2) RepairJPEG（边界修复 + RST 对齐截尾）
//   3) InjectStandardDHT（缺 DHT 段时）
//   4) RepairJPEG → 再 InjectStandardDHT 组合
//   5) StitchHuffmanState（合成 RST 注入 + 损坏点重同步）—— 终极策略
//
// 返回 (final, true) 仅当某个策略产生的字节通过 image/jpeg.Decode。
// 失败返回 (nil, false)。
//
// 这是给 recovery engine 的"最终手段"接口：所有 baseline 修复路径已无可挽救
// 时再调用这个；输出落盘前调用方应再做一次 hash 校验记录到 manifest。
func DeepRepairJPEG(data []byte) (final []byte, ok bool) {
	// 策略 1：原文件
	if _, err := jpeg.Decode(bytes.NewReader(data)); err == nil {
		return data, true
	}
	// 策略 2：边界修复
	if r, _ := RepairJPEG(data); r != nil {
		if _, err := jpeg.Decode(bytes.NewReader(r)); err == nil {
			return r, true
		}
	}
	// 策略 3：DHT 注入
	if r, _ := InjectStandardDHT(data); r != nil {
		if _, err := jpeg.Decode(bytes.NewReader(r)); err == nil {
			return r, true
		}
		// 策略 4：DHT 注入 + 再边界修复
		if r2, _ := RepairJPEG(r); r2 != nil {
			if _, err := jpeg.Decode(bytes.NewReader(r2)); err == nil {
				return r2, true
			}
		}
	}
	// 策略 5：Huffman state stitching（中段损坏 + 合成 RST 重同步）
	if r, _ := StitchHuffmanState(data); r != nil {
		if _, err := jpeg.Decode(bytes.NewReader(r)); err == nil {
			return r, true
		}
	}
	// 策略 5b：DHT 注入后再 stitching
	if r1, _ := InjectStandardDHT(data); r1 != nil {
		if r, _ := StitchHuffmanState(r1); r != nil {
			if _, err := jpeg.Decode(bytes.NewReader(r)); err == nil {
				return r, true
			}
		}
	}
	return nil, false
}
