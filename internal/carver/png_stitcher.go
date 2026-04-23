package carver

// PNG chunk stitcher —— 对被碎片化的 PNG 尝试"按 chunk 重组"。
//
// PNG 文件结构（RFC 2083）:
//   signature (8 bytes: 89 50 4E 47 0D 0A 1A 0A)
//   chunk {length:4 BE, type:4 ASCII, data:length, crc32:4}
//   ... repeat ...
//   IEND chunk (terminator)
//
// 每个 chunk 有**独立 CRC32**（覆盖 type + data），这让"拼接正确性"可被数学验证 ——
// 随机拼错两个片段 CRC 匹配概率 1/2^32 ≈ 0.
//
// 碎片化场景：
//   文件系统把 PNG 的 data run 拆成多段不连续的 disk extent，标准 carver 从 IHDR
//   往后顺序读会在断点处读到垃圾字节（其他文件内容或空闲区）。
//
// 重组策略：
//   1. 从 IHDR（必为第一个 chunk）开始解析 chunk 链
//   2. 每读一个 chunk header，用其 length 预计算下一个 chunk 的 CRC offset
//   3. 验算 CRC：匹配 → 合法 chunk，继续；不匹配 → 断点
//   4. 断点后在"后续合理范围"（默认 64MB）里扫所有 PNG chunk type magic：
//      IDAT / PLTE / tRNS / zTXt / tEXt / iTXt / pHYs / IEND
//   5. 对每个候选位置倒推其 chunk header，验 CRC → 确认是合法 chunk 中段
//   6. 把断点前的"已验证"和断点后的"匹配上的"拼起来，继续第 3 步
//   7. 命中 IEND 结束；CRC 全通过 = 高置信度重组
//
// 覆盖范围：
//   ✅ 单次断点 + 合理 scatter（常见文件系统碎片）
//   ✅ 全部 critical chunk（IHDR/PLTE/IDAT/IEND）按 CRC 验证
//   ❌ 每 IDAT 内部的 zlib stream 的碎片化（需要 zlib decompress 验证，可能后续版本）
//   ❌ 超过 MaxSearchWindow 的极端分散（工作目录外）

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"data-recovery/internal/disk"
)

// PNGStitchResult 重组输出
type PNGStitchResult struct {
	Data          []byte  // 重组后的 PNG 字节流（含 signature + all chunks + IEND）
	CRCsVerified  int     // 通过 CRC 校验的 chunk 数
	FragmentsHit  int     // 经历多少次断点跳转（0 = 完整连续）
	ConfidenceHex float32 // 0..1
	Notes         string
}

// PNGStitcher 配置 + reader
type PNGStitcher struct {
	Reader          disk.DiskReader
	MaxSearchWindow int64 // 断点后搜索的最大窗口（字节），默认 64MB
	MaxOutputBytes  int64 // 重组 PNG 最大大小（防意外爆内存），默认 64MB
}

// NewPNGStitcher 默认配置的 stitcher
func NewPNGStitcher(r disk.DiskReader) *PNGStitcher {
	return &PNGStitcher{
		Reader:          r,
		MaxSearchWindow: 64 * 1024 * 1024,
		MaxOutputBytes:  64 * 1024 * 1024,
	}
}

var pngSignature = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

// PNG chunk type 4cc → 是否 critical（IHDR/PLTE/IDAT/IEND 是 critical；大写首字母是 critical 规则）
var pngCriticalTypes = map[string]bool{
	"IHDR": true, "PLTE": true, "IDAT": true, "IEND": true,
}

// 合法 chunk type 清单（白名单，过滤随机 4 字节噪音）
var pngValidTypes = map[string]bool{
	"IHDR": true, "PLTE": true, "IDAT": true, "IEND": true,
	"tRNS": true, "cHRM": true, "gAMA": true, "iCCP": true,
	"sBIT": true, "sRGB": true, "tEXt": true, "zTXt": true,
	"iTXt": true, "bKGD": true, "hIST": true, "pHYs": true,
	"sPLT": true, "tIME": true, "acTL": true, "fcTL": true,
	"fdAT": true, // APNG
}

// Stitch 从 pngStart 开始尝试重组 PNG。pngStart 必须是 PNG signature 的字节位置。
func (s *PNGStitcher) Stitch(pngStart int64) (*PNGStitchResult, error) {
	// 验签名
	sig := make([]byte, 8)
	n, err := s.Reader.ReadAt(sig, pngStart)
	if err != nil || n < 8 {
		return nil, fmt.Errorf("读 PNG 签名: %w", err)
	}
	for i, b := range pngSignature {
		if sig[i] != b {
			return nil, fmt.Errorf("不是 PNG 签名 @%d", pngStart)
		}
	}

	out := make([]byte, 0, 1024*1024)
	out = append(out, pngSignature...)

	pos := pngStart + 8 // 下一个 chunk header 起点
	result := &PNGStitchResult{}

	// 主循环：读 chunk → 验 CRC → 追加 → 继续
	for {
		if int64(len(out)) > s.MaxOutputBytes {
			return nil, fmt.Errorf("PNG 重组超过 %d 字节上限", s.MaxOutputBytes)
		}

		header := make([]byte, 8)
		n, err := s.Reader.ReadAt(header, pos)
		if err != nil || n < 8 {
			return nil, fmt.Errorf("读 chunk header @%d: %w", pos, err)
		}
		length := binary.BigEndian.Uint32(header[0:4])
		ctype := string(header[4:8])

		// 先验 type 合法性 —— 命中断点
		if !pngValidTypes[ctype] {
			if s.MaxSearchWindow <= 0 {
				return nil, fmt.Errorf("chunk type %q 不合法 @%d（断点）", ctype, pos)
			}
			nextPos, nextHeader, nextLen, nextType, found := s.searchNextChunk(pos, s.MaxSearchWindow)
			if !found {
				return nil, fmt.Errorf("断点后 %d 字节内未找到合法 chunk", s.MaxSearchWindow)
			}
			result.FragmentsHit++
			pos = nextPos
			header = nextHeader
			length = nextLen
			ctype = nextType
		}

		// length 上限防御（单 chunk 最大 2^31 按规范；> 128MB 现实中几乎不可能）
		if length > 128*1024*1024 {
			return nil, fmt.Errorf("chunk %s length %d 异常大", ctype, length)
		}

		// 读 data + crc
		dataAndCRC := make([]byte, int(length)+4)
		dataStart := pos + 8
		n2, _ := s.Reader.ReadAt(dataAndCRC, dataStart)
		if n2 < int(length)+4 {
			return nil, fmt.Errorf("chunk %s data 读不完整（读到 %d / 需 %d）", ctype, n2, int(length)+4)
		}
		data := dataAndCRC[:length]
		storedCRC := binary.BigEndian.Uint32(dataAndCRC[length : length+4])

		// CRC32 覆盖 type + data
		calc := crc32.NewIEEE()
		calc.Write(header[4:8])
		calc.Write(data)
		if calc.Sum32() != storedCRC {
			// 尝试在合理窗口内搜索下一个合法 chunk（chunk data 的一部分也被打断了）
			if s.MaxSearchWindow <= 0 {
				return nil, fmt.Errorf("chunk %s CRC 不匹配 @%d", ctype, pos)
			}
			nextPos, nextHeader, nextLen, nextType, found := s.searchNextChunk(pos+8, s.MaxSearchWindow)
			if !found {
				return nil, fmt.Errorf("CRC 失败后搜不到下一个合法 chunk")
			}
			result.FragmentsHit++
			pos = nextPos
			header = nextHeader
			_ = nextLen
			_ = nextType
			continue // 重试新 pos
		}

		// CRC 通过 → 把整个 chunk (header + data + crc) 追加到 output
		out = append(out, header...)
		out = append(out, dataAndCRC...)
		result.CRCsVerified++

		if ctype == "IEND" {
			break
		}
		pos = dataStart + int64(length) + 4
	}

	result.Data = out
	if result.FragmentsHit == 0 {
		result.ConfidenceHex = 1.0
		result.Notes = "连续无碎片，所有 CRC 通过"
	} else {
		result.ConfidenceHex = 0.9 // 即使有跳转，CRC 全过已是高置信
		result.Notes = fmt.Sprintf("经历 %d 次 chunk 跳转，所有 %d 个 chunk CRC 通过", result.FragmentsHit, result.CRCsVerified)
	}
	return result, nil
}

// searchNextChunk 在 [start, start+window) 范围找第一个"合法 chunk"：
// 它的 type 是 pngValidTypes 之一 + CRC 匹配。
// 返回 chunk header 位置（即 length 字段起点）。
func (s *PNGStitcher) searchNextChunk(start, window int64) (int64, []byte, uint32, string, bool) {
	if window > s.MaxSearchWindow {
		window = s.MaxSearchWindow
	}
	// 以 512 字节步长扫（PNG chunk 没强制对齐，但文件系统 block 多数 512/4K；
	// 更细步长代价过高）
	const step int64 = 512
	buf := make([]byte, step+8)
	for probe := start; probe < start+window; probe += step {
		n, _ := s.Reader.ReadAt(buf, probe)
		if n < 8 {
			continue
		}
		// 在这 512+8 字节里逐字节找候选 type
		for i := 0; i+8 <= n; i++ {
			ctype := string(buf[i+4 : i+8])
			if !pngValidTypes[ctype] {
				continue
			}
			length := binary.BigEndian.Uint32(buf[i : i+4])
			if length > 128*1024*1024 {
				continue
			}
			// 读该 chunk 的 data + crc 验证 CRC
			candidatePos := probe + int64(i)
			body := make([]byte, int(length)+4)
			m, _ := s.Reader.ReadAt(body, candidatePos+8)
			if m < int(length)+4 {
				continue
			}
			calc := crc32.NewIEEE()
			calc.Write([]byte(ctype))
			calc.Write(body[:length])
			if calc.Sum32() == binary.BigEndian.Uint32(body[length:length+4]) {
				hdrCopy := make([]byte, 8)
				copy(hdrCopy, buf[i:i+8])
				return candidatePos, hdrCopy, length, ctype, true
			}
		}
	}
	return 0, nil, 0, "", false
}
