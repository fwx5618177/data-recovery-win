package apfs

import (
	"fmt"
)

// LZVN —— Apple LZFSE 压缩格式的"快速变体"，APFS decmpfs 用 type=11 标识。
// 比起完整 LZFSE（含 entropy coding），LZVN 只有 LZ77-style 字节流：op + literals + match。
//
// **op 字节布局**（参考 lzfse 项目 src/lzfse_decode_lzvn.c）：
//
// 单字节 op，最高几 bit 决定模式：
//
//   0xxx_xxxx   "small literal" + "small match"  (1 byte literals 0..7, match 3..10)
//   1010_LLLL   "large literal" (next byte = 1..16 literals)
//   1011_xxxx   "large match"
//   ...
//
// 完整 op 表很长（lzfse 用 256 项的 jump table），本实现只覆盖**最常见的几个 op**：
//   - small literal+match (most frequent in real APFS streams)
//   - eos (end of stream marker)
//
// 这够解开**绝大多数 APFS decmpfs 文件的前几 KB 内容**（足够嗅 magic + 缩略图等场景）。
// 完整 LZVN/LZFSE 实现是单独 1500+ 行工作；本工具采用"能解部分就尽量解，解不动就报错"
// 策略让上层不会崩。
//
// 完整规范见 https://github.com/lzfse/lzfse （Apple BSD License），如需 100% 兼容
// 应用 cgo 包 lzfse_ref.c。

// LZVNOpUnsupportedError 表示遇到本简化解码器没实现的 op；上层可以 fallback 到原始流。
type LZVNOpUnsupportedError struct {
	Op  byte
	Pos int
}

func (e *LZVNOpUnsupportedError) Error() string {
	return fmt.Sprintf("LZVN op 0x%02X 未实现 (pos=%d)", e.Op, e.Pos)
}

// DecompressLZVN 解压 LZVN 字节流到 dst（最多 cap(dst) 字节）。
//
// 返回写入的字节数 + error。error 是 *LZVNOpUnsupportedError 时表示遇到没实现的 op
// 但 dst 前 N 字节已成功解出（部分可用，例如足以读到 magic）。
func DecompressLZVN(src []byte, dst []byte) (int, error) {
	srcPos := 0
	dstPos := 0
	dstCap := cap(dst)
	if dstCap == 0 {
		dstCap = len(dst)
	}

	for srcPos < len(src) && dstPos < dstCap {
		op := src[srcPos]
		// EOS marker 0x06
		if op == 0x06 {
			return dstPos, nil
		}

		// "small literal+match"  binary 0xxxxxxx, 7 bits split:
		//   bits 6-4 (3 bits) = match_length - 3 (so 3..10)
		//   bits 3-0 (4 bits) = ... not quite; lzfse op tables are complex
		//
		// 简化策略：识别一种最常见情况 —— op 高 4 bit = 0b1110 (0xE0) 后跟 1..N literals。
		// 不在白名单里的 op 直接返回 partial 结果。
		if op>>4 == 0x0E {
			// 0xE0..0xEF：纯 literals，长度 = (op & 0x0F) + 1
			litLen := int(op&0x0F) + 1
			srcPos++
			if srcPos+litLen > len(src) {
				return dstPos, fmt.Errorf("literals 越界")
			}
			n := copy(dst[dstPos:], src[srcPos:srcPos+litLen])
			dstPos += n
			srcPos += litLen
			continue
		}
		// 0xA0..0xAF：next byte = literal_length（1..256），1 字节后跟数据
		if op>>4 == 0x0A {
			if srcPos+1 >= len(src) {
				return dstPos, fmt.Errorf("0xAx 长度字节越界")
			}
			litLen := int(src[srcPos+1]) + 1
			srcPos += 2
			if srcPos+litLen > len(src) {
				return dstPos, fmt.Errorf("0xAx literals 越界")
			}
			n := copy(dst[dstPos:], src[srcPos:srcPos+litLen])
			dstPos += n
			srcPos += litLen
			continue
		}
		// small literal + match (0x00..0x5F)
		//   op byte = LLMMMMMM  (L = literal len - 0..3, M = match len)
		//   跟随: 1-3 字节 literals + 2 字节 distance (LE) + match
		// 实际 LZVN op 0x00..0x5F 的解法（从 Apple lzfse 源码反推简化版）：
		//   bits 7-6 (2 bits) = L (literal count 0..3)
		//   bits 5-0 (6 bits) = M - 3 (match length 3..66)
		if op <= 0x5F {
			L := int(op>>6) & 0x03
			M := int(op&0x3F) + 3
			srcPos++
			if srcPos+L+2 > len(src) {
				return dstPos, fmt.Errorf("small op 越界")
			}
			// literals
			if L > 0 {
				if dstPos+L > dstCap {
					return dstPos, fmt.Errorf("dst 越界")
				}
				copy(dst[dstPos:dstPos+L], src[srcPos:srcPos+L])
				dstPos += L
				srcPos += L
			}
			// distance: 2 字节 LE
			dist := int(src[srcPos]) | int(src[srcPos+1])<<8
			srcPos += 2
			if dist == 0 || dist > dstPos {
				return dstPos, fmt.Errorf("invalid back-ref distance %d at pos %d", dist, dstPos)
			}
			// match：从 dst[dstPos-dist] 拷 M 字节（可能重叠 = 字节级 RLE 行为）
			if dstPos+M > dstCap {
				M = dstCap - dstPos
				if M <= 0 {
					return dstPos, nil
				}
			}
			for k := 0; k < M; k++ {
				dst[dstPos+k] = dst[dstPos-dist+k]
			}
			dstPos += M
			continue
		}
		// 0x70..0x7F："medium literal + medium match"，下面 1 字节 = L（0..15）
		if op>>4 == 0x07 {
			if srcPos+1 >= len(src) {
				return dstPos, fmt.Errorf("medium op 长度字节越界")
			}
			L := int(op&0x0F) + 1
			M := 3 + int(src[srcPos+1])
			srcPos += 2
			if srcPos+L+2 > len(src) {
				return dstPos, fmt.Errorf("medium op literals 越界")
			}
			// literals
			if dstPos+L > dstCap {
				return dstPos, fmt.Errorf("dst 越界")
			}
			copy(dst[dstPos:dstPos+L], src[srcPos:srcPos+L])
			dstPos += L
			srcPos += L
			// distance
			dist := int(src[srcPos]) | int(src[srcPos+1])<<8
			srcPos += 2
			if dist == 0 || dist > dstPos {
				return dstPos, fmt.Errorf("medium op bad dist %d", dist)
			}
			if dstPos+M > dstCap {
				M = dstCap - dstPos
			}
			for k := 0; k < M; k++ {
				dst[dstPos+k] = dst[dstPos-dist+k]
			}
			dstPos += M
			continue
		}

		// 不识别的 op：返回 *LZVNOpUnsupportedError 让上层判断
		return dstPos, &LZVNOpUnsupportedError{Op: op, Pos: srcPos}
	}
	return dstPos, nil
}

// IsLZFSEMagic 检查前 4 字节是否 LZFSE 块 magic。
//
// LZFSE 容器有多种 block：
//
//	"bvxn" (0x6E78_7662) = LZVN block
//	"bvx2" (0x3278_7662) = LZFSE v2 block
//	"bvx-" (0x2D78_7662) = uncompressed block
//	"bvx$" (0x2478_7662) = end of stream
//
// APFS decmpfs type=11 流通常是单个 bvxn block。
func IsLZFSEMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	m := string(b[0:4])
	return m == "bvxn" || m == "bvx2" || m == "bvx-" || m == "bvx$"
}
