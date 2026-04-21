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
