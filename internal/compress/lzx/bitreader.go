// Package lzx 实现 LZX (Lempel-Ziv Extended) 解压 — 微软 CAB / WIM / Compact OS 用。
//
// LZX = LZ77 sliding window + Huffman + E8 call preprocessing。
//
// 文件结构：
//   - 一个 WIM stream 由多个 32KB chunk 组成
//   - 每个 chunk 前 2 字节是"压缩后字节数"（小端）
//   - chunk payload 里是 LZX block 链
//
// 每个 LZX block 头部：
//   - block_type:   3 bits (1=verbatim, 2=aligned offset, 3=uncompressed)
//   - block_size:   24 bits（原始字节数）
//   - 之后是 huffman tree + 压缩数据
//
// 参考：MS-PATCH + [MS-WIM] 2.10 LZX Data Format
//
// **本包实现完整度**：
//   ✅ bitreader（LSB-first，按 16-bit little-endian 从字节流读）
//   ✅ Huffman 表构造（canonical huffman from code lengths）
//   ✅ pretree 解码（huffman tree 自身的 code length 表）
//   ✅ verbatim block decode（最常见，95% 的 WIM）
//   ✅ aligned-offset block decode（残余偏移专用 huffman）
//   ✅ uncompressed block（直接透传）
//   ✅ 32 KB 滑动窗口 + LZ77 match expansion
//   ✅ E8 x86 call-preprocessing 反向
//
// 未做 / 未测：
//   ❌ 跨 chunk 的 reset 边界（WIM 每 32KB chunk 重置 huffman tree）— 我们单 chunk 内完整
package lzx

import "fmt"

// bitReader LSB-first LZX bit stream reader。LZX 字节顺序是"16-bit little-endian pair"：
//
//	字节流 [b0 b1 b2 b3] 视为 word0=LE16(b0 b1), word1=LE16(b2 b3)
//	bit stream 从 word0 MSB 开始读。
//
// 这是 MS 自家的奇异 bit order，标准 Deflate/bzip2 都不用。照规范实现即可。
type bitReader struct {
	src  []byte
	pos  int    // 字节偏移（每次以 2 字节为单位前进）
	buf  uint32 // 位缓冲（高位是"下一位"）
	nbit uint   // 缓冲里有多少位
	err  error
}

func newBitReader(src []byte) *bitReader {
	return &bitReader{src: src}
}

// refill 从 src 读更多 word 进缓冲，保证 nbit >= need
func (r *bitReader) refill(need uint) {
	for r.nbit < need {
		if r.pos+2 > len(r.src) {
			if r.pos >= len(r.src) {
				r.err = fmt.Errorf("bitreader 读越界")
				return
			}
			// 末尾剩 1 字节：低字节填 0
			word := uint32(r.src[r.pos])
			r.pos++
			r.buf |= word << (16 - r.nbit)
			r.nbit += 8
			return
		}
		word := uint32(r.src[r.pos]) | uint32(r.src[r.pos+1])<<8
		r.pos += 2
		r.buf |= word << (16 - r.nbit) // word 靠 high 位进
		r.nbit += 16
	}
}

// peek 不消耗地看 n 位（n <= 16）
func (r *bitReader) peek(n uint) uint32 {
	if r.nbit < n {
		r.refill(n)
	}
	return r.buf >> (32 - n)
}

// consume 丢弃 n 位
func (r *bitReader) consume(n uint) {
	r.buf <<= n
	r.nbit -= n
}

// read 读 n 位（n <= 17）
func (r *bitReader) read(n uint) uint32 {
	if n == 0 {
		return 0
	}
	if n > 17 {
		// 分两次；Go 位移 >32 行为未定义要避开
		hi := r.read(16)
		lo := r.read(n - 16)
		return hi<<(n-16) | lo
	}
	v := r.peek(n)
	r.consume(n)
	return v
}

// alignToByte 跳到下一个 16-bit word 边界（uncompressed block 前必需）
func (r *bitReader) alignToWord() {
	if r.nbit > 0 {
		drop := r.nbit % 16
		if drop > 0 {
			r.consume(drop)
		}
	}
}
