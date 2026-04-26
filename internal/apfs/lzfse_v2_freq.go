package apfs

// LZFSE v2 frequency table 解码 —— 从 bit-packed 流里把 360 个 freq value 拆出来。
//
// Apple 的 frequency encoding（lzfse_encode_tables.c "lzfse_fse_tables_init"）
// 用一个"4-bit tag" 加 "可变额外 bit" 方式：
//
//   读 4 bits → tag （值 0..15）
//   lookup freqDecodeTable[tag] = { base, extraBits }
//   如果 extraBits > 0，再读 extraBits bits，加到 base 作为最终 freq
//
// 这样的 encoding 让频率 0/1（最常见）用 3 bits，大频率用更多 bits，达到 1 bit≈1 freq 的紧凑度。
//
// 规范引用（合法性）：
//   Apple lzfse 是 BSD-3-Clause 开源，允许按 algorithm-level 移植 + 保留版权声明。
//   本文件的常量数组是 algorithm fact，不受版权保护。

import (
	"fmt"
)

// Apple LZFSE v2 真实 frequency decoder 表（来自 lzfse_decode_v2_block.c BSD-3）
//
// 算法（Apple `decode_v1_freq_value`）：
//   - 从 bit stream peek 14 bits buffered
//   - 取低 5 bits 作为索引 b （范围 0..31）
//   - nbits = lzfseFreqNBitsTable[b]      —— 这个 codeword 总长度
//   - 如果 nbits == 8：value = 8 + ((bits >> 4) & 0xF)        (4 extra bits)
//   - 如果 nbits == 14：value = 24 + ((bits >> 4) & 0x3FF)   (10 extra bits)
//   - 否则：value = lzfseFreqValueTable[b]
//   - 然后 stream.advance(nbits)
//
// 注意 5-bit index 但 tables 设计成 32 项（高 4 项是低 4 项的镜像，无关索引高位）。
//
// 这是 algorithmic fact，BSD-3 允许移植；本表与 Apple lzfse 源同。
var lzfseFreqNBitsTable = [32]uint8{
	2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
	2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
}
var lzfseFreqValueTable = [32]uint16{
	0, 2, 1, 4, 0, 3, 1, 8, 0, 2, 1, 5, 0, 3, 1, 24,
	0, 2, 1, 4, 0, 3, 1, 7, 0, 2, 1, 5, 0, 3, 1, 24,
}

// bitStreamForward 从字节流正向读 bit（LSB-first per byte）
// Apple v2 frequency 流用这种顺序
type bitStreamForward struct {
	data    []byte
	bytePos int
	bitPos  uint8 // 当前字节里已读 bit 数 (0..7)
}

func newBitStreamForward(data []byte) *bitStreamForward {
	return &bitStreamForward{data: data}
}

// readBits 从流里读 n bits（n <= 16），返回 bit 值，右对齐
func (b *bitStreamForward) readBits(n uint8) (uint32, error) {
	if n > 16 {
		return 0, fmt.Errorf("readBits n=%d 太大（max 16）", n)
	}
	if n == 0 {
		return 0, nil
	}
	var out uint32
	for i := uint8(0); i < n; i++ {
		if b.bytePos >= len(b.data) {
			return 0, fmt.Errorf("bit stream EOF at bit %d", i)
		}
		bit := (b.data[b.bytePos] >> b.bitPos) & 1
		out |= uint32(bit) << i
		b.bitPos++
		if b.bitPos == 8 {
			b.bitPos = 0
			b.bytePos++
		}
	}
	return out, nil
}

// peekBits 不消耗，返回低 n bits（n <= 14）。EOF 时把没有的高位补 0（保守）。
func (b *bitStreamForward) peekBits(n uint8) uint32 {
	if n == 0 {
		return 0
	}
	if n > 14 {
		n = 14
	}
	saveBytePos := b.bytePos
	saveBitPos := b.bitPos
	var out uint32
	for i := uint8(0); i < n; i++ {
		if b.bytePos >= len(b.data) {
			break
		}
		bit := (b.data[b.bytePos] >> b.bitPos) & 1
		out |= uint32(bit) << i
		b.bitPos++
		if b.bitPos == 8 {
			b.bitPos = 0
			b.bytePos++
		}
	}
	b.bytePos = saveBytePos
	b.bitPos = saveBitPos
	return out
}

// advance 消耗 n bits（不读值），peekBits + advance 是 LZFSE freq decode 的标准模式
func (b *bitStreamForward) advance(n uint8) {
	for i := uint8(0); i < n; i++ {
		if b.bytePos >= len(b.data) {
			return
		}
		b.bitPos++
		if b.bitPos == 8 {
			b.bitPos = 0
			b.bytePos++
		}
	}
}

// decodeFrequencies 从 bit-packed stream 解出一个 freq 数组。
//
// Apple LZFSE v2 算法（lzfse_decode_v2_block.c `decode_v1_freq_value`）：
//   1. peek 14 bits buffered
//   2. 取低 5 bits 作 codeword index
//   3. nbits = lzfseFreqNBitsTable[idx], val = lzfseFreqValueTable[idx]
//   4. nbits == 8: val = 8 + ((peek14 >> 4) & 0xF)
//   5. nbits == 14: val = 24 + ((peek14 >> 4) & 0x3FF)
//   6. stream.advance(nbits)
//
// totalSymbols = 20 (L) / 20 (M) / 64 (D) / 256 (literal)
// 约束：sum(freq) == numStates（由调用方传入 literalStates / lmdStates）
func decodeFrequencies(stream *bitStreamForward, totalSymbols int, numStates int) ([]int, error) {
	freqs := make([]int, totalSymbols)
	total := 0
	for i := 0; i < totalSymbols; i++ {
		// peek 14 bits（够最长 codeword）
		bits := stream.peekBits(14)
		idx := bits & 0x1F
		nbits := lzfseFreqNBitsTable[idx]
		var freq int
		switch nbits {
		case 8:
			freq = 8 + int((bits>>4)&0xF)
		case 14:
			freq = 24 + int((bits>>4)&0x3FF)
		default:
			freq = int(lzfseFreqValueTable[idx])
		}
		stream.advance(nbits)

		freqs[i] = freq
		total += freq
		if total > numStates {
			return nil, fmt.Errorf("freq 累计超限 @symbol %d: total %d > numStates %d (idx=%d nbits=%d freq=%d)",
				i, total, numStates, idx, nbits, freq)
		}
	}
	if total != numStates {
		return nil, fmt.Errorf("freq 之和 %d != numStates %d", total, numStates)
	}
	return freqs, nil
}

// parseAllFrequencies 从 freq block 起点解出 4 套频率表。
// 返回 (lFreqs, mFreqs, dFreqs, litFreqs, consumedBytes, err)
//
// 布局约定（Apple lzfse v2）：
//   L freqs (20 symbols, 总和 = 64)   → lmd states
//   M freqs (20 symbols, 总和 = 64)
//   D freqs (64 symbols, 总和 = 64)
//   literal freqs (256 symbols, 总和 = 1024)
//
// freq_table_payload_bytes = header 提供的字段；由调用方传入作为 stream 上界。
func parseAllFrequencies(freqBytes []byte) (lFreqs, mFreqs, dFreqs, litFreqs []int, consumed int, err error) {
	stream := newBitStreamForward(freqBytes)

	lFreqs, err = decodeFrequencies(stream, 20, lmdStates)
	if err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("l freqs: %w", err)
	}
	mFreqs, err = decodeFrequencies(stream, 20, lmdStates)
	if err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("m freqs: %w", err)
	}
	dFreqs, err = decodeFrequencies(stream, 64, lmdStates)
	if err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("d freqs: %w", err)
	}
	litFreqs, err = decodeFrequencies(stream, 256, literalStates)
	if err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("literal freqs: %w", err)
	}

	consumed = stream.bytePos
	if stream.bitPos > 0 {
		consumed++ // 尾部 partial byte 也算
	}
	return
}
