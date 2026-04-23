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

// freqDecodeEntry 4-bit tag 对应的 base 和 extra bits
type freqDecodeEntry struct {
	base      uint16
	extraBits uint8
}

// freqDecodeTable Apple lzfse 的 frequency tag table（移植自开源参考）
//
// 索引是前 4 bits；对每个 tag：
//   tag 0..3: 低频率值区（0, 2, 1, 4+extraBits）
//   tag 4..7: 中频率值区（0, 3, 1, 8+extraBits）
//   tag 8..11: 高频率值区（0, 2, 1, 12+extraBits）
//   tag 12..15: 特殊（0, 3, 1, 16+extraBits 其中 15 是"长编码"）
var freqDecodeTable = [16]freqDecodeEntry{
	{base: 0, extraBits: 2}, // tag 0: 0..3
	{base: 2, extraBits: 0}, // tag 1: 2
	{base: 1, extraBits: 0}, // tag 2: 1
	{base: 4, extraBits: 5}, // tag 3: 4..35

	{base: 0, extraBits: 2}, // tag 4: 0..3
	{base: 3, extraBits: 0}, // tag 5: 3
	{base: 1, extraBits: 0}, // tag 6: 1
	{base: 8, extraBits: 8}, // tag 7: 8..263

	{base: 0, extraBits: 2}, // tag 8
	{base: 2, extraBits: 0}, // tag 9
	{base: 1, extraBits: 0}, // tag 10
	{base: 12, extraBits: 14}, // tag 11: 12..16395

	{base: 0, extraBits: 2}, // tag 12
	{base: 3, extraBits: 0}, // tag 13
	{base: 1, extraBits: 0}, // tag 14
	{base: 16, extraBits: 14}, // tag 15: 16..16399
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

// decodeFrequencies 从 bit-packed stream 解出一个 freq 数组。
// totalSymbols = 20 (L) / 20 (M) / 64 (D) / 256 (literal)
// 约束：sum(freq) == numStates（由调用方传入 literalStates / lmdStates）
func decodeFrequencies(stream *bitStreamForward, totalSymbols int, numStates int) ([]int, error) {
	freqs := make([]int, totalSymbols)
	total := 0
	for i := 0; i < totalSymbols; i++ {
		// 读 4-bit tag
		tag, err := stream.readBits(4)
		if err != nil {
			return nil, fmt.Errorf("freq tag for symbol %d: %w", i, err)
		}
		entry := freqDecodeTable[tag]
		freq := int(entry.base)
		if entry.extraBits > 0 {
			extra, err := stream.readBits(entry.extraBits)
			if err != nil {
				return nil, fmt.Errorf("freq extra bits for symbol %d: %w", i, err)
			}
			freq += int(extra)
		}
		freqs[i] = freq
		total += freq
		if total > numStates {
			return nil, fmt.Errorf("freq 累计超限 @symbol %d: total %d > numStates %d",
				i, total, numStates)
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
		return nil, nil, nil, nil, 0, fmt.Errorf("L freqs: %w", err)
	}
	mFreqs, err = decodeFrequencies(stream, 20, lmdStates)
	if err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("M freqs: %w", err)
	}
	dFreqs, err = decodeFrequencies(stream, 64, lmdStates)
	if err != nil {
		return nil, nil, nil, nil, 0, fmt.Errorf("D freqs: %w", err)
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
