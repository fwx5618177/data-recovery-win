package apfs

// LZFSE v2 FSE (Finite State Entropy / tANS) decoder table build + state transition
//
// FSE 是 Yann Collet 设计的"对称压缩数值"（tANS / table ANS）的一种 engineering 实现。
// 相对 Huffman：
//   - 更靠近 Shannon 熵下界（常见数据压缩率提升 5-10%）
//   - 用 state-based 转移表（256-4096 state），每个 state 有 {symbol, nbits, delta}
//   - 解码速度比 arithmetic coding 快（无除法）
//
// Apple lzfse v2 用两种 FSE table：
//   literal: 1024 states (accuracy log = 10)
//   LMD:      64 states (accuracy log = 6)
//
// decode 一步的原型：
//     entry = table[state]
//     emit entry.symbol
//     raw_bits = pull_bits(bitstream, entry.nbits)
//     state = entry.delta + raw_bits   （delta 在 build 阶段已预算好，保证 state 在 [0, numStates)）
//
// table build 的核心：对每个 symbol s（频率 freq[s]），在 [0, numStates) 里分配 freq[s]
// 个 state，使得每个 state 的 (nbits, delta) 满足 state 转移平滑。
//
// 参考：Apple lzfse_fse.c fse_init_decoder_table()；Yann Collet FSE paper。

import (
	"fmt"
)

// buildFSEDecoderTable 构造 FSE 解码器 table —— **严格** 移植 Apple
// lzfse_fse.c 的 fse_init_decoder_table（BSD-3）。
//
// freqs[i] = symbol i 的频率（累计 = numStates）
// numStates 必须是 2 的幂
//
// 关键算法（Apple 不用 Yann Collet 的 spread 函数！）：
//
//	for each symbol i with freq f != 0:
//	    k = clz(f) - clz(numStates)    // 满足 N <= (f<<k) < 2*N
//	    j0 = (2*N >> k) - f
//	    // **states 按 symbol 顺序连续分配**（不 spread）
//	    for j = 0..f-1:
//	        if j < j0:
//	            entry.k     = k
//	            entry.delta = ((f+j) << k) - N
//	        else:
//	            entry.k     = k - 1
//	            entry.delta = (j - j0) << (k - 1)
//	        *t++ = entry
//
// 早期实现错用 Yann Collet 的 spread 函数 + 不同 delta 计算 → encoder/decoder
// state 转移不一致 → L/M/D 解出错值。Apple 的 encoder 也按这个布局产 state，
// decoder 必须严格匹配。
func buildFSEDecoderTable(freqs []int, numStates int) ([]fseEntry, error) {
	if numStates == 0 || (numStates&(numStates-1)) != 0 {
		return nil, fmt.Errorf("numStates 必须是 2 的幂: %d", numStates)
	}
	total := 0
	for _, f := range freqs {
		if f < 0 {
			return nil, fmt.Errorf("负 frequency")
		}
		total += f
	}
	if total != numStates {
		return nil, fmt.Errorf("freq 之和 %d != numStates %d", total, numStates)
	}

	table := make([]fseEntry, numStates)
	nClzNumStates := clz32(uint32(numStates))

	pos := 0
	for sym, f := range freqs {
		if f == 0 {
			continue
		}
		k := int(clz32(uint32(f))) - int(nClzNumStates) // shift: N <= (f<<k) < 2*N
		j0 := ((2 * numStates) >> uint(k)) - f
		for j := 0; j < f; j++ {
			var entry fseEntry
			entry.symbol = int16(sym)
			if j < j0 {
				entry.nbits = uint8(k)
				entry.deltaState = int32(((f + j) << uint(k)) - numStates)
			} else {
				entry.nbits = uint8(k - 1)
				entry.deltaState = int32((j - j0) << uint(k-1))
			}
			table[pos] = entry
			pos++
		}
	}
	if pos != numStates {
		return nil, fmt.Errorf("table init: pos=%d ≠ numStates=%d", pos, numStates)
	}

	return table, nil
}

// clz32 count leading zeros for uint32（用 32-bit 等价 Apple `__builtin_clz`）
func clz32(x uint32) uint8 {
	if x == 0 {
		return 32
	}
	n := uint8(0)
	for (x & 0x80000000) == 0 {
		x <<= 1
		n++
	}
	return n
}

// fseDecodeOne 从 bit stream 解码一个 symbol；state 原地更新
func fseDecodeOne(table []fseEntry, state *uint16, br *reverseBitReader) (int16, error) {
	entry := table[*state]
	sym := entry.symbol
	var bits uint32
	var err error
	if entry.nbits > 0 {
		bits, err = br.pull(entry.nbits)
		if err != nil {
			return 0, fmt.Errorf("fseDecodeOne pull: %w", err)
		}
	}
	next := int32(bits) + entry.deltaState
	if next < 0 {
		next = 0 // 损坏流的兜底；真实情况不该发生
	}
	*state = uint16(next)
	return sym, nil
}
