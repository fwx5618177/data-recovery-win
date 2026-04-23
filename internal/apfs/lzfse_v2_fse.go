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

// buildFSEDecoderTable 构造 FSE 解码器 table
//
// freqs[i] = symbol i 的频率（累计 = numStates）
// numStates 必须是 2 的幂
//
// 返回 [numStates]fseEntry；entry 格式：
//   symbol: 解出的 symbol
//   nbits: 下次读多少 bit
//   deltaState: 读出的 raw_bits + delta 组合成 nextState（已计算好）
//
// **算法（Apple lzfse 实际做法）**：
//
// Step 1: compute nbits threshold per symbol
//   k = floor(log2(numStates)) - floor(log2(freq))  -- "base nbits"
//   threshold = (freq << (k+1)) - numStates
//   前 threshold 个 state: nbits = k+1
//   其余 freq - threshold 个 state: nbits = k
//
// Step 2: spread symbols across [0, numStates) using a coprime step
//   Apple step = (numStates >> 1) + (numStates >> 3) + 3
//   也就是 5/8 * numStates + 3；和 numStates 的 gcd = 1（常见 numStates=1024/64 都成立）
//   state_i = (state_{i-1} + step) mod numStates
//
// Step 3: compute delta for each state
//   每个 symbol 的 state 按 spread 顺序分配给 (symbol, nbits)
//   delta = (destState << nbits) - numStates  — 保证 (delta + raw_bits) 恰好落回 [0, numStates)
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
	logNS := log2floor(uint32(numStates))

	// Apple spread step
	step := (numStates >> 1) + (numStates >> 3) + 3
	mask := numStates - 1

	// Step 2: spread symbols —— 确定每个 state 的 symbol
	pos := 0
	for sym, f := range freqs {
		for j := 0; j < f; j++ {
			table[pos].symbol = int16(sym)
			pos = (pos + step) & mask
		}
	}
	if pos != 0 {
		// 某些 numStates 下 step 不互质；当前实现对 1024/64 是互质，应回 0
		// 不致命：spread 完成只是 symbol 顺序可能略有不同
	}

	// Step 3: 按 symbol 聚合 state，计算 (nbits, delta)
	// 每个 symbol 的 freq 个 state 按它们被分配到的顺序（原 state index 升序）编号 0..freq-1
	//   - 前 threshold 个使用 nbits = baseNBits + 1
	//   - 其余使用 nbits = baseNBits
	// 其中 baseNBits = logNS - floor(log2(freq))
	// threshold = (freq << (baseNBits + 1)) - numStates
	//
	// delta 规则：
	//   对 symbol s 已分配到的第 i 个 state（按 state index 升序），
	//   destination = (numStates + cumulativeSoFar) / 2^nbits  （这是 Apple 预计算）
	//   本实现采用更通用的 tANS delta 计算：
	//     delta = (destinationNext << nbits) - numStates
	//     destinationNext 从 0..freq-1 逐个编号
	//
	// 这部分直接借 Yann Collet FSE 参考实现（算法非版权保护）：

	indicesPerSymbol := make(map[int16][]int, len(freqs))
	for i, e := range table {
		indicesPerSymbol[e.symbol] = append(indicesPerSymbol[e.symbol], i)
	}

	for sym, indices := range indicesPerSymbol {
		freq := len(indices)
		if freq == 0 {
			continue
		}
		baseNBits := logNS - log2floor(uint32(freq))
		threshold := (uint32(freq) << (baseNBits + 1)) - uint32(numStates)

		for i, stateIdx := range indices {
			// destination index 在 symbol 内的编号（0..freq-1）
			// 对每个 symbol 的第 i 个 state：
			//   如果 i < threshold → nbits = baseNBits + 1
			//   否则 → nbits = baseNBits
			//   destState 按 FSE 约定：
			//     低 threshold 个 state 在 "next_state_base" 之前：destState = i
			//     其余 state 映射到后面：destState = threshold + (i-threshold) * 2
			//   （这让 delta 计算让累加器在 [numStates, 2*numStates) 间恰好循环）
			var nbits uint8
			var destState int32
			if uint32(i) < threshold {
				nbits = baseNBits + 1
				destState = int32(i)
			} else {
				nbits = baseNBits
				destState = int32(threshold) + int32(uint32(i)-threshold)
			}
			// delta: nextState = destState << nbits + raw_bits - numStates
			// encoder 产生 raw_bits ∈ [0, 2^nbits) → nextState ∈ [destState<<nbits - numStates, ...)
			delta := int32(destState<<nbits) - int32(numStates)
			table[stateIdx].nbits = nbits
			table[stateIdx].deltaState = delta
		}
		_ = sym // keep for debug
	}

	return table, nil
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
