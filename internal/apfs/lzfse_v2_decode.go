package apfs

// LZFSE v2 main decode loop —— 把 header / frequency / FSE table / bit reader 串起来。
//
// Block 流程（Apple lzfse_decode_v2_block.c）:
//   1. header 44 字节（已有 parseV2Header）
//   2. frequency 表（L/M/D/literal 4 张；已有 parseAllFrequencies）
//   3. 构造 4 张 FSE decoder table（L、M、D：nStates=64；literal：nStates=1024）
//   4. literal payload: 4 个并行 FSE stream（每轮 decode 8 literals）
//   5. LMD payload: 1 个 FSE stream decode (L, M, D) 三元组 × n_matches
//
// Block output 构造：
//   for each match i:
//     L_i literals（从 literal buffer 取）
//     M_i 字节回溯复制（距离 D_i）
//   最后剩 (n_raw - sum(L_i + M_i)) 个 trailing literals
//
// 参考：lzfse_decode_v2_block.c (开源 BSD-3)
//
// **重要诚实声明**：
//   本实现没有 Apple 官方测试向量验证。frequency decoder 的 tag table、FSE build 的
//   spread 常数、bit reader 字节序都按开源规范移植。**真实 bvx2 文件可能仍有未覆盖
//   的边界**（encoder padding / compact form / L/M 偏移编码等）。如解码失败会返回错误，
//   上层 lzfse.go 会 fallback 到 macOS compression_tool（100% 可靠的 Apple 官方库）。

import (
	"fmt"
)

// LMD extra bits / base value 表 —— **严格** 移植 Apple `lzfse_internal.h`（BSD-3）。
//
//	L_sym ∈ [0, 20) → L = l_base_value[sym] + pull(l_extra_bits[sym])
//	M_sym ∈ [0, 20) → M = m_base_value[sym] + pull(m_extra_bits[sym])
//	D_sym ∈ [0, 64) → D = d_base_value[sym] + pull(d_extra_bits[sym])
//
// **早期 bug**：L sym 16-19 / M sym 16-19 的 base/extra 与 Apple 不符：
//   L sym 19 早期：base 30, extra 5 → 范围 30..61（错）
//                 Apple：base 60, extra 8 → 范围 60..315
//   M sym 19 早期：base 30, extra 8 → 范围 30..285（错）
//                 Apple：base 312, extra 11 → 范围 312..2359  ← 关键！
//                 9000 字节高度重复输入用 6 个长 match 才合理（每 ~1500 byte）
var lzfseLExtraBits = [20]uint8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8,
}
var lzfseLBaseValue = [20]uint16{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
}

var lzfseMExtraBits = [20]uint8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11,
}
var lzfseMBaseValue = [20]uint16{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312,
}

// D 的 extra bits/base 是 16-bit 分段线性：symbols 0..63 编码 0..229372+(2^15-1)
var lzfseDExtraBits = [64]uint8{
	0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
	4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
	8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
	12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
}
var lzfseDBaseValue = [64]uint32{
	0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52,
	60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892,
	1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332,
	16380, 20476, 24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
}

// decodeV2BlockPureGo 从 bvx2 block bytes 解压到 dst。
// 成功返回实际解出字节数（≤ len(dst)）。
func decodeV2BlockPureGo(block []byte, dst []byte) (int, error) {
	h, err := parseV2Header(block)
	if err != nil {
		return 0, err
	}
	if int(h.nRawBytes) > len(dst) {
		return 0, fmt.Errorf("dst 容量不足 (need %d, got %d)", h.nRawBytes, len(dst))
	}

	// --- 1. 解析 frequency 表 ---
	freqStart := h.freqTableStart
	freqEnd := int(h.headerSize)
	if freqStart >= len(block) || freqEnd > len(block) || freqStart > freqEnd {
		return 0, fmt.Errorf("freq 表区间越界 [%d,%d), block %d", freqStart, freqEnd, len(block))
	}
	// 关键：只把 freq payload (= headerSize - 32 字节) 传给解析器，
	// 不能给整个 block —— 否则 peek/advance 越过 freq 末尾会读到 literal payload 字节，
	// 产生伪 codeword 累加 freq 总和 ≠ numStates。
	lFreqs, mFreqs, dFreqs, litFreqs, freqConsumed, err := parseAllFrequencies(block[freqStart:freqEnd])
	if err != nil {
		return 0, fmt.Errorf("解 frequency 表: %w", err)
	}

	// --- 2. 构造 4 个 FSE decoder table ---
	// 注意每个 FSE 流的 state 数量不同（Apple `LZFSE_ENCODE_*_STATES`）：
	//   L=64, M=64, D=256, literal=1024
	lTable, err := buildFSEDecoderTable(lFreqs, lStates)
	if err != nil {
		return 0, fmt.Errorf("build L table: %w", err)
	}
	mTable, err := buildFSEDecoderTable(mFreqs, mStates)
	if err != nil {
		return 0, fmt.Errorf("build M table: %w", err)
	}
	dTable, err := buildFSEDecoderTable(dFreqs, dStates)
	if err != nil {
		return 0, fmt.Errorf("build D table: %w", err)
	}
	litTable, err := buildFSEDecoderTable(litFreqs, literalStates)
	if err != nil {
		return 0, fmt.Errorf("build literal table: %w", err)
	}

	// --- 3. 划分 payload ---
	// freq payload 完整长度 = headerSize - 32（Apple 定义），所以
	// literal payload 的起点 = headerSize（不是按 freq parser 实际消费字节算）。
	// 这一点容易踩坑：freq decoder 是 bit-stream，结尾可能有 byte-padding bits
	// 不被消费，但 spec 规定 literal payload 紧贴 headerSize 字节边界。
	_ = freqConsumed
	payloadStart := int(h.headerSize)
	litPayloadEnd := payloadStart + int(h.nLiteralPayloadBytes)
	lmdPayloadEnd := litPayloadEnd + int(h.nLMDPayloadBytes)
	if lmdPayloadEnd > len(block) {
		return 0, fmt.Errorf("payload 越界 (need %d, block %d)", lmdPayloadEnd, len(block))
	}

	// --- 4. Decode literal stream (4 个并行 FSE) ---
	// 注意：传整个 block + payload 结束位置；reverse bit reader 会借助 header 字节
	// 作为"无关 garbage" 占据 accum 低位（详见 lzfse_v2_bitreader.go 的"关键陷阱"）
	literals := make([]byte, h.nLiterals)
	if err := decodeLiterals(block, litPayloadEnd, int(h.literalBits),
		h.literalStates, litTable, literals); err != nil {
		return 0, fmt.Errorf("decode literals: %w", err)
	}

	// --- 5. Decode LMD stream + 按 (L,M,D) 生成输出 ---
	outLen, err := decodeLMD(block, lmdPayloadEnd, int(h.lmdBits),
		h.lState, h.mState, h.dState,
		lTable, mTable, dTable,
		literals, dst, int(h.nRawBytes), int(h.nMatches))
	if err != nil {
		return 0, fmt.Errorf("decode LMD: %w", err)
	}
	return outLen, nil
}

// decodeLiterals 4 个并行 FSE 流解码 literal stream
//
// Apple 算法（lzfse_decode_base.c 行 454-481）：
//
//	for i = 0; i < n_literals; i += 4:
//	    literals[i+0] = fse_decode(&state0, table, &in)
//	    literals[i+1] = fse_decode(&state1, table, &in)
//	    literals[i+2] = fse_decode(&state2, table, &in)
//	    literals[i+3] = fse_decode(&state3, table, &in)
//
// 关键：output 是**正向 index 顺序**（i, i+1, ...），但 bit 流是**从末尾反向 pull**。
// FSE 的固有不对称：encoder 倒序产 bit，decoder 反向 pull bit + 正序 emit symbol。
//
// 早期实现把 idx 从末尾倒着填，导致输出顺序颠倒（解出乱字节再被 LMD 复制 → 损坏数据）。
func decodeLiterals(block []byte, payloadEnd int, padBits int, initialStates [4]uint16,
	table []fseEntry, out []byte) error {

	br, err := newReverseBitReader(block, payloadEnd, padBits)
	if err != nil {
		return err
	}

	states := initialStates // 4 个状态 copy
	total := len(out)
	for i := 0; i+3 < total; i += 4 {
		for s := 0; s < 4; s++ {
			sym, err := fseDecodeOne(table, &states[s], br)
			if err != nil {
				return fmt.Errorf("literal fse @ idx %d stream %d: %w", i+s, s, err)
			}
			out[i+s] = byte(sym)
		}
	}
	// Apple 保证 n_literals 是 4 的倍数；尾部不齐留 0。
	return nil
}

// decodeLMD 1 个 FSE stream 解 (L,M,D) 三元组 × nMatches，同时正向 emit output。
//
// Apple 算法（lzfse_decode_base.c lzfse_decode_lmd 行 156-243）：
//
//	D = -1  // illegal init，触发首次 D=0 时报错
//	for i = 0; i < nMatches; i++:
//	    L_sym, L_extra → L value (one combined fse_value_decode pull)
//	    M_sym, M_extra → M value
//	    new_D = D_value
//	    D = new_D ? new_D : D    ← rep-distance: D=0 means "reuse previous D"
//	    emit L literals from `lit` cursor
//	    emit M bytes back-ref at distance D
//
// 关键修正（vs 旧实现）：
//   1. 正向迭代 i = 0..nMatches-1（旧版反向 → match 顺序颠倒，output 错位）
//   2. 三元组 pull 顺序：(L state + L extra) (M state + M extra) (D state + D extra)
//      —— Apple 把每对 state+extra 放一个 fse_value_decode 调用里。我们拆成两个 pull
//      但顺序必须匹配。旧版 L state → M state → D state → L extra → M extra → D extra
//      错乱了 bit 流。
//   3. D=0 → 复用 prev D（rep-distance optimization）。Apple 在编码端把高频出现的
//      "重复上一次距离" 编码为单 symbol D=0 节省 bits。
func decodeLMD(block []byte, payloadEnd int, padBits int,
	lStateIn, mStateIn, dStateIn uint16,
	lTable, mTable, dTable []fseEntry,
	literals []byte, dst []byte, nRaw int, nMatches int) (int, error) {

	br, err := newReverseBitReader(block, payloadEnd, padBits)
	if err != nil {
		return 0, err
	}

	lS := lStateIn
	mS := mStateIn
	dS := dStateIn

	litCursor := 0
	outCursor := 0
	D := uint32(0) // rep-distance，第一次 D=0 是非法（Apple 用 -1 init）

	for i := 0; i < nMatches; i++ {
		// L: state + extra
		lSym, err := fseDecodeOne(lTable, &lS, br)
		if err != nil {
			return outCursor, fmt.Errorf("LMD L state i=%d: %w", i, err)
		}
		lExtra, err := br.pull(lzfseLExtraBits[lSym])
		if err != nil {
			return outCursor, fmt.Errorf("LMD L extra i=%d: %w", i, err)
		}
		L := uint32(lzfseLBaseValue[lSym]) + lExtra

		// M: state + extra
		mSym, err := fseDecodeOne(mTable, &mS, br)
		if err != nil {
			return outCursor, fmt.Errorf("LMD M state i=%d: %w", i, err)
		}
		mExtra, err := br.pull(lzfseMExtraBits[mSym])
		if err != nil {
			return outCursor, fmt.Errorf("LMD M extra i=%d: %w", i, err)
		}
		M := uint32(lzfseMBaseValue[mSym]) + mExtra

		// D: state + extra；D=0 → 复用 prev D
		dSym, err := fseDecodeOne(dTable, &dS, br)
		if err != nil {
			return outCursor, fmt.Errorf("LMD D state i=%d: %w", i, err)
		}
		dExtra, err := br.pull(lzfseDExtraBits[dSym])
		if err != nil {
			return outCursor, fmt.Errorf("LMD D extra i=%d: %w", i, err)
		}
		newD := lzfseDBaseValue[dSym] + dExtra
		if newD != 0 {
			D = newD
		}

		// emit L literals
		if litCursor+int(L) > len(literals) {
			return outCursor, fmt.Errorf("literal 越界 @i=%d: cursor %d + L %d > total %d",
				i, litCursor, L, len(literals))
		}
		if outCursor+int(L) > len(dst) {
			return outCursor, fmt.Errorf("dst 溢出 @L-emit i=%d", i)
		}
		copy(dst[outCursor:outCursor+int(L)], literals[litCursor:litCursor+int(L)])
		litCursor += int(L)
		outCursor += int(L)

		// emit M-byte back-ref at distance D
		if D == 0 || int(D) > outCursor {
			return outCursor, fmt.Errorf("非法 back-ref distance D=%d @i=%d outCursor=%d (newD=%d)",
				D, i, outCursor, newD)
		}
		if outCursor+int(M) > len(dst) {
			return outCursor, fmt.Errorf("dst 溢出 @M-emit i=%d (need %d+%d, dst %d)",
				i, outCursor, M, len(dst))
		}
		src := outCursor - int(D)
		for j := uint32(0); j < M; j++ {
			dst[outCursor+int(j)] = dst[src+int(j)]
		}
		outCursor += int(M)
	}

	// trailing literals（最后一组 match 之后的剩余 literal，不对应任何 back-ref）
	remain := nRaw - outCursor
	if remain > 0 {
		if litCursor+remain > len(literals) {
			return outCursor, fmt.Errorf("trailing literals 越界 (need %d+%d, total %d)",
				litCursor, remain, len(literals))
		}
		if outCursor+remain > len(dst) {
			return outCursor, fmt.Errorf("dst 溢出 @trailing (need %d+%d, dst %d)",
				outCursor, remain, len(dst))
		}
		copy(dst[outCursor:outCursor+remain], literals[litCursor:litCursor+remain])
		outCursor += remain
	}
	return outCursor, nil
}
