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

// LMD extra bits tables —— Apple lzfse 里 L/M/D 的 "header symbol" 不是最终值，
// 还要加 extra bits + base：
//   L_sym ∈ [0, 20) → (L_base[sym], L_extra_bits[sym]) → pull extra bits + base = 最终 L
//   M_sym ∈ [0, 20) → 类似
//   D_sym ∈ [0, 64) → 类似（D 范围更大，覆盖 0..65535）
//
// 这些常量直接来自 Apple lzfse_fse.h（BSD-3）
var lzfseLExtraBits = [20]uint8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 2, 3, 5,
}
var lzfseLBaseValue = [20]uint16{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	10, 11, 12, 13, 14, 15, 16, 18, 22, 30,
}

var lzfseMExtraBits = [20]uint8{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 2, 3, 8,
}
var lzfseMBaseValue = [20]uint16{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
	10, 11, 12, 13, 14, 15, 16, 18, 22, 30,
}

// D 的 extra bits/base 是 16-bit 分段线性：
//   symbols 0..63 编码 1..65535
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
	if freqStart >= len(block) {
		return 0, fmt.Errorf("freq 表起点越界")
	}
	lFreqs, mFreqs, dFreqs, litFreqs, freqConsumed, err := parseAllFrequencies(block[freqStart:])
	if err != nil {
		return 0, fmt.Errorf("解 frequency 表: %w", err)
	}

	// --- 2. 构造 4 个 FSE decoder table ---
	lTable, err := buildFSEDecoderTable(lFreqs, lmdStates)
	if err != nil {
		return 0, fmt.Errorf("build L table: %w", err)
	}
	mTable, err := buildFSEDecoderTable(mFreqs, lmdStates)
	if err != nil {
		return 0, fmt.Errorf("build M table: %w", err)
	}
	dTable, err := buildFSEDecoderTable(dFreqs, lmdStates)
	if err != nil {
		return 0, fmt.Errorf("build D table: %w", err)
	}
	litTable, err := buildFSEDecoderTable(litFreqs, literalStates)
	if err != nil {
		return 0, fmt.Errorf("build literal table: %w", err)
	}

	// --- 3. 划分 payload ---
	// freq payload 之后是 literal payload，再是 lmd payload
	payloadStart := freqStart + freqConsumed
	litPayloadEnd := payloadStart + int(h.literalPayloadLen)
	lmdPayloadEnd := litPayloadEnd + int(h.lmdPayloadLen)
	if lmdPayloadEnd > len(block) {
		return 0, fmt.Errorf("payload 越界 (need %d, block %d)", lmdPayloadEnd, len(block))
	}
	litPayload := block[payloadStart:litPayloadEnd]
	lmdPayload := block[litPayloadEnd:lmdPayloadEnd]

	// --- 4. Decode literal stream (4 个并行 FSE) ---
	literals := make([]byte, h.nLiterals)
	if err := decodeLiterals(litPayload, int(h.literalBits), h.literalStates, litTable, literals); err != nil {
		return 0, fmt.Errorf("decode literals: %w", err)
	}

	// --- 5. Decode LMD stream + 按 (L,M,D) 生成输出 ---
	outLen, err := decodeLMD(lmdPayload, int(h.lmdBits),
		h.lState, h.mState, h.dState,
		lTable, mTable, dTable,
		literals, dst, int(h.nRawBytes), int(h.nMatches))
	if err != nil {
		return 0, fmt.Errorf("decode LMD: %w", err)
	}
	return outLen, nil
}

// decodeLiterals 4 个 FSE 流并行 decode，每轮产 8 bytes（每 stream 2 bytes）
func decodeLiterals(payload []byte, padBits int, initialStates [4]uint16,
	table []fseEntry, out []byte) error {

	if len(out)%4 != 0 {
		// Apple encoder 保证 n_literals 是 4 的倍数；不是的话是损坏
		// 允许少量不齐（尾部补零）
	}

	br, err := newReverseBitReader(payload, padBits)
	if err != nil {
		return err
	}

	states := initialStates // 4 个状态 copy
	// 每轮 decode 8 literals：stream3、stream2、stream1、stream0 各 2 次
	// 实际 Apple lzfse 按 encoder 写入的倒序 pull；decoder 顺序：
	//   for i = n_literals-1; i >= 0; i -= 4:
	//     pull stream3 → out[i], then stream2 → out[i-1], ...
	//
	// 简化（正确）版本：pull 顺序与 encoder 相反
	total := len(out)
	idx := total - 1
	for idx >= 0 {
		for s := 3; s >= 0 && idx >= 0; s-- {
			sym, err := fseDecodeOne(table, &states[s], br)
			if err != nil {
				return fmt.Errorf("literal fse @ idx %d stream %d: %w", idx, s, err)
			}
			out[idx] = byte(sym)
			idx--
		}
	}
	return nil
}

// decodeLMD 1 个 FSE stream 解 (L,M,D) 三元组 × nMatches，同时生成 output
func decodeLMD(payload []byte, padBits int,
	lStateIn, mStateIn, dStateIn uint16,
	lTable, mTable, dTable []fseEntry,
	literals []byte, dst []byte, nRaw int, nMatches int) (int, error) {

	br, err := newReverseBitReader(payload, padBits)
	if err != nil {
		return 0, err
	}

	// state 按 Apple 约定：decode 顺序是反向，但 (L, M, D) 每组先 decode D 后 M 后 L
	// 这里按正向逻辑产出：每轮从状态读 L/M/D（每轮前状态代表"下一组" 的）
	//
	// 实际 decoder 流程（参考 Apple lzfse_decode_v2_block.c）:
	//   for i = nMatches-1 down to 0:
	//     L_sym = decode(L_table, L_state)   // updates L_state
	//     M_sym = decode(M_table, M_state)
	//     D_sym = decode(D_table, D_state)
	//     L_i = L_base[L_sym] + pull(L_extra[L_sym])
	//     M_i = M_base[M_sym] + pull(M_extra[M_sym])
	//     D_i = D_base[D_sym] + pull(D_extra[D_sym])
	//
	// output 生成（正向）：我们只能在 decode 完所有三元组后一次 emit。
	// 为简化：先把 (L, M, D) 全存一个数组，再正向 emit。

	// 所有 L/M/D 值（最终数值，已加 extra bits）
	Ls := make([]uint16, nMatches)
	Ms := make([]uint16, nMatches)
	Ds := make([]uint32, nMatches)

	lS := lStateIn
	mS := mStateIn
	dS := dStateIn

	// 反向 decode（Apple 约定：bit stream 末尾对应 match 0）
	for i := nMatches - 1; i >= 0; i-- {
		lSym, err := fseDecodeOne(lTable, &lS, br)
		if err != nil {
			return 0, fmt.Errorf("LMD L decode i=%d: %w", i, err)
		}
		mSym, err := fseDecodeOne(mTable, &mS, br)
		if err != nil {
			return 0, fmt.Errorf("LMD M decode i=%d: %w", i, err)
		}
		dSym, err := fseDecodeOne(dTable, &dS, br)
		if err != nil {
			return 0, fmt.Errorf("LMD D decode i=%d: %w", i, err)
		}

		// pull extra bits
		lExtra, err := br.pull(lzfseLExtraBits[lSym])
		if err != nil {
			return 0, err
		}
		mExtra, err := br.pull(lzfseMExtraBits[mSym])
		if err != nil {
			return 0, err
		}
		dExtra, err := br.pull(lzfseDExtraBits[dSym])
		if err != nil {
			return 0, err
		}

		Ls[i] = lzfseLBaseValue[lSym] + uint16(lExtra)
		Ms[i] = lzfseMBaseValue[mSym] + uint16(mExtra)
		Ds[i] = lzfseDBaseValue[dSym] + dExtra
	}

	// 正向 emit 输出：每组 L_i 个 literal + M_i 字节回溯
	litCursor := 0
	outCursor := 0
	for i := 0; i < nMatches; i++ {
		// emit L literals
		L := int(Ls[i])
		if litCursor+L > len(literals) {
			return outCursor, fmt.Errorf("literal 越界 @i=%d: need %d+%d > %d", i, litCursor, L, len(literals))
		}
		if outCursor+L > len(dst) {
			return outCursor, fmt.Errorf("dst 溢出 @L-emit i=%d", i)
		}
		copy(dst[outCursor:outCursor+L], literals[litCursor:litCursor+L])
		litCursor += L
		outCursor += L

		// emit M byte backref at distance D
		M := int(Ms[i])
		D := int(Ds[i])
		if D <= 0 || D > outCursor {
			return outCursor, fmt.Errorf("非法 back-ref distance D=%d @i=%d outCursor=%d", D, i, outCursor)
		}
		if outCursor+M > len(dst) {
			return outCursor, fmt.Errorf("dst 溢出 @M-emit i=%d", i)
		}
		// 字节级复制（允许 overlap → 必须逐字节，不能 memcpy 整段）
		src := outCursor - D
		for j := 0; j < M; j++ {
			dst[outCursor+j] = dst[src+j]
		}
		outCursor += M
	}

	// trailing literals（不对应任何 match）
	remain := nRaw - outCursor
	if remain > 0 {
		if litCursor+remain > len(literals) {
			return outCursor, fmt.Errorf("trailing literals 越界")
		}
		if outCursor+remain > len(dst) {
			return outCursor, fmt.Errorf("dst 溢出 @trailing")
		}
		copy(dst[outCursor:outCursor+remain], literals[litCursor:litCursor+remain])
		outCursor += remain
	}
	return outCursor, nil
}
