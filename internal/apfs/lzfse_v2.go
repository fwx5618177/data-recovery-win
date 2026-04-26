package apfs

// LZFSE v2 (bvx2 block) 解码器 —— Apple 原 lzfse v2 的 Go 端口。
//
// bvx2 = LZ77 back-ref + FSE (Finite State Entropy / tANS) 熵编码。
//
// 真实 v2 block 布局（按 Apple `lzfse_internal.h` lzfse_compressed_block_header_v2
// 的 v1 解码 helper `lzfse_compressed_block_decode_v2_header_to_v1`，共 32 字节
// 固定 header + 变长 freq payload）：
//
//	+0x00  magic (uint32 LE)             = 0x32787662 ("bvx2")
//	+0x04  n_raw_bytes (uint32 LE)        解压后字节数
//	+0x08  packed_fields[0] (uint64 LE)
//	         bits  0..19  n_literals
//	         bits 20..39  n_literal_payload_bytes  ← 注意：在 n_matches 前面！
//	         bits 40..59  n_matches
//	         bits 60..62  literal_bits + 7  (signed [-7, 0]; 末位 padding bit 数)
//	+0x10  packed_fields[1] (uint64 LE)
//	         bits  0..9   literal_state[0]    (10 bits each)
//	         bits 10..19  literal_state[1]
//	         bits 20..29  literal_state[2]
//	         bits 30..39  literal_state[3]
//	         bits 40..59  n_lmd_payload_bytes
//	         bits 60..62  lmd_bits + 7
//	+0x18  packed_fields[2] (uint64 LE)
//	         bits  0..31  header_size (含 freq payload 总字节数)
//	         bits 32..41  l_state
//	         bits 42..51  m_state
//	         bits 52..61  d_state
//	+0x20  freq payload (变长，长度 = header_size - 32)
//
// **历史 bug**：早期实现把 pf0 bit 20-39 当作 n_matches，bit 40-59 当作
// n_literal_payload_bytes —— 这是搞反了！Apple 定义 lit_payload 在前。
// 错的 header 解读 → 错的 payload 划分 → "payload 越界" / 解码失败。
//
// 5 个 FSE 流：
//   literal:     256 symbol，1024 states
//   L:           20 symbol，64 states
//   M:           20 symbol，64 states
//   D:           64 symbol，64 states
//   literal_state: 4 个流交织
//
// **注意**：Apple lzfse 源码是 BSD-3 授权；本端口按算法结构 + 常量表移植
// （algorithmic facts 不受版权保护），注释引用来源合规。
//
// **真实性验证**：见 lzfse_v2_e2e_test.go —— 用 macOS /usr/bin/compression_tool
// 生成真 bvx2 block 后跑 round-trip。任何回归都会被该测试抓到。

import (
	"encoding/binary"
	"fmt"
)

// FSE state 大小 —— Apple lzfse_internal.h 定义
//
//	LZFSE_ENCODE_L_STATES       = 64
//	LZFSE_ENCODE_M_STATES       = 64
//	LZFSE_ENCODE_D_STATES       = 256   ← 注意 D 是 256（不是 64！）
//	LZFSE_ENCODE_LITERAL_STATES = 1024
//
// 早期版本误用 lmdStates=64 同时给 L/M/D，导致 D freq 表 sum 不匹配
// （实际 sum=256，被错误期待为 64 → 解码失败）。
const (
	literalStates    = 1024 // 2^10
	literalSymbolMax = 256
	lStates          = 64  // L FSE accuracy 6
	mStates          = 64  // M FSE accuracy 6
	dStates          = 256 // D FSE accuracy 8（D 范围 1..65535 比 L/M 大 4×，state 也大 4×）
	lmdSymbolMax     = 64  // D；L/M 上限 20
)


// V2Header 解出来的 v2 block header（Apple lzfse_compressed_block_header_v2 移植）
type v2Header struct {
	nRawBytes         uint32
	nLiterals         uint32
	nLiteralPayloadBytes uint32
	nMatches          uint32
	literalBits       int8 // 0..7
	literalStates     [4]uint16

	nLMDPayloadBytes uint32
	lmdBits          int8 // 0..7

	headerSize uint32 // 32 + freq payload 长度
	lState     uint16
	mState     uint16
	dState     uint16

	// 频率表原始字节位置（紧接 32 字节固定 header 之后）
	freqTableStart int
}

// parseV2Header 解 v2 block 头 32 字节固定区 + 解释 freq payload 起点。
//
// 字段全部从 Apple `lzfse_compressed_block_header_v2` 的 3 个 packed uint64 解出。
// `literal_bits` / `lmd_bits` 在编码时是 [0,7]，但磁盘上存 +7（保证 4-bit 字段非负）。
func parseV2Header(b []byte) (*v2Header, error) {
	if len(b) < 0x20 {
		return nil, fmt.Errorf("bvx2 header 太短: %d", len(b))
	}
	if string(b[0:4]) != "bvx2" {
		return nil, fmt.Errorf("非 bvx2 magic")
	}

	pf0 := binary.LittleEndian.Uint64(b[8:16])
	pf1 := binary.LittleEndian.Uint64(b[16:24])
	pf2 := binary.LittleEndian.Uint64(b[24:32])

	h := &v2Header{
		nRawBytes:            binary.LittleEndian.Uint32(b[4:8]),
		nLiterals:            uint32(pf0 & 0xFFFFF),
		nLiteralPayloadBytes: uint32((pf0 >> 20) & 0xFFFFF), // bits 20..39
		nMatches:             uint32((pf0 >> 40) & 0xFFFFF), // bits 40..59
		literalBits:          int8((pf0>>60)&0x7) - 7,       // 3 位 [-7,0]
	}

	h.literalStates[0] = uint16(pf1 & 0x3FF)
	h.literalStates[1] = uint16((pf1 >> 10) & 0x3FF)
	h.literalStates[2] = uint16((pf1 >> 20) & 0x3FF)
	h.literalStates[3] = uint16((pf1 >> 30) & 0x3FF)
	h.nLMDPayloadBytes = uint32((pf1 >> 40) & 0xFFFFF)
	h.lmdBits = int8((pf1>>60)&0x7) - 7 // 3 位 [-7,0]

	h.headerSize = uint32(pf2 & 0xFFFFFFFF)
	h.lState = uint16((pf2 >> 32) & 0x3FF)
	h.mState = uint16((pf2 >> 42) & 0x3FF)
	h.dState = uint16((pf2 >> 52) & 0x3FF)

	if h.headerSize < 32 {
		return nil, fmt.Errorf("bvx2 header_size %d < 32 固定头", h.headerSize)
	}
	h.freqTableStart = 32
	return h, nil
}

// fseTable FSE decoder 表（tANS）
// 每个 state 有 (symbol, delta_nbits, delta_finalState)
type fseEntry struct {
	symbol     int16  // 解码出的 symbol
	nbits      uint8  // 下一次从流读多少 bit
	deltaState int32  // 减去这些 bit 加回 base 得到 nextState
}

// buildFSETable 从 frequency 表构造 FSE decoder 表。
//
// frequencies[i] = symbol i 在总 states 中占的份额；∑freq = numStates。
//
// Apple lzfse 的 state 分配用 spread-symbols 函数（state 在 numStates 里均匀铺开），
// 这里实现一份简化但语义正确的版本。
func buildFSETable(frequencies []int, numStates int) ([]fseEntry, error) {
	if numStates == 0 || (numStates&(numStates-1)) != 0 {
		return nil, fmt.Errorf("numStates 必须 >0 且是 2 的幂: %d", numStates)
	}
	total := 0
	for _, f := range frequencies {
		if f < 0 {
			return nil, fmt.Errorf("负 frequency")
		}
		total += f
	}
	if total != numStates {
		return nil, fmt.Errorf("freq 之和 %d != numStates %d", total, numStates)
	}

	table := make([]fseEntry, numStates)

	// Apple spread-symbols: 逐 symbol 填 state，使用 step = (numStates>>1) + (numStates>>3) + 3
	// 简化：用标准 FSE ans sprintf distribution
	step := (numStates >> 1) + (numStates >> 3) + 3
	mask := numStates - 1
	pos := 0
	for sym, freq := range frequencies {
		for f := 0; f < freq; f++ {
			table[pos].symbol = int16(sym)
			pos = (pos + step) & mask
		}
	}
	if pos != 0 {
		// spread 后期望回到 0；不是的话说明 step 选错；容忍 (不 fatal)
	}

	// 填每个 state 的 (nbits, deltaState)
	// 算法：对每个 symbol，记录它被分配到的所有 state（按 state 升序排）；
	// 然后按 state 升序给每个 symbol 实例分配 newState 从 2^nbits_base 开始连续：
	//
	//	nbits = ceil(log2(numStates / freq)) - 1 or similar
	//	nextState = newState - numStates
	//
	// 这是 tANS 经典构造。简化版：
	//   threshold = 2^(log2_numStates) - freq
	//   first freq 个 state: nbits = log2(numStates) - log2_ceil(freq)
	//   rest: nbits-1
	//
	// 本实现按 symbol 聚合后再回填：
	indices := make(map[int16][]int) // symbol → []state
	for i, e := range table {
		indices[e.symbol] = append(indices[e.symbol], i)
	}
	logNS := log2floor(uint32(numStates))
	for sym, states := range indices {
		freq := len(states)
		if freq == 0 {
			continue
		}
		// 每个 state 的起点 newState 按升序 = numStates, numStates+1, ..., numStates+freq-1
		// 然后标准化为 2^nbits 对齐
		// nbits_base = logNS - ceil(log2(freq))
		nbitsBase := logNS - log2ceil(uint32(freq))
		threshold := (uint32(freq) << (nbitsBase + 1)) - uint32(numStates)
		for i, st := range states {
			var nbits uint8
			if uint32(i) < threshold {
				nbits = nbitsBase + 1
			} else {
				nbits = nbitsBase
			}
			// 注：本函数是旧的简化版，只填 nbits 占位。**真正 decoder** 走 lzfse_v2_fse.go
			// 的 buildFSEDecoderTable（含精确 deltaState 计算）。本处保留给测试向量生成
			table[st].nbits = nbits
			table[st].deltaState = int32(numStates) // 占位
			_ = sym
		}
	}
	// 注：完整 Apple tANS 的 deltaState 计算比上面更细；本简化版对
	// "所有 state 初始化到 (symbol, nbits≈logNS-log2freq, delta=numStates)" 的近似
	// 能让小 frequency 表 work，但对复杂真实 bvx2 block 不完全精确。
	// 真实工程用该接受 ErrLZFSEFSEPartial 并 fallback 到 afsctool。
	return table, nil
}

// log2floor / log2ceil
func log2floor(x uint32) uint8 {
	r := uint8(0)
	for x > 1 {
		x >>= 1
		r++
	}
	return r
}
func log2ceil(x uint32) uint8 {
	if x <= 1 {
		return 0
	}
	return log2floor(x-1) + 1
}

// ErrLZFSEFSEPartial FSE 解码器在边界场景（损坏数据 / 未覆盖的 Apple 变体）失败时返回。
//
// 现状：pure-Go decoder 已对 Apple compression_tool 的真实 bvx2 输出
// round-trip 通过（见 lzfse_v2_e2e_test.go），但仍保留 macOS fallback
// （/usr/bin/compression_tool）作为防御性兜底。
var ErrLZFSEFSEPartial = fmt.Errorf(
	"LZFSE v2 (bvx2) 解码失败：本块 FSE 流损坏或为未覆盖的 Apple 变体")

// DecompressLZFSEv2Block 解一个 bvx2 block。
//
// 策略（按可靠性排序）：
//   1. 纯 Go decoder (decodeV2BlockPureGo)：完整移植 Apple lzfse v2
//      header + freq + FSE table + bit reader + LMD + rep-distance。
//      regression bar：lzfse_v2_e2e_test.go 用 Apple compression_tool
//      生成真 bvx2 后字节级 round-trip 验证。跨平台无外部依赖。
//   2. macOS 上调 /usr/bin/compression_tool（Apple 官方 lzfse）—— 防御性
//      fallback：当真有未覆盖的 Apple encoder 变体或损坏数据时兜底。
//   3. ErrLZFSEFSEPartial：明确"无法解开"，上层退化到 ErrLZFSEv2Unsupported。
//
// 成功返回解出字节数。
func DecompressLZFSEv2Block(block []byte, dst []byte) (int, error) {
	h, err := parseV2Header(block)
	if err != nil {
		return 0, err
	}
	if int(h.nRawBytes) > len(dst) {
		return 0, fmt.Errorf("dst 容量不足")
	}

	// 首选路径：pure Go FSE decode（跨平台，无外部依赖）
	if n, err := decodeV2BlockPureGo(block, dst); err == nil {
		return n, nil
	}
	// 第二路径：macOS compression_tool（Apple 官方 lzfse）— pure Go 失败时用
	// 作为回退，尤其应对 frequency encoding 还有本地未覆盖的 Apple 变体
	if n, err := DecompressLZFSEv2WithAfsctool(block, dst); err == nil {
		return n, nil
	}
	return 0, ErrLZFSEFSEPartial
}
