package lzx

import "fmt"

// canonical Huffman decoder —— LZX 的所有 huffman tree 都是 canonical + 用 code lengths
// 数组表示（每个 symbol 对应它的码长）。
//
// 解码策略：查表法。对"最长码长 ≤ tablePrefixBits (9 bit)"的直接查 L1 表；
// 超过的用 L2 二级表。这是 zlib 里同款实现，快 + 内存小。

const (
	tablePrefixBits = 9 // 一级 lookup 表用 9 bit 查；覆盖 ~95% 符号
	maxCodeBits     = 17
)

// canonicalTable 单个 huffman 表，针对某种 symbol 集（pretree / main / length / aligned-offset）
type canonicalTable struct {
	// decode[index] = packed entry: low 16 bit = symbol, high 8 bit = nBits
	decode []uint32
}

const (
	decodeInvalid uint32 = 0xFFFFFFFF
)

// buildCanonical 从 codeLengths 数组构造 canonical huffman decode table。
// codeLengths[i] = symbol i 的码长；0 表示不存在。
//
// 标准 canonical 构造：
//   - 按 (length, symbol) 排序
//   - 相同 length 的按 symbol 升序获得连续 code 值
//   - code 从最短长度的 0 开始，每次 +1；length 增加时码值左移
func buildCanonical(codeLengths []byte) (*canonicalTable, error) {
	// 1. 统计每种码长有多少个 symbol
	var numCodes [maxCodeBits + 1]int
	for _, l := range codeLengths {
		if l > maxCodeBits {
			return nil, fmt.Errorf("code length %d 超出 max %d", l, maxCodeBits)
		}
		numCodes[l]++
	}

	// 2. 算每种码长的起始 code 值（next_code[n]）
	var nextCode [maxCodeBits + 2]uint32
	code := uint32(0)
	for bits := uint(1); bits <= maxCodeBits; bits++ {
		code = (code + uint32(numCodes[bits-1])) << 1
		nextCode[bits] = code
	}

	// 3. 给每个 symbol 赋 canonical code
	type symEntry struct {
		symbol int
		nbits  byte
		code   uint32
	}
	syms := make([]symEntry, 0, len(codeLengths))
	for sym, l := range codeLengths {
		if l == 0 {
			continue
		}
		c := nextCode[l]
		nextCode[l]++
		syms = append(syms, symEntry{symbol: sym, nbits: l, code: c})
	}

	// 4. 构造 decode 表：长度 <= tablePrefixBits 的 symbol 直接填到 1<<tablePrefixBits 表
	// 长度更长的用 overflow linked chain（简化：不做 L2 表 — LZX 的 maxCodeBits=16 意味着
	// 大表是 64KB，可接受，直接全 1<<maxCodeBits 位数组）
	size := 1 << maxCodeBits
	table := make([]uint32, size)
	for i := range table {
		table[i] = decodeInvalid
	}
	for _, e := range syms {
		// canonical code e.code 的 MSB-first 解读：填入以"e.code padded 到 maxCodeBits"为起点的
		// 连续 2^(maxCodeBits - nbits) 个槽位
		base := e.code << (maxCodeBits - uint32(e.nbits))
		span := uint32(1) << (maxCodeBits - uint32(e.nbits))
		entry := uint32(e.nbits)<<24 | uint32(e.symbol)&0xFFFFFF
		for i := uint32(0); i < span; i++ {
			table[base+i] = entry
		}
	}
	return &canonicalTable{decode: table}, nil
}

// decodeSymbol 从 bit stream 读下一个 symbol
func (t *canonicalTable) decodeSymbol(r *bitReader) (int, error) {
	// peek maxCodeBits，查表拿 (nbits, symbol)，consume nbits
	r.refill(maxCodeBits)
	if r.err != nil {
		return 0, r.err
	}
	idx := r.buf >> (32 - maxCodeBits)
	entry := t.decode[idx]
	if entry == decodeInvalid {
		return 0, fmt.Errorf("huffman: 非法 code (idx=0x%X)", idx)
	}
	nbits := uint(entry >> 24)
	symbol := int(entry & 0xFFFFFF)
	r.consume(nbits)
	return symbol, nil
}
