package apfs

// LZFSE v2 backward bit reader —— Apple lzfse 的 bit stream 是**从末尾向前读**。
//
// 理由（FSE/ANS 熵编码的固有特性）：
//   encoder 按正向产生 symbols，但每次把新 bits 推到 accumulator 的**高位**；
//   decoder 必须**反向**取出：从流末尾开始，累加器每次右移 N bits 消费。
//   这样每个 symbol decode 的 "pull N bits" 刚好对应 encoder 的 "push N bits"。
//
// 参考：Apple lzfse_decode_v2_block.c 的 bitStreamRev 结构 + Yann Collet 的
//      FSE paper "Asymmetric Numeral Systems"。
//
// 本实现的 bit reader 按 64-bit accumulator 缓冲，每次从流末尾填充 64 bit。
// 位顺序按 little-endian（Apple 格式）。

import "fmt"

// reverseBitReader 从字节流末尾向前读 bit
//
// 字节序约定（与 Apple lzfse 一致）：
//   流是 little-endian；每 8 字节合成一个 uint64；从 accumulator 的**低位**读出 bits。
//   fill 后，accumulator 的低 64-bitPos 位是可用数据（bitPos 是已消费的 bit 数）。
type reverseBitReader struct {
	data    []byte
	bytePos int     // 当前"下一个读回 accumulator 的字节位置"（从末尾 - 8 起）
	accum   uint64  // 64 位累加器
	bitPos  int     // accum 已消费的 bit 数（0..63）
}

// newReverseBitReader 创建一个从 data 末尾开始反向读的 reader。
//
// headBits 是流开头要保留的 unused bits（Apple header 里 literal_bits / lmd_bits 字段）
// 这是 encoder 对齐 accumulator 时留下的"padding bit"数量；decode 开始前要先 pull 掉。
func newReverseBitReader(data []byte, headBits int) (*reverseBitReader, error) {
	// bitPos 初始化为 64 = accum 完全消费状态，首次 fill() 不会把空 accum 当 leftover
	r := &reverseBitReader{data: data, bytePos: len(data), bitPos: 64}
	if err := r.fill(); err != nil {
		return nil, err
	}
	// 先消费掉 encoder padding bit
	if headBits > 0 {
		if _, err := r.pull(uint8(headBits)); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// fill 从流末尾拉 1..8 字节进 accumulator。
// 每次 fill 完后保证 accum 里有至少 56 bit 可供读（只要流还没读完）。
func (r *reverseBitReader) fill() error {
	// bitPos 已消费的 bit 数；accum 剩余 (64 - bitPos) bit
	// 如果已消费 >= 8 bit，可拉一个字节补进来（从低位推进，但因为反向所以从流末尾拉）
	// 实际策略：每次 fill 拉 8 字节（若流还够），重置 bitPos
	if r.bytePos == 0 {
		// 流耗尽
		if r.bitPos >= 64 {
			return fmt.Errorf("bit stream EOF")
		}
		return nil
	}
	// 从末尾拉 8 字节（或剩余所有）
	take := 8
	if r.bytePos < take {
		take = r.bytePos
	}
	// 先把当前 accum 里剩余的 bits 暂存起来，放到新数据的"高位"之上
	//
	// 反向 bit stream：流末尾的字节包含最后写入的 bit（按 encoder 视角）；
	// decoder 要先读那些 bit。所以 fill 流程：
	//   newBytes = data[bytePos-take : bytePos]
	//   把这 take 字节看作 uint64（little-endian），和已剩余 accum 拼接：
	//   leftover = accum >> bitPos （高位是 "还未 pull 的 bit"）
	//   accum = newBytes + (leftover << (take*8))
	//   bitPos -= take * 8
	leftover := r.accum >> uint(r.bitPos)
	leftoverBits := 64 - r.bitPos
	startIdx := r.bytePos - take

	// 反向 bit stream：stream 末尾的字节是"最近 encoder 写入"，decoder 要先读它。
	// 所以末尾字节进 accum 的**低位**（下次 pull 从低位取）；次末尾进稍高位...
	// 这意味着拼 newBytes 时顺序是 data[bytePos-1] → byte[0], data[bytePos-2] → byte[1]...
	var newBytes uint64
	for i := 0; i < take; i++ {
		// r.data[bytePos-1-i] 放在 newBytes 的第 i 个 byte（低→高）
		newBytes |= uint64(r.data[r.bytePos-1-i]) << (uint(i) * 8)
	}
	// 填入 accum：低 take*8 bit 是新数据，其上是 leftover
	r.accum = newBytes | (leftover << uint(take*8))
	r.bytePos = startIdx
	r.bitPos = 64 - (take*8 + leftoverBits)
	if r.bitPos < 0 {
		return fmt.Errorf("bit reader overflow")
	}
	return nil
}

// pull 从 accumulator 低位读 n bit，右对齐返回。n 最多 32（足够 Apple 的 FSE + extra bits）。
func (r *reverseBitReader) pull(n uint8) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	if n > 32 {
		return 0, fmt.Errorf("pull n=%d 超过 32", n)
	}
	// 如果 accum 剩余不足，先 fill
	if 64-r.bitPos < int(n) {
		if err := r.fill(); err != nil {
			return 0, err
		}
		if 64-r.bitPos < int(n) {
			return 0, fmt.Errorf("pull: 数据不足（请求 %d bit，剩 %d）", n, 64-r.bitPos)
		}
	}
	mask := (uint64(1) << uint(n)) - 1
	out := (r.accum >> uint(r.bitPos)) & mask
	r.bitPos += int(n)
	return uint32(out), nil
}

