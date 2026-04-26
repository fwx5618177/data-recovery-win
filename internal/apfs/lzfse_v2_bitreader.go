package apfs

// LZFSE v2 backward FSE bit reader —— 严格移植 Apple `lzfse_fse.h`
// 的 fse_in_stream / fse_in_init / fse_in_flush / fse_in_pull 语义。
//
// 关键约定（Apple 模型，与朴素 LSB-bit-stream 不同）：
//
//	accum 是 64-bit 累加器
//	bits [0..accum_nbits-1] 是有效数据，bits [accum_nbits..63] 必须为 0
//	**HIGH 位 = 最近推入的 bit**（即 encoder 最后写的）
//	**LOW 位 = 最早推入的 bit**
//	pull(N): result = accum >> (accum_nbits - N)，然后 accum &= mask, nbits -= N
//	→ 从 HIGH 端取 N bit，符合 FSE encoder→decoder 反向 LIFO 语义
//
// 关键陷阱（**容易踩**）：Apple init 时**总是**装载 8 字节（不论 payload 大小），
// 即使 payload 只有 6 字节。Apple 借助 `buf_start` = 整个 source 起点 来允许 init
// 倒退超出 payload 边界（payload 前面的 header 字节作为"无关 garbage" 装到 accum
// 低位，会被 pull 自动消费掉）。
//
// 所以本 reader 接受 `data` = 整个 source slice + `payloadEnd` = payload 结束位置。
// init 从 payloadEnd 倒退 8 字节装 accum；padBits 作为 accumNBits 的"扣除量"
// （= encoder 末尾对齐填充的 0 bit 数 |padBits|，∈ [0, 7]）。

import "fmt"

type reverseBitReader struct {
	data       []byte // 整个 source slice（**包含** payload 前面的 bytes）
	bufPos     int    // 下一次从 buf 读时的指针位置（指向当前未消费的字节后一位）
	accum      uint64 // 64-bit 累加器，bits [0..accumNBits-1] 有效
	accumNBits int    // 有效 bit 数
}

// newReverseBitReader 从 data[0:payloadEnd] 末尾反向初始化 bit reader。
//
// data: 整个 source buffer（必须 ≥ 8 字节，否则 init 失败）
// payloadEnd: payload 结束位置（exclusive），从这里向前读
// padBits: literal_bits 或 lmd_bits（Apple header 字段，∈ [-7, 0]）
//
//	|padBits| = encoder 末尾对齐填充的 0 bit 数
//
// **要求 data 必须 ≥ 8 字节**（Apple 不支持 64-bit FSE 流 < 8 字节装载；
// LZFSE block 格式保证 header ≥ 32 字节，total source 总是远超 8）。
func newReverseBitReader(data []byte, payloadEnd int, padBits int) (*reverseBitReader, error) {
	if padBits < -7 || padBits > 0 {
		return nil, fmt.Errorf("padBits %d 不在 [-7, 0]", padBits)
	}
	if payloadEnd > len(data) {
		return nil, fmt.Errorf("payloadEnd %d > len %d", payloadEnd, len(data))
	}
	if payloadEnd < 8 {
		return nil, fmt.Errorf("source 总长 %d < 8（Apple 64-bit FSE init 不支持）", payloadEnd)
	}
	r := &reverseBitReader{data: data, bufPos: payloadEnd}
	// Apple fse_in_checked_init64：n != 0 装 8 字节 (accum_nbits = n+64)，
	// n == 0 装 7 字节 (accum_nbits = n+56)
	var loadBytes int
	if padBits != 0 {
		loadBytes = 8
		r.accumNBits = padBits + 64
	} else {
		loadBytes = 7
		r.accumNBits = padBits + 56
	}
	r.bufPos -= loadBytes
	r.accum = readLE(data[r.bufPos : r.bufPos+loadBytes])

	// 有效性自检：bits 高于 accumNBits 必须为 0（encoder padding）
	if r.accumNBits < 0 || r.accumNBits >= 64 {
		return nil, fmt.Errorf("init: accumNBits %d 越界", r.accumNBits)
	}
	if r.accumNBits == 0 {
		if r.accum != 0 {
			return nil, fmt.Errorf("init: accum 非零但 accumNBits=0")
		}
	} else if (r.accum >> uint(r.accumNBits)) != 0 {
		return nil, fmt.Errorf("init: encoder padding 非零 (accum=%016x nbits=%d)",
			r.accum, r.accumNBits)
	}
	return r, nil
}

// readLE 把 bytes 当 little-endian 64-bit 装载（不够 8 字节高位补 0）
func readLE(b []byte) uint64 {
	var x uint64
	for i, c := range b {
		x |= uint64(c) << uint(i*8)
	}
	return x
}

// flush 在每次需要更多 bits 之前调用。从 buf 装载 0..7 字节使 accum_nbits 接近 64。
func (r *reverseBitReader) flush() {
	// nbits 是要装载的 bit 数（按字节对齐，即 (63 - accumNBits) 向下到 8 倍数）
	nbits := (63 - r.accumNBits) & ^7
	if nbits <= 0 {
		return
	}
	loadBytes := nbits >> 3
	if r.bufPos < loadBytes {
		loadBytes = r.bufPos
		nbits = loadBytes * 8
	}
	if loadBytes == 0 {
		return
	}
	r.bufPos -= loadBytes
	incoming := readLE(r.data[r.bufPos : r.bufPos+loadBytes])
	// 旧 accum 左移让位，新 bytes 填低位
	r.accum = (r.accum << uint(nbits)) | incoming
	r.accumNBits += nbits
}

// pull 从 accum HIGH 端取 N bit，返回值在低 N bit。
func (r *reverseBitReader) pull(n uint8) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	if n > 32 {
		return 0, fmt.Errorf("pull n=%d > 32", n)
	}
	if int(n) > r.accumNBits {
		// 需要更多 bits → 先 flush
		r.flush()
		if int(n) > r.accumNBits {
			return 0, fmt.Errorf("pull: 数据不足（请求 %d bit，剩 %d）", n, r.accumNBits)
		}
	}
	// 取 HIGH N bit
	r.accumNBits -= int(n)
	result := r.accum >> uint(r.accumNBits)
	// 清掉刚取走的 high N bit
	if r.accumNBits == 0 {
		r.accum = 0
	} else {
		r.accum &= (uint64(1) << uint(r.accumNBits)) - 1
	}
	return uint32(result), nil
}
