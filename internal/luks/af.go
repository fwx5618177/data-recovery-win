package luks

// ============================================================================
// AFsplitter (Anti-Forensic Information Splitter)
//
// LUKS 在 keyslot 区域里把 master key（典型 64B）扩展成 keyBytes * stripes 字节
// （4000 stripes → 256000 字节），用 pseudo-random 数据做"防取证扩散"——单 bit
// 错误就让 merge 出错。
//
// 算法（spec：https://gitlab.com/cryptsetup/cryptsetup/-/wikis/Specification 附录 A）：
//
//   AFsplit:
//     d := 0
//     for i := 0..stripes-2:
//       random_block_i = rand(blockSize)
//       d = diffuse(d XOR random_block_i, hash)
//     final_block = d XOR master_key
//     buffer = random_block_0 || random_block_1 || ... || final_block
//
//   AFmerge（我们要做的逆向）：
//     d := 0
//     for i := 0..stripes-2:
//       d = diffuse(d XOR buffer[i*B : (i+1)*B], hash)
//     mk = d XOR buffer[(stripes-1)*B : stripes*B]
//
// 其中 diffuse 把固定大小 buffer "搅乱"：
//
//   diffuse(in, hash):
//     output = []byte
//     for blocks of size hashLen:
//       counter_be = 4 字节 big-endian 块索引
//       output += hash(counter_be || in_block)
//     return output  (长度等于 in 长度，最后一块按 in 剩余字节截断)
// ============================================================================

import (
	"encoding/binary"
	"fmt"
	"hash"
)

// AFmerge 把分散后的 keyslot 数据合并回 master_key。
//
//	in:        AFsplit 输出（长度 = mkLen * stripes）
//	mkLen:     master key 字节数
//	stripes:   分散块数（典型 4000）
//	newHash:   hash.Hash 构造器，匹配 LUKS1 的 hash_spec
func AFmerge(in []byte, mkLen, stripes int, newHash func() hash.Hash) ([]byte, error) {
	if mkLen <= 0 || stripes <= 0 {
		return nil, fmt.Errorf("AF 参数非法: mkLen=%d stripes=%d", mkLen, stripes)
	}
	if len(in) != mkLen*stripes {
		return nil, fmt.Errorf("AF 输入长度 %d 与 mkLen*stripes=%d 不匹配", len(in), mkLen*stripes)
	}

	// d 是累加器
	d := make([]byte, mkLen)
	for i := 0; i < stripes-1; i++ {
		block := in[i*mkLen : (i+1)*mkLen]
		// d ^= block
		for j := range d {
			d[j] ^= block[j]
		}
		// d = diffuse(d)
		d = diffuse(d, newHash)
	}
	// final = d XOR last_block
	last := in[(stripes-1)*mkLen : stripes*mkLen]
	mk := make([]byte, mkLen)
	for j := range mk {
		mk[j] = d[j] ^ last[j]
	}
	return mk, nil
}

// AFsplit 是 AFmerge 的逆操作，仅供测试构造 fixture 用。
//
// rand 应当返回 (mkLen*(stripes-1)) 字节伪随机数据；测试场景可以用 deterministic
// 输入便于结果可重复。
func AFsplit(mk []byte, stripes int, randBytes []byte, newHash func() hash.Hash) ([]byte, error) {
	mkLen := len(mk)
	if stripes <= 0 || mkLen <= 0 {
		return nil, fmt.Errorf("AFsplit 参数非法")
	}
	if len(randBytes) != mkLen*(stripes-1) {
		return nil, fmt.Errorf("randBytes 长度 %d 与 mkLen*(stripes-1)=%d 不匹配",
			len(randBytes), mkLen*(stripes-1))
	}

	out := make([]byte, mkLen*stripes)
	d := make([]byte, mkLen)
	for i := 0; i < stripes-1; i++ {
		block := randBytes[i*mkLen : (i+1)*mkLen]
		copy(out[i*mkLen:], block)
		for j := range d {
			d[j] ^= block[j]
		}
		d = diffuse(d, newHash)
	}
	// final = d XOR mk
	for j := 0; j < mkLen; j++ {
		out[(stripes-1)*mkLen+j] = d[j] ^ mk[j]
	}
	return out, nil
}

// diffuse 把 in 切成 hashLen 大小的块，每块前缀一个 4 字节 BE counter 后哈希。
// 输出长度等于 in；最后一块按需截断。
func diffuse(in []byte, newHash func() hash.Hash) []byte {
	h := newHash()
	hashLen := h.Size()
	out := make([]byte, len(in))

	pos := 0
	counter := uint32(0)
	for pos < len(in) {
		blockEnd := pos + hashLen
		if blockEnd > len(in) {
			blockEnd = len(in)
		}
		// 重置 hash
		h.Reset()
		// counter (BE)
		var cb [4]byte
		binary.BigEndian.PutUint32(cb[:], counter)
		h.Write(cb[:])
		h.Write(in[pos:blockEnd])
		sum := h.Sum(nil)
		// 复制最多 (blockEnd - pos) 字节
		n := blockEnd - pos
		if n > len(sum) {
			n = len(sum)
		}
		copy(out[pos:blockEnd], sum[:n])
		pos = blockEnd
		counter++
	}
	return out
}
