package apfs

import (
	"testing"
)

// FuzzParseV2Header bvx2 header parser 不能因任意字节 panic
func FuzzParseV2Header(f *testing.F) {
	// seed：合法 header
	seed := make([]byte, 44)
	copy(seed[0:4], []byte("bvx2"))
	f.Add(seed)

	// seed：短 header
	f.Add([]byte("bvx2"))
	f.Add([]byte{}) // 空

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseV2Header panic on len=%d: %v", len(data), r)
			}
		}()
		_, _ = parseV2Header(data)
	})
}

// FuzzDecompressLZFSE 完整 LZFSE container decoder 不 panic
// 输入任意字节（可能含 bvxn/bvx-/bvx2/bvx$ 等 magic 片段）
func FuzzDecompressLZFSE(f *testing.F) {
	f.Add([]byte("bvx$"))
	f.Add([]byte("bvx-\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	seed := make([]byte, 32)
	copy(seed[0:4], []byte("bvxn"))
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecompressLZFSE panic: %v", r)
			}
		}()
		// 给 dst 足够大（也限上限避免巨量 alloc）
		dstLen := len(data) * 4
		if dstLen > 1<<20 {
			dstLen = 1 << 20 // 1MB 上限
		}
		if dstLen < 64 {
			dstLen = 64
		}
		dst := make([]byte, dstLen)
		_, _ = DecompressLZFSE(data, dst)
	})
}

// FuzzDecodeFrequencies lzfse v2 的 4-bit tag + variable extra bits 解码器
// 不能 panic
func FuzzDecodeFrequencies(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF})
	// 合法 freq：20 个 symbols，每个 tag=2（value=1），共 20 → numStates=16 不匹配但 parser 应 error 而非 panic
	seed := make([]byte, 200)
	for i := range seed {
		seed[i] = 0x22 // tag=2 重复
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseAllFrequencies panic on len=%d: %v", len(data), r)
			}
		}()
		_, _, _, _, _, _ = parseAllFrequencies(data)
	})
}
