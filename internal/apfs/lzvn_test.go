package apfs

import (
	"bytes"
	"testing"
)

// 简化 op：0xE0..0xEF 是 literals only，长度 (op & 0x0F)+1，后跟数据
func TestDecompressLZVN_LiteralsOnly(t *testing.T) {
	// 构造："hello" + EOS
	// op 0xE4 = 5 个 literal
	src := []byte{0xE4, 'h', 'e', 'l', 'l', 'o', 0x06}
	dst := make([]byte, 32)
	n, err := DecompressLZVN(src, dst)
	if err != nil {
		t.Fatalf("DecompressLZVN: %v", err)
	}
	if n != 5 {
		t.Errorf("解出 %d 字节 want 5", n)
	}
	if !bytes.Equal(dst[:n], []byte("hello")) {
		t.Errorf("内容不对: %q", dst[:n])
	}
}

// 0xA0 op：下一字节是长度
func TestDecompressLZVN_LongLiterals(t *testing.T) {
	// op 0xA0 + lenByte=4（→ 5 literals） + "world"
	src := []byte{0xA0, 4, 'w', 'o', 'r', 'l', 'd', 0x06}
	dst := make([]byte, 32)
	n, err := DecompressLZVN(src, dst)
	if err != nil {
		t.Fatalf("DecompressLZVN: %v", err)
	}
	if string(dst[:n]) != "world" {
		t.Errorf("内容不对: %q", dst[:n])
	}
}

// 不支持的 op 应返回 *LZVNOpUnsupportedError + dst 已有部分数据
func TestDecompressLZVN_UnsupportedOpReturnsPartial(t *testing.T) {
	// 先 5 个 literals，再一个 0xC0（未实现）
	src := []byte{0xE4, 'h', 'e', 'l', 'l', 'o', 0xC0, 0xFF}
	dst := make([]byte, 32)
	n, err := DecompressLZVN(src, dst)
	if n != 5 {
		t.Errorf("应解出 5 字节再卡住，得到 %d", n)
	}
	if _, ok := err.(*LZVNOpUnsupportedError); !ok {
		t.Errorf("应返回 *LZVNOpUnsupportedError，得到 %T", err)
	}
}

// small op (op ≤ 0x5F): L=bits7-6, M=(op&0x3F)+3
//
//	op=0x42  = 01 000010 → L=1, M=5
//
// 先用 0xE2 "ABC" 累积 3 字节，再用 0x42 做 1 literal "D" + distance=3 match 5
func TestDecompressLZVN_SmallOpMatch(t *testing.T) {
	src := []byte{
		0xE2, 'A', 'B', 'C', // 3 literals
		0x42, 'D', 0x04, 0x00, // 1 literal "D" + distance=4 + match 5 bytes
		0x06, // EOS
	}
	dst := make([]byte, 32)
	n, err := DecompressLZVN(src, dst)
	if err != nil {
		t.Fatalf("DecompressLZVN: %v", err)
	}
	// dst[0..3] = "ABCD"，dstPos=4；distance=4 → 从 dst[0]='A' 起 5 字节（含重叠）= "ABCDA"
	want := []byte("ABCDABCDA")
	if n != len(want) {
		t.Fatalf("n=%d want %d; got=%q", n, len(want), dst[:n])
	}
	for i := range want {
		if dst[i] != want[i] {
			t.Fatalf("byte %d = %q want %q (full got=%q)", i, dst[i], want[i], dst[:n])
		}
	}
}

func TestIsLZFSEMagic(t *testing.T) {
	for _, m := range []string{"bvxn", "bvx2", "bvx-", "bvx$"} {
		if !IsLZFSEMagic([]byte(m)) {
			t.Errorf("应识别 %s", m)
		}
	}
	if IsLZFSEMagic([]byte("xxxx")) {
		t.Error("不应识别 xxxx")
	}
	if IsLZFSEMagic([]byte("bv")) {
		t.Error("不应识别太短")
	}
}
