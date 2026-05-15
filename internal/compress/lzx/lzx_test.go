package lzx

import (
	"testing"
)

// LZX bitreader 是 MS 奇异的"16-bit LE word + bit 从 MSB 取"格式。
//
// 字节流 [b0 b1 b2 b3]:
//
//	word0 = LE16(b0 b1) = b0 | b1<<8
//	word1 = LE16(b2 b3) = b2 | b3<<8
//
// bit stream 从 word0 的 MSB 开始读。
//
// 例：b0=0x12 b1=0x34 → word0 = 0x3412
//
//	先读 4 bit: 0x3 (bit 15..12)
//	再读 4 bit: 0x4 (bit 11..8)
//	再读 4 bit: 0x1 (bit 7..4)
func TestBitReader_MSBFirst16LEWord(t *testing.T) {
	src := []byte{0x12, 0x34}
	r := newBitReader(src)
	for _, want := range []uint32{0x3, 0x4, 0x1, 0x2} {
		got := r.read(4)
		if got != want {
			t.Errorf("read 4bit: got 0x%X want 0x%X", got, want)
		}
	}
}

// 读超过 16 位的值（跨 word 边界）
func TestBitReader_SpansWordBoundary(t *testing.T) {
	src := []byte{0x12, 0x34, 0x56, 0x78}
	r := newBitReader(src)
	// 跳过 12 bit = 3 个 nibble "341"
	r.read(12)
	// 再读 16 bit 应得低 4 bit of word0 (0x2) 拼 high 12 bit of word1 (0x785)
	// word0 = 0x3412, word1 = 0x7856
	// 读 16 bit 起点 = word0 bit 3..0 + word1 bit 15..4 = (0x2 << 12) | (0x785) = 0x2785
	got := r.read(16)
	if got != 0x2785 {
		t.Errorf("cross-word read: got 0x%X want 0x2785", got)
	}
}

// canonical huffman 构造 + 解码 round-trip
// 参考 Deflate RFC 1951 example：3 个 symbol，码长 [2, 1, 3, 3]
// 码：A=10, B=0, C=110, D=111（canonical MSB-first）
func TestCanonicalHuffman_Decode(t *testing.T) {
	// symbol 0,1,2,3 对应 A,B,C,D；码长 [2,1,3,3]
	lens := []byte{2, 1, 3, 3}
	tab, err := buildCanonical(lens)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// 编码 "BACD"：B=0 A=10 C=110 D=111 → bit stream MSB-first "0 10 110 111"
	// 接进 LZX 的 16-bit LE word 读法：
	//   bit stream: 01011 0111 (9 bits) → 填到 word0 的 MSB
	//   bit[15..7] = 01011 0111 剩下 7 bit 填 0
	//   word0 value = 0b0101_1011_1000_0000 = 0x5B80
	//   byte LE: 0x80 0x5B
	// + padding 字节让 bitreader refill 17 位不越界
	src := []byte{0x80, 0x5B, 0x00, 0x00, 0x00, 0x00}
	r := newBitReader(src)

	want := []int{1, 0, 2, 3} // B A C D
	for _, w := range want {
		sym, err := tab.decodeSymbol(r)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if sym != w {
			t.Errorf("got %d want %d", sym, w)
		}
	}
}

// buildCanonical 拒绝非法码长（超过 maxCodeBits）
func TestCanonicalHuffman_RejectsTooLongCode(t *testing.T) {
	lens := []byte{18} // > 17 = maxCodeBits
	if _, err := buildCanonical(lens); err == nil {
		t.Error("过长码长应被拒")
	}
}

// 完整 LZX decode 的真实 round-trip 需要构造完整 LZX stream（含 pretree / main tree /
// delta code lengths + 数据），那不是一两百字节能做的合成测试。本 test suite 只验证
// 组件级正确性；端到端 round-trip 留给 integration test 用真 WIM 文件。

// 但我们验证 NewDecoder 不 panic + 空输入返回合理 error
func TestNewDecoder_EmptySrc(t *testing.T) {
	d := NewDecoder(32*1024, 100)
	_, err := d.Decode([]byte{}, make([]byte, 100))
	if err == nil {
		t.Error("空输入应返回 error")
	}
}
