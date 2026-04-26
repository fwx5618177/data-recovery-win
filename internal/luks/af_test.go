package luks

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// 关键约束：AFsplit + AFmerge 必须 round-trip。
// 这是 LUKS1 解锁能否成功的灵魂——任何 diffuse / counter 编码错位都会让 master key 错。

func TestAFRoundTrip_DefaultStripes(t *testing.T) {
	mk := bytes.Repeat([]byte{0x42}, 32) // 32B master key
	stripes := 4000
	rand := make([]byte, 32*(stripes-1))
	for i := range rand {
		rand[i] = byte(i & 0xFF)
	}

	split, err := AFsplit(mk, stripes, rand, sha256.New)
	if err != nil {
		t.Fatal(err)
	}
	if len(split) != 32*stripes {
		t.Errorf("split 输出长度: got %d, want %d", len(split), 32*stripes)
	}

	merged, err := AFmerge(split, 32, stripes, sha256.New)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(merged, mk) {
		t.Errorf("AF round-trip 失败:\n  got  %x\n  want %x", merged, mk)
	}
}

func TestAFRoundTrip_TinyStripes(t *testing.T) {
	// 测试极小 stripes（边界）
	mk := bytes.Repeat([]byte{0x99}, 64)
	stripes := 4
	rand := make([]byte, 64*3)
	for i := range rand {
		rand[i] = byte(i)
	}
	split, _ := AFsplit(mk, stripes, rand, sha256.New)
	merged, _ := AFmerge(split, 64, stripes, sha256.New)
	if !bytes.Equal(merged, mk) {
		t.Errorf("tiny round-trip 失败")
	}
}

func TestAFMerge_AnyBitFlipBreaksKey(t *testing.T) {
	// AFsplit 的"防取证"特性：单 bit 错就让 merge 出错的 key
	mk := bytes.Repeat([]byte{0xAA}, 32)
	stripes := 100
	rand := make([]byte, 32*(stripes-1))
	for i := range rand {
		rand[i] = byte(i * 7 & 0xFF)
	}
	split, _ := AFsplit(mk, stripes, rand, sha256.New)

	// 翻转中间某个字节的 1 bit
	tampered := append([]byte{}, split...)
	tampered[stripes*32/2] ^= 0x01

	merged, _ := AFmerge(tampered, 32, stripes, sha256.New)
	if bytes.Equal(merged, mk) {
		t.Errorf("被篡改的 split 应得不到原 mk，但 AFmerge 还是返回了原值")
	}
}

func TestAFMerge_RejectsWrongInputSize(t *testing.T) {
	if _, err := AFmerge(make([]byte, 99), 32, 4, sha256.New); err == nil {
		t.Errorf("输入长度不匹配应报错")
	}
}

func TestDiffuse_OutputSizeMatchesInput(t *testing.T) {
	for _, n := range []int{1, 31, 32, 33, 63, 64, 65, 100} {
		in := bytes.Repeat([]byte{0xBE}, n)
		out := diffuse(in, sha256.New)
		if len(out) != n {
			t.Errorf("diffuse 输入 %d 字节，输出 %d 字节（应相同）", n, len(out))
		}
	}
}
