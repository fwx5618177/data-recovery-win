package apfs

import (
	"encoding/binary"
	"errors"
	"testing"
)

// v2 header parse smoke 测试（详细布局验证见 TestParseV2Header_FieldPositions）
func TestParseV2Header(t *testing.T) {
	buf := make([]byte, 64)
	copy(buf[0:4], []byte("bvx2"))
	binary.LittleEndian.PutUint32(buf[4:8], 1024)
	// pf0 = n_literals=500, n_matches=30, n_lit_payload=100, literal_bits=-2 (= 5 stored)
	pf0 := uint64(500) | (uint64(30) << 20) | (uint64(100) << 40) | (uint64(5) << 60)
	binary.LittleEndian.PutUint64(buf[8:16], pf0)
	// pf1 = literal_states 100..400 (10-bit each), n_lmd_payload=80, lmd_bits=0 (= 7 stored)
	pf1 := uint64(100) | (uint64(200) << 10) | (uint64(300) << 20) |
		(uint64(400) << 30) | (uint64(80) << 40) | (uint64(7) << 60)
	binary.LittleEndian.PutUint64(buf[16:24], pf1)
	// pf2 = header_size=64, lState=10, mState=20, dState=30
	pf2 := uint64(64) | (uint64(10) << 32) | (uint64(20) << 42) | (uint64(30) << 52)
	binary.LittleEndian.PutUint64(buf[24:32], pf2)

	h, err := parseV2Header(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.nRawBytes != 1024 || h.nLiterals != 500 || h.lmdBits != 0 {
		t.Errorf("header: %+v", h)
	}
	if h.literalStates[0] != 100 || h.literalStates[3] != 400 {
		t.Errorf("literalStates: %+v", h.literalStates)
	}
}

func TestParseV2Header_BadMagic(t *testing.T) {
	buf := make([]byte, 64)
	copy(buf[0:4], []byte("XXXX"))
	if _, err := parseV2Header(buf); err == nil {
		t.Error("非 bvx2 应报错")
	}
}

// buildFSETable 正确性：给固定 frequency 构造 decoder table，遍历所有 state 确认
// 每个 state 都有合法 symbol。
//
// 注：真实 LZFSE 用 N=1024 (literal) 或 N=64 (LMD)；本测试用 N=16（Apple spread
// 函数 step = 8+2+3=13, gcd(13,16)=1 互质可遍历）。
func TestBuildFSETable_ValidDistribution(t *testing.T) {
	// 频率：symbol 0=8, symbol 1=4, symbol 2=4，总和 16
	freqs := []int{8, 4, 4}
	tab, err := buildFSETable(freqs, 16)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(tab) != 16 {
		t.Fatalf("table size %d want 16", len(tab))
	}
	// 每个 state 的 symbol 必须在 [0, len(freqs))
	for i, e := range tab {
		if e.symbol < 0 || int(e.symbol) >= len(freqs) {
			t.Errorf("state %d: symbol %d 越界", i, e.symbol)
		}
	}
	// 每个 symbol 出现次数 = freq
	counts := make(map[int16]int)
	for _, e := range tab {
		counts[e.symbol]++
	}
	for s, wantFreq := range freqs {
		if counts[int16(s)] != wantFreq {
			t.Errorf("symbol %d: count %d want %d", s, counts[int16(s)], wantFreq)
		}
	}
}

func TestBuildFSETable_RejectsNonPower2(t *testing.T) {
	if _, err := buildFSETable([]int{3, 4}, 7); err == nil {
		t.Error("numStates 非 2 的幂应被拒")
	}
}

func TestBuildFSETable_RejectsFreqMismatch(t *testing.T) {
	if _, err := buildFSETable([]int{1, 2, 3}, 8); err == nil {
		t.Error("freq 之和不等于 numStates 应被拒")
	}
}

func TestLog2Funcs(t *testing.T) {
	cases := []struct {
		in               uint32
		wantFloor, wantCeil uint8
	}{
		{1, 0, 0},
		{2, 1, 1},
		{3, 1, 2},
		{4, 2, 2},
		{5, 2, 3},
		{8, 3, 3},
		{16, 4, 4},
		{1024, 10, 10},
	}
	for _, c := range cases {
		if g := log2floor(c.in); g != c.wantFloor {
			t.Errorf("log2floor(%d)=%d want %d", c.in, g, c.wantFloor)
		}
		if g := log2ceil(c.in); g != c.wantCeil {
			t.Errorf("log2ceil(%d)=%d want %d", c.in, g, c.wantCeil)
		}
	}
}

// DecompressLZFSEv2Block 当前实现对复杂场景返回 ErrLZFSEFSEPartial；上层正确退化
//
// 用一个语法上合法但语义不可解的 bvx2 block：headerSize=32（最小），
// freq payload 0 字节但 nLiterals=100。decoder 试图解但因 freq 表全为零
// 必然失败，最终返回 ErrLZFSEFSEPartial（pure-Go fail + macOS fallback fail）。
func TestDecompressLZFSEv2Block_PartialReturnsExpectedError(t *testing.T) {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte("bvx2"))
	binary.LittleEndian.PutUint32(hdr[4:8], 100)
	// pf2 with header_size=32，让 freq payload = 0 字节但其他字段都是 0
	pf2 := uint64(32)
	binary.LittleEndian.PutUint64(hdr[24:32], pf2)
	_, err := DecompressLZFSEv2Block(hdr, make([]byte, 200))
	if !errors.Is(err, ErrLZFSEFSEPartial) {
		t.Errorf("应返回 ErrLZFSEFSEPartial，实际 %v", err)
	}
}
