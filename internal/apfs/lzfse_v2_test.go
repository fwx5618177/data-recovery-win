package apfs

import (
	"encoding/binary"
	"errors"
	"testing"
)

// v2 header parse —— 验证 44 字节固定布局解码正确
func TestParseV2Header(t *testing.T) {
	buf := make([]byte, 64)
	copy(buf[0:4], []byte("bvx2"))
	binary.LittleEndian.PutUint32(buf[4:8], 1024)       // n_raw_bytes
	binary.LittleEndian.PutUint32(buf[8:12], 200)       // n_payload_bytes
	binary.LittleEndian.PutUint32(buf[12:16], 500)      // n_literals
	binary.LittleEndian.PutUint32(buf[16:20], 30)       // n_matches
	binary.LittleEndian.PutUint16(buf[20:22], 100)      // lit state 0
	binary.LittleEndian.PutUint16(buf[22:24], 200)
	binary.LittleEndian.PutUint16(buf[24:26], 300)
	binary.LittleEndian.PutUint16(buf[26:28], 400)
	buf[28] = 5                                         // literal_bits
	binary.LittleEndian.PutUint16(buf[29:31], 10)       // l_state
	binary.LittleEndian.PutUint16(buf[31:33], 20)       // m_state
	binary.LittleEndian.PutUint16(buf[33:35], 30)       // d_state
	buf[35] = 7                                         // lmd_bits
	binary.LittleEndian.PutUint32(buf[36:40], 100)      // literal_payload_len
	binary.LittleEndian.PutUint32(buf[40:44], 80)       // lmd_payload_len

	h, err := parseV2Header(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.nRawBytes != 1024 || h.nLiterals != 500 || h.lmdBits != 7 {
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
func TestDecompressLZFSEv2Block_PartialReturnsExpectedError(t *testing.T) {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte("bvx2"))
	binary.LittleEndian.PutUint32(hdr[4:8], 100)
	_, err := DecompressLZFSEv2Block(hdr, make([]byte, 200))
	if !errors.Is(err, ErrLZFSEFSEPartial) {
		t.Errorf("应返回 ErrLZFSEFSEPartial，实际 %v", err)
	}
}
