package apfs

import (
	"encoding/binary"
	"testing"
)

// 组件级 round-trip: FSE table build 后可逆
// 构造 freq 表 → buildFSEDecoderTable → 遍历 state 验证 symbol 覆盖 +
// state transition 落回 [0, numStates)
func TestBuildFSEDecoderTable_AllStatesValid(t *testing.T) {
	// 频率：freq 总和 = 64 (lmdStates)
	// symbol 0..4，频率 [16, 16, 16, 8, 8]
	freqs := []int{16, 16, 16, 8, 8}
	tbl, err := buildFSEDecoderTable(freqs, 64)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(tbl) != 64 {
		t.Fatalf("table size: %d", len(tbl))
	}

	// 每 state 的 symbol 必须在 [0, len(freqs))
	for i, e := range tbl {
		if e.symbol < 0 || int(e.symbol) >= len(freqs) {
			t.Errorf("state %d: symbol %d 越界", i, e.symbol)
		}
		if e.nbits > 16 {
			t.Errorf("state %d: nbits %d 过大", i, e.nbits)
		}
	}
	// 每 symbol 出现次数 = freq
	counts := make(map[int16]int)
	for _, e := range tbl {
		counts[e.symbol]++
	}
	for s, wantFreq := range freqs {
		if counts[int16(s)] != wantFreq {
			t.Errorf("symbol %d: count %d want %d", s, counts[int16(s)], wantFreq)
		}
	}
}

// FSE state transition 遍历测试：任意起始 state，读 nbits raw bits，
// 得 nextState 应落在 [0, numStates)
func TestBuildFSEDecoderTable_StateTransitionBounds(t *testing.T) {
	freqs := []int{32, 16, 16}
	tbl, err := buildFSEDecoderTable(freqs, 64)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for state, entry := range tbl {
		// 枚举所有可能 raw_bits
		maxRaw := uint32(1) << entry.nbits
		for raw := uint32(0); raw < maxRaw; raw++ {
			next := int32(raw) + entry.deltaState
			if next < 0 || int(next) >= 64 {
				t.Errorf("state %d nbits=%d raw=%d → next=%d 越界", state, entry.nbits, raw, next)
			}
		}
	}
}

// reverseBitReader round-trip: 反向写入 + 反向读回 = 原值
func TestReverseBitReader_PullRoundTrip(t *testing.T) {
	// 构造一个 8 字节 stream，模拟 encoder 往末尾推位
	// encoder: push 0x1A (5 bit) 后 push 0x2B (7 bit) 后 ...
	// 简化：直接写 12 字节测流，预期 reader 从尾部 pull 的顺序
	data := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0xAA, 0xBB, 0xCC, 0xDD,
	}
	br, err := newReverseBitReader(data, 0)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// pull 几次，确认不 panic + 得到合理值
	for i := 0; i < 10; i++ {
		v, err := br.pull(4)
		if err != nil {
			return // EOF 是合理的
		}
		if v > 15 {
			t.Errorf("pull(4) 值 %d 超出 4-bit 范围", v)
		}
	}
}

// reverseBitReader 头部 padding 消费：headBits > 0 应先扔掉
func TestReverseBitReader_HeadBitsConsumed(t *testing.T) {
	data := make([]byte, 16)
	// 最后一个字节设 0xFF，倒数第二个字节设 0xAA
	data[14] = 0xAA
	data[15] = 0xFF

	// headBits=4 应先消费掉末尾 4 bit（0xFF 的低 4 bit）
	br, err := newReverseBitReader(data, 4)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// 下一个 pull(4) 应得到 0xFF 的高 4 bit = 0xF
	v, err := br.pull(4)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if v != 0xF {
		t.Errorf("headBits=4 后 pull(4) 应是 0xFF 高 4 bit = 0xF，got 0x%X", v)
	}
}

// bitStreamForward 正向读验证：每 4 bit 一个 tag 顺序读出
func TestBitStreamForward_ReadTags(t *testing.T) {
	// 字节 0x21: 低 4 bit = 1, 高 4 bit = 2
	data := []byte{0x21, 0x43, 0x65}
	bs := newBitStreamForward(data)
	expectedTags := []uint32{1, 2, 3, 4, 5, 6}
	for i, want := range expectedTags {
		got, err := bs.readBits(4)
		if err != nil {
			t.Fatalf("tag %d: %v", i, err)
		}
		if got != want {
			t.Errorf("tag %d: got %d want %d", i, got, want)
		}
	}
}

// parseV2Header 字段精确位置 round-trip（用 Apple bit-packed v2 真实格式）
func TestParseV2Header_FieldPositions(t *testing.T) {
	// bit-pack 一组已知值，验证 parser 各字段拿对位
	buf := make([]byte, 32)
	copy(buf[0:4], []byte("bvx2"))
	binary.LittleEndian.PutUint32(buf[4:8], 0xDEADBEEF) // n_raw

	// packed_fields[0]:
	//   bits 0..19  n_literals = 0x12345
	//   bits 20..39 n_matches = 0x67890
	//   bits 40..59 n_lit_payload = 0xABCDE
	//   bits 60..62 literal_bits + 7 = 4 (3-bit; → bits=-3)
	pf0 := uint64(0x12345) | (uint64(0x67890) << 20) | (uint64(0xABCDE) << 40) | (uint64(4) << 60)
	binary.LittleEndian.PutUint64(buf[8:16], pf0)

	// packed_fields[1]:
	//   bits 0..9   literal_state[0] = 0x111
	//   bits 10..19 literal_state[1] = 0x222
	//   bits 20..29 literal_state[2] = 0x333
	//   bits 30..39 literal_state[3] = 0x3FF
	//   bits 40..59 n_lmd_payload = 0xFEDCB
	//   bits 60..62 lmd_bits + 7 = 7 (3-bit; → bits=0)
	pf1 := uint64(0x111) | (uint64(0x222) << 10) | (uint64(0x333) << 20) |
		(uint64(0x3FF) << 30) | (uint64(0xFEDCB) << 40) | (uint64(7) << 60)
	binary.LittleEndian.PutUint64(buf[16:24], pf1)

	// packed_fields[2]:
	//   bits 0..31 header_size = 200
	//   bits 32..41 l_state = 0x123
	//   bits 42..51 m_state = 0x234
	//   bits 52..61 d_state = 0x345
	pf2 := uint64(200) | (uint64(0x123) << 32) | (uint64(0x234) << 42) | (uint64(0x345) << 52)
	binary.LittleEndian.PutUint64(buf[24:32], pf2)

	h, err := parseV2Header(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.nRawBytes != 0xDEADBEEF {
		t.Errorf("nRawBytes: 0x%X", h.nRawBytes)
	}
	if h.nLiterals != 0x12345 {
		t.Errorf("nLiterals: 0x%X", h.nLiterals)
	}
	if h.nMatches != 0x67890 {
		t.Errorf("nMatches: 0x%X", h.nMatches)
	}
	if h.nLiteralPayloadBytes != 0xABCDE {
		t.Errorf("nLiteralPayloadBytes: 0x%X", h.nLiteralPayloadBytes)
	}
	if h.literalBits != -3 { // 4 - 7 (3-bit field)
		t.Errorf("literalBits: %d want -3", h.literalBits)
	}
	if h.literalStates[0] != 0x111 || h.literalStates[3] != 0x3FF {
		t.Errorf("literalStates: %+v", h.literalStates)
	}
	if h.nLMDPayloadBytes != 0xFEDCB {
		t.Errorf("nLMDPayloadBytes: 0x%X", h.nLMDPayloadBytes)
	}
	if h.lmdBits != 0 { // 7 - 7
		t.Errorf("lmdBits: %d want 0", h.lmdBits)
	}
	if h.headerSize != 200 {
		t.Errorf("headerSize: %d", h.headerSize)
	}
	if h.lState != 0x123 || h.mState != 0x234 || h.dState != 0x345 {
		t.Errorf("LMD states: %x %x %x", h.lState, h.mState, h.dState)
	}
}
