package ntfs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildUncompressedBlock 造一个标记为"未压缩"的 LZNT1 block，数据原样放。
func buildUncompressedBlock(data []byte) []byte {
	if len(data) == 0 || len(data) > lznt1MaxBlockSize {
		panic("bad data size")
	}
	buf := make([]byte, 2+len(data))
	// header: length=len(data)-1, 未压缩位 = 0
	// NTFS 规范：未压缩 block 头部还是带 signature bits，我们用 0x3000（block size marker）
	header := uint16(len(data)-1) | 0x3000
	binary.LittleEndian.PutUint16(buf[0:2], header)
	copy(buf[2:], data)
	return buf
}

// buildCompressedLiteralsBlock 造一个压缩 block，但所有 token 都是 literal（等于没压缩）。
// 用来测 token 解码逻辑本身，不依赖实际的回指压缩器。
func buildCompressedLiteralsBlock(data []byte) []byte {
	if len(data) == 0 {
		panic("bad data size")
	}
	// 每 8 字节 literal + 1 字节 flag（全 0 表示全 literal）
	var body bytes.Buffer
	for i := 0; i < len(data); i += 8 {
		end := i + 8
		if end > len(data) {
			end = len(data)
		}
		body.WriteByte(0) // 8 个 bit 全 0 = 全 literal
		body.Write(data[i:end])
	}

	blockLen := body.Len()
	buf := make([]byte, 2+blockLen)
	// header: bit 15 = 1（压缩），length = blockLen - 1
	header := uint16(blockLen-1) | 0x8000 | 0x3000
	binary.LittleEndian.PutUint16(buf[0:2], header)
	copy(buf[2:], body.Bytes())
	return buf
}

func TestDecompressLZNT1_UncompressedBlock(t *testing.T) {
	payload := []byte("hello world this is literal")
	block := buildUncompressedBlock(payload)
	got, err := DecompressLZNT1(block)
	if err != nil {
		t.Fatalf("DecompressLZNT1: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("解压结果不匹配:\n  got  %q\n  want %q", got, payload)
	}
}

func TestDecompressLZNT1_CompressedAllLiterals(t *testing.T) {
	// "压缩"但所有 token 都是 literal —— 验证 flag byte / token 逻辑
	payload := []byte("abcdefghijklmnop1234567890")
	block := buildCompressedLiteralsBlock(payload)
	got, err := DecompressLZNT1(block)
	if err != nil {
		t.Fatalf("DecompressLZNT1: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("解压全 literal 的压缩 block 结果错:\n  got  %q\n  want %q", got, payload)
	}
}

func TestDecompressLZNT1_CompressedBackRef(t *testing.T) {
	// 构造："AAAA" 手写压缩：第一个 A 是 literal，随后的 3 个通过 back-ref (offset=1, length=3) 拿到。
	// 已解压 1 字节时，computeOffsetBits(1) = 12，所以 token 里：
	//   offset field 12 bits, length field 4 bits
	//   offset = 1 → encoded = 0（0+1=1）
	//   length = 3 → encoded = 0（0+3=3）
	// token = (0 << 4) | 0 = 0x0000
	var body bytes.Buffer
	body.WriteByte(0b0000_0010) // flag: bit0=literal 'A'; bit1=back-ref token
	body.WriteByte('A')
	binary.Write(&body, binary.LittleEndian, uint16(0x0000))

	blockLen := body.Len()
	buf := make([]byte, 2+blockLen)
	header := uint16(blockLen-1) | 0x8000 | 0x3000
	binary.LittleEndian.PutUint16(buf[0:2], header)
	copy(buf[2:], body.Bytes())

	got, err := DecompressLZNT1(buf)
	if err != nil {
		t.Fatalf("DecompressLZNT1: %v", err)
	}
	want := []byte("AAAA")
	if !bytes.Equal(got, want) {
		t.Errorf("back-ref 解码错:\n  got  %q\n  want %q", got, want)
	}
}

func TestDecompressLZNT1_StopsOnZeroHeader(t *testing.T) {
	// header == 0 是 compression unit 尾部填充标记，应该停止解码不报错
	buf := buildUncompressedBlock([]byte("hello"))
	buf = append(buf, 0x00, 0x00, 0xDE, 0xAD) // 零 header + 垃圾
	got, err := DecompressLZNT1(buf)
	if err != nil {
		t.Fatalf("遇到零 header 不应报错，实际: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("零 header 后不应继续解码，实际: %q", got)
	}
}

func TestDecompressLZNT1_RejectsOutOfRangeBackRef(t *testing.T) {
	// 构造：第一个 token 就是 back-ref，但已解压 0 字节 → offset 必然越界
	var body bytes.Buffer
	body.WriteByte(0b0000_0001) // flag: bit0 = back-ref token
	binary.Write(&body, binary.LittleEndian, uint16(0x0000))

	blockLen := body.Len()
	buf := make([]byte, 2+blockLen)
	header := uint16(blockLen-1) | 0x8000 | 0x3000
	binary.LittleEndian.PutUint16(buf[0:2], header)
	copy(buf[2:], body.Bytes())

	_, err := DecompressLZNT1(buf)
	if err == nil {
		t.Error("0 字节已解压时的 back-ref 应报错")
	}
}

func TestComputeOffsetBits(t *testing.T) {
	cases := []struct {
		n, want int
	}{
		{0, 12},
		{15, 12},
		{16, 11},
		{31, 11},
		{32, 10},
		{255, 8},
		{256, 7},
		{511, 7},
		{512, 6},
		{2047, 5},
		{2048, 4},
		{4000, 4},
	}
	for _, c := range cases {
		if got := computeOffsetBits(c.n); got != c.want {
			t.Errorf("computeOffsetBits(%d) = %d want %d", c.n, got, c.want)
		}
	}
}
