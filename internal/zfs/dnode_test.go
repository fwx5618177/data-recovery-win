package zfs

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// TestLZ4RawDecompress 用手工构造的 LZ4 block 验证解压器正确性
// LZ4 block format:
//
//	token: upper 4 bits = literal len, lower 4 bits = match len - 4
//	literals 跟在 token 后
//	match offset (2 bytes LE) 跟在 literal 之后
func TestLZ4RawDecompress_LiteralsOnly(t *testing.T) {
	// 3 个 literal，无 match
	// token = 0x30 = 3 literal len, 0 match len
	src := []byte{0x30, 'A', 'B', 'C'}
	dst := make([]byte, 10)
	n, err := lz4RawDecompress(src, dst)
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	if !bytes.Equal(dst[:n], []byte("ABC")) {
		t.Errorf("got %q want %q", dst[:n], "ABC")
	}
}

func TestLZ4RawDecompress_WithMatch(t *testing.T) {
	// 编码 "ABCABC"：前 3 字节 literal，后 3 字节 match (offset=3, len=3+4=7 太多)
	// 实际 LZ4 MINMATCH=4，我们做 "ABCDABCD"
	// token: 4 literals ("ABCD") + match (offset=4, len=0 means 0+4=4 bytes)
	src := []byte{
		0x40, // 4 literals, match_len_code = 0 → len=4
		'A', 'B', 'C', 'D',
		0x04, 0x00, // match offset = 4
	}
	dst := make([]byte, 16)
	n, err := lz4RawDecompress(src, dst)
	if err != nil {
		t.Fatalf("解压: %v", err)
	}
	if !bytes.Equal(dst[:n], []byte("ABCDABCD")) {
		t.Errorf("got %q want ABCDABCD", dst[:n])
	}
}

func TestLZ4RawDecompress_OverlappingMatch(t *testing.T) {
	// "AAAAAAA"：literal=1 ("A")，然后 match offset=1 len=6 (overlap)
	// token: 1 literal, match_len_code = 2 (→ 2+4=6)
	src := []byte{
		0x12, // 1 literal, match_len_code = 2
		'A',
		0x01, 0x00, // offset = 1
	}
	dst := make([]byte, 16)
	n, err := lz4RawDecompress(src, dst)
	if err != nil {
		t.Fatalf("解压 overlap: %v", err)
	}
	want := []byte("AAAAAAA")
	if !bytes.Equal(dst[:n], want) {
		t.Errorf("overlap got %q want %q", dst[:n], want)
	}
}

func TestLZ4Decompress_WithHeader(t *testing.T) {
	// ZFS LZ4 封装：前 4 字节 big-endian 是 compressed size
	body := []byte{0x30, 'X', 'Y', 'Z'}
	full := make([]byte, 0, 4+len(body))
	hdrBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(hdrBuf, uint32(len(body)))
	full = append(full, hdrBuf...)
	full = append(full, body...)

	dst := make([]byte, 8)
	n, err := lz4Decompress(full, dst)
	if err != nil {
		t.Fatalf("头封装: %v", err)
	}
	if !bytes.Equal(dst[:n], []byte("XYZ")) {
		t.Errorf("header decomp got %q", dst[:n])
	}
}

// ZAP micro round-trip test
func TestParseZAPMicro(t *testing.T) {
	block := make([]byte, 4096)
	// header: block_type = 0x800000000000000F
	binary.LittleEndian.PutUint64(block[0:8], 0x800000000000000F)
	// entry 1 at offset 64
	binary.LittleEndian.PutUint64(block[64:72], 12345) // value
	binary.LittleEndian.PutUint32(block[72:76], 7)     // cd
	copy(block[78:], []byte("hello.txt\x00"))

	entries, err := ParseZAPMicro(block)
	if err != nil {
		t.Fatalf("解析: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("应有 entry")
	}
	if entries[0].Name != "hello.txt" || entries[0].Value != 12345 || entries[0].CD != 7 {
		t.Errorf("entry 不对: %+v", entries[0])
	}
}

// ZSTD round-trip：用真实 zstd encoder 压 → 我们的 decoder 解 → 对比
func TestZSTDDecompress_RoundTrip(t *testing.T) {
	plain := []byte("The quick brown fox jumps over the lazy dog. Repeat: ABCABCABCABC")
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}
	encoded := enc.EncodeAll(plain, nil)
	enc.Close()

	// 模拟 ZFS 8 字节封装（c_len BE + 4 字节 padding）
	wrapped := make([]byte, 8+len(encoded))
	binary.BigEndian.PutUint32(wrapped[0:4], uint32(len(encoded)))
	copy(wrapped[8:], encoded)

	out, err := zstdDecompress(wrapped, len(plain))
	if err != nil {
		t.Fatalf("解压: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Errorf("round-trip 不等:\n got %q\nwant %q", out, plain)
	}
}

// Dnode 解析 round-trip test
func TestParseDnode(t *testing.T) {
	buf := make([]byte, 512)
	buf[0] = dmuOtPlainFile
	buf[1] = 17                                     // ind_blk_shift
	buf[2] = 1                                      // nlevels
	buf[3] = 1                                      // nblkptr
	buf[8], buf[9] = 2, 0                           // datablkszsec = 2 (1KB)
	binary.LittleEndian.PutUint64(buf[16:24], 100)  // maxblkid
	binary.LittleEndian.PutUint64(buf[24:32], 4096) // used

	// 单一 blkptr @ offset 64
	// DVA[0]: word0 = (vdev<<32) | asize
	binary.LittleEndian.PutUint64(buf[64:72], (uint64(2)<<32)|0x100)
	binary.LittleEndian.PutUint64(buf[72:80], 0x1234)

	d, err := ParseDnode(buf)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if d.Type != dmuOtPlainFile {
		t.Errorf("type: %d", d.Type)
	}
	if d.DataBlockSize() != 1024 {
		t.Errorf("blksize: %d", d.DataBlockSize())
	}
	if len(d.BlkPtrs) != 1 {
		t.Fatalf("blkptrs: %d", len(d.BlkPtrs))
	}
	if d.BlkPtrs[0].DVAs[0].VDev != 2 {
		t.Errorf("vdev: %d", d.BlkPtrs[0].DVAs[0].VDev)
	}
}
