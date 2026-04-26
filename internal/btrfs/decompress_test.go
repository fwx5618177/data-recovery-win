package btrfs

import (
	"bytes"
	"compress/zlib"
	"errors"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestDecompressExtent_NoneJustSlices(t *testing.T) {
	src := []byte("HelloWorldThisIsBtrfs")
	// offset 5 长度 5 = "World"
	got, err := DecompressExtent(src, BTRFS_COMPRESSION_NONE, 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "World" {
		t.Errorf("None-compression slice got %q want World", got)
	}
}

func TestDecompressExtent_Zlib(t *testing.T) {
	plain := []byte("the quick brown fox jumps over the lazy dog")
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(plain)
	w.Close()

	got, err := DecompressExtent(buf.Bytes(), BTRFS_COMPRESSION_ZLIB, uint64(len(plain)), 0)
	if err != nil {
		t.Fatalf("zlib decompress: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("zlib round-trip 不一致:\n  got %q\n  want %q", got, plain)
	}
}

// 测 ExtentOffset 切片：解压全 1KB，但只取 [200, 300)
func TestDecompressExtent_ZlibWithOffset(t *testing.T) {
	plain := bytes.Repeat([]byte("ABCD"), 256) // 1024 字节
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(plain)
	w.Close()

	got, err := DecompressExtent(buf.Bytes(), BTRFS_COMPRESSION_ZLIB, 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain[200:300]) {
		t.Errorf("Offset 切片错")
	}
}

func TestDecompressExtent_Zstd(t *testing.T) {
	plain := bytes.Repeat([]byte("zstd_repeating_pattern_"), 100)
	enc, _ := zstd.NewWriter(nil)
	encoded := enc.EncodeAll(plain, nil)
	enc.Close()

	got, err := DecompressExtent(encoded, BTRFS_COMPRESSION_ZSTD, uint64(len(plain)), 0)
	if err != nil {
		t.Fatalf("zstd decompress: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("zstd round-trip 不一致 (len got=%d want=%d)", len(got), len(plain))
	}
}

// LZO 当前明确不支持
func TestDecompressExtent_LZOReturnsErr(t *testing.T) {
	_, err := DecompressExtent([]byte("anything"), BTRFS_COMPRESSION_LZO, 100, 0)
	if !errors.Is(err, ErrCompressionUnsupported) {
		t.Errorf("LZO 应返回 ErrCompressionUnsupported, got %v", err)
	}
}

// 损坏的 zlib 流应返回 error 而不是 panic
func TestDecompressExtent_CorruptZlib(t *testing.T) {
	junk := []byte{0x78, 0x9C, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00}
	if _, err := DecompressExtent(junk, BTRFS_COMPRESSION_ZLIB, 100, 0); err == nil {
		t.Errorf("损坏 zlib 流应 error")
	}
}

// 解压结果远超 expectedLen 应被拒（zip-bomb 防御）
func TestDecompressExtent_ZstdBombDefense(t *testing.T) {
	// 构造 1MB 全 0 → zstd 压缩成几十字节；用 expectedLen=10 触发防御
	plain := make([]byte, 1024*1024)
	enc, _ := zstd.NewWriter(nil)
	encoded := enc.EncodeAll(plain, nil)
	enc.Close()

	_, err := DecompressExtent(encoded, BTRFS_COMPRESSION_ZSTD, 10, 0)
	if err == nil {
		t.Errorf("解压结果远大于 expectedLen 应 error")
	}
}
