package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// bvx$ EOS marker 单独一个 block，应直接结束，dst 无输出
func TestDecompressLZFSE_EOSOnly(t *testing.T) {
	src := []byte("bvx$")
	dst := make([]byte, 32)
	n, err := DecompressLZFSE(src, dst)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 0 {
		t.Errorf("EOS 单独 block 应输出 0 字节，得 %d", n)
	}
}

// bvx- 未压缩 block：直接透传
func TestDecompressLZFSE_UncompressedBlock(t *testing.T) {
	payload := []byte("hello world")
	src := []byte{}
	src = append(src, []byte("bvx-")...)
	szRaw := make([]byte, 4)
	binary.LittleEndian.PutUint32(szRaw, uint32(len(payload)))
	src = append(src, szRaw...)
	src = append(src, szRaw...) // n_raw == n_payload for bvx-
	src = append(src, payload...)
	// 紧跟 EOS
	src = append(src, []byte("bvx$")...)

	dst := make([]byte, 64)
	n, err := DecompressLZFSE(src, dst)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(dst[:n], payload) {
		t.Errorf("解出 %q want %q", dst[:n], payload)
	}
}

// bvxn (LZVN) block 套上 LZFSE 容器头
func TestDecompressLZFSE_LZVNBlock(t *testing.T) {
	// 先构造 LZVN payload："ABCD" literals + EOS
	lzvnPayload := []byte{0xE3, 'A', 'B', 'C', 'D', 0x06}
	raw := []byte("ABCD")

	src := []byte{}
	src = append(src, []byte("bvxn")...)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(raw)))
	src = append(src, b...)
	binary.LittleEndian.PutUint32(b, uint32(len(lzvnPayload)))
	src = append(src, b...)
	src = append(src, lzvnPayload...)
	src = append(src, []byte("bvx$")...)

	dst := make([]byte, 64)
	n, err := DecompressLZFSE(src, dst)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(dst[:n], raw) {
		t.Errorf("LZVN 套 bvxn 解出 %q want %q", dst[:n], raw)
	}
}

// bvx2 触发明确的 ErrLZFSEv2Unsupported
func TestDecompressLZFSE_V2Unsupported(t *testing.T) {
	src := []byte("bvx2extra")
	dst := make([]byte, 32)
	_, err := DecompressLZFSE(src, dst)
	if !errors.Is(err, ErrLZFSEv2Unsupported) {
		t.Errorf("应返回 ErrLZFSEv2Unsupported，实际 %v", err)
	}
}
