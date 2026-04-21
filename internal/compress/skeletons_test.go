package compress

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"
)

func TestParseDecmpfsHeader(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(buf[4:8], 3) // type=3 zlib
	binary.LittleEndian.PutUint64(buf[8:16], 1024)
	hdr, err := ParseDecmpfsHeader(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if hdr.Type != 3 || hdr.RawSize != 1024 {
		t.Errorf("hdr=%+v", hdr)
	}
}

func TestDecompressDecmpfsInline_Zlib(t *testing.T) {
	// 构造 type=3 zlib inline
	plain := []byte("hello world hello world hello world")
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	zw.Write(plain)
	zw.Close()

	buf := make([]byte, 16+zbuf.Len())
	binary.LittleEndian.PutUint32(buf[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(buf[4:8], 3)
	binary.LittleEndian.PutUint64(buf[8:16], uint64(len(plain)))
	copy(buf[16:], zbuf.Bytes())

	got, err := DecompressDecmpfsInline(buf)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("不一致:\n  got  %q\n  want %q", got, plain)
	}
}

func TestDecompressDecmpfsInline_LZVNUnsupported(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], decmpfsMagic)
	binary.LittleEndian.PutUint32(buf[4:8], 7) // LZVN
	_, err := DecompressDecmpfsInline(buf)
	if err == nil {
		t.Error("LZVN 应返回 ErrUnsupported")
	}
}

// WIM header 识别 + 压缩类型判断
func TestParseWIMHeader(t *testing.T) {
	buf := make([]byte, 0x20)
	copy(buf[0:8], []byte("MSWIM\x00\x00\x00"))
	// header_size=208, version=1, flags=0x40000 (LZX), chunk_size=0x8000
	binary.LittleEndian.PutUint32(buf[8:12], 208)
	binary.LittleEndian.PutUint32(buf[12:16], 0x00010D00)
	binary.LittleEndian.PutUint32(buf[16:20], 0x40000)
	binary.LittleEndian.PutUint32(buf[20:24], 0x8000)
	h, err := ParseWIMHeader(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.Compression != "LZX" || h.ChunkSize != 0x8000 {
		t.Errorf("hdr=%+v", h)
	}
}

func TestIsLZXCompact(t *testing.T) {
	good := []byte{'M', 'S', 'W', 'I', 'M', 0, 0, 0}
	if !IsLZXCompact(good) {
		t.Error("应识别 MSWIM")
	}
	if IsLZXCompact([]byte("XXXX")) {
		t.Error("不该识别 random")
	}
}
