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

func TestIsLZXCompact(t *testing.T) {
	good := []byte{'M', 'S', 'W', 'I', 'M', 0, 0, 0}
	if !IsLZXCompact(good) {
		t.Error("应识别 MSWIM")
	}
	if IsLZXCompact([]byte("XXXX")) {
		t.Error("不该识别 random")
	}
}
