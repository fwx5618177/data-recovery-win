package netfs

import (
	"bytes"
	"testing"
)

// XDR 是 NFS 客户端的最底层——所有上层 bug 最终都追到 encode/decode 对称性。
// 我们用 "encode → decode 必须 round-trip" 作为基本契约。

func TestXDR_RoundTripUint32(t *testing.T) {
	cases := []uint32{0, 1, 0x7FFFFFFF, 0xFFFFFFFF, 42, 100000}
	for _, v := range cases {
		var w xdrWriter
		w.writeUint32(v)
		r := newXDRReader(w.Bytes())
		got, err := r.readUint32()
		if err != nil {
			t.Fatalf("decode %d: %v", v, err)
		}
		if got != v {
			t.Errorf("uint32 round-trip: wrote %d, read %d", v, got)
		}
	}
}

func TestXDR_RoundTripInt64(t *testing.T) {
	cases := []int64{0, 1, -1, 0x7FFFFFFFFFFFFFFF, -0x8000000000000000}
	for _, v := range cases {
		var w xdrWriter
		w.writeInt64(v)
		r := newXDRReader(w.Bytes())
		got, err := r.readInt64()
		if err != nil {
			t.Fatalf("decode %d: %v", v, err)
		}
		if got != v {
			t.Errorf("int64 round-trip: wrote %d, read %d", v, got)
		}
	}
}

func TestXDR_OpaquePadding(t *testing.T) {
	// XDR opaque 必须 4 字节对齐；3 字节写入应 pad 1 字节
	var w xdrWriter
	w.writeOpaque([]byte{0xAA, 0xBB, 0xCC})
	got := w.Bytes()
	// 4 (len) + 3 (data) + 1 (pad) = 8 字节
	if len(got) != 8 {
		t.Errorf("3字节 opaque 编码应占 8 字节，实际 %d", len(got))
	}
	// Last byte = pad = 0
	if got[7] != 0 {
		t.Errorf("padding 字节应为 0，实际 %x", got[7])
	}
	// 解码还原
	r := newXDRReader(got)
	out, err := r.readOpaque(100)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0xAA, 0xBB, 0xCC}) {
		t.Errorf("opaque round-trip: got %x", out)
	}
}

func TestXDR_StringUTF8(t *testing.T) {
	var w xdrWriter
	w.writeString("中文字符串")
	r := newXDRReader(w.Bytes())
	s, err := r.readString(1024)
	if err != nil {
		t.Fatal(err)
	}
	if s != "中文字符串" {
		t.Errorf("UTF-8 string round-trip 失败: %q", s)
	}
}

func TestXDR_BoolEncoding(t *testing.T) {
	var w xdrWriter
	w.writeBool(true)
	w.writeBool(false)
	r := newXDRReader(w.Bytes())
	t1, _ := r.readBool()
	t2, _ := r.readBool()
	if !t1 || t2 {
		t.Errorf("bool round-trip 失败: got (%v,%v)", t1, t2)
	}
}

func TestXDR_ReadShort(t *testing.T) {
	// 截断数据应返回 io.ErrUnexpectedEOF
	r := newXDRReader([]byte{0x00, 0x00})
	if _, err := r.readUint32(); err == nil {
		t.Errorf("数据截断应返回错误")
	}
}

func TestXDR_OpaqueMaxLenGuard(t *testing.T) {
	// 声称 1GB 的 opaque 必须被拒绝（防止恶意 server OOM）
	var w xdrWriter
	w.writeUint32(1 << 30) // 1G
	// 不写 body；readOpaque 检查长度就该失败
	r := newXDRReader(w.Bytes())
	if _, err := r.readOpaque(1 << 20); err == nil {
		t.Errorf("opaque 长度超过 maxLen 应返回错误")
	}
}

func TestXDR_MultiField(t *testing.T) {
	var w xdrWriter
	w.writeUint32(42)
	w.writeString("hello")
	w.writeInt64(-9999)
	w.writeBool(true)

	r := newXDRReader(w.Bytes())
	if v, _ := r.readUint32(); v != 42 {
		t.Errorf("field 1: got %d", v)
	}
	if s, _ := r.readString(64); s != "hello" {
		t.Errorf("field 2: got %q", s)
	}
	if v, _ := r.readInt64(); v != -9999 {
		t.Errorf("field 3: got %d", v)
	}
	if b, _ := r.readBool(); !b {
		t.Errorf("field 4: got false")
	}
}
