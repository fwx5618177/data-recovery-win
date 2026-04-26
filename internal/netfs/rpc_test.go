package netfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// RPC record 层的 fragment 处理逻辑单独测；对端 wire 协议交给集成测试。

func TestReadFullRecord_SingleFragment(t *testing.T) {
	// 一个 last-fragment bit=1 + body "hello"
	var buf bytes.Buffer
	var hdr [4]byte
	body := []byte("hello")
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body))|0x80000000)
	buf.Write(hdr[:])
	buf.Write(body)

	got, err := readFullRecord(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("want %q got %q", body, got)
	}
}

func TestReadFullRecord_MultipleFragments(t *testing.T) {
	// 分成两段：第一段不带 last bit；第二段带
	var buf bytes.Buffer
	writeFragment := func(body []byte, last bool) {
		var hdr [4]byte
		v := uint32(len(body))
		if last {
			v |= 0x80000000
		}
		binary.BigEndian.PutUint32(hdr[:], v)
		buf.Write(hdr[:])
		buf.Write(body)
	}
	writeFragment([]byte("foo "), false)
	writeFragment([]byte("bar "), false)
	writeFragment([]byte("baz"), true)

	got, err := readFullRecord(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "foo bar baz" {
		t.Errorf("multi-fragment assembly: got %q", got)
	}
}

func TestReadFullRecord_TruncatedHeader(t *testing.T) {
	buf := bytes.NewReader([]byte{0x80, 0x00}) // 只写 2 字节
	_, err := readFullRecord(buf)
	if err == nil {
		t.Errorf("截断 header 应返回错误")
	}
}

func TestReadFullRecord_TruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(100)|0x80000000) // 声称 100 字节
	buf.Write(hdr[:])
	buf.Write([]byte("short"))

	_, err := readFullRecord(&buf)
	if err == nil {
		t.Errorf("截断 body 应返回错误")
	}
}

func TestReadFullRecord_OversizedFragment(t *testing.T) {
	var hdr [4]byte
	// 声称 10MB，超过 8MB 单 fragment 上限
	binary.BigEndian.PutUint32(hdr[:], uint32(10*1024*1024)|0x80000000)
	_, err := readFullRecord(bytes.NewReader(hdr[:]))
	if err == nil {
		t.Errorf("单 fragment 超上限应返回错误")
	}
}

// ----- fake reader 用来避免碰网络 -----

type errorReader struct{ err error }

func (r *errorReader) Read(p []byte) (int, error) { return 0, r.err }

func TestReadFullRecord_NetworkError(t *testing.T) {
	_, err := readFullRecord(&errorReader{err: io.ErrUnexpectedEOF})
	if err == nil {
		t.Errorf("网络读错误应透传出去")
	}
}
