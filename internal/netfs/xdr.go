package netfs

// ============================================================================
// XDR (External Data Representation, RFC 4506) 最小编解码器
//
// ONC RPC 在 wire 上传什么都是 XDR：
//   - 定长 int32/uint32 (4 bytes, big-endian)
//   - 定长 int64/uint64 (8 bytes, big-endian)
//   - bool = int32(0/1)
//   - opaque/string = length(4) + bytes + pad(0..3 使长度 4 字节对齐)
//   - variable-length array = count(4) + item[0..count]
//
// 为什么不用第三方 XDR 库：XDR 太简单（整个文件 <120 行），引依赖反而增加
// supply-chain 风险，尤其对一个会处理法律证据的工具。
// ============================================================================

import (
	"encoding/binary"
	"fmt"
	"io"
)

// xdrWriter 轻量 XDR 编码器，底层是 bytes slice。
// 没用 bytes.Buffer 是为了避免 Write 接口的 error 路径 —— 内存 append 不会失败。
type xdrWriter struct {
	buf []byte
}

func (w *xdrWriter) writeUint32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *xdrWriter) writeBool(v bool) {
	if v {
		w.writeUint32(1)
	} else {
		w.writeUint32(0)
	}
}

func (w *xdrWriter) writeUint64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.buf = append(w.buf, b[:]...)
}

func (w *xdrWriter) writeInt64(v int64) { w.writeUint64(uint64(v)) }

// writeOpaque 写一段变长字节数据（带 4 字节长度前缀 + 4 字节对齐的填充 0）。
// NFS 的 filehandle / data payload / 所有字符串都走这里。
func (w *xdrWriter) writeOpaque(b []byte) {
	w.writeUint32(uint32(len(b)))
	w.buf = append(w.buf, b...)
	// 4 字节对齐 padding
	if pad := (4 - len(b)%4) % 4; pad > 0 {
		w.buf = append(w.buf, make([]byte, pad)...)
	}
}

// writeString XDR string ≡ opaque（RFC 4506 §4.11）
func (w *xdrWriter) writeString(s string) { w.writeOpaque([]byte(s)) }

// Bytes 返回当前缓冲区（不拷贝；调用方知道用完即丢）。
func (w *xdrWriter) Bytes() []byte { return w.buf }

// ----------------------------------------------------------------------------

// xdrReader 轻量 XDR 解码器。
type xdrReader struct {
	buf []byte
	pos int
}

func newXDRReader(buf []byte) *xdrReader { return &xdrReader{buf: buf} }

// remaining 返回未消费的字节数（调试用）。
func (r *xdrReader) remaining() int { return len(r.buf) - r.pos }

func (r *xdrReader) readUint32() (uint32, error) {
	if r.pos+4 > len(r.buf) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

func (r *xdrReader) readBool() (bool, error) {
	v, err := r.readUint32()
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

func (r *xdrReader) readUint64() (uint64, error) {
	if r.pos+8 > len(r.buf) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

func (r *xdrReader) readInt64() (int64, error) {
	v, err := r.readUint64()
	return int64(v), err
}

// readOpaque 读变长字节数据。maxLen 是防御性上限（0=不限），避免恶意 server
// 发一个声称有 4GB 的 opaque 让我们 OOM。
func (r *xdrReader) readOpaque(maxLen int) ([]byte, error) {
	n, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if maxLen > 0 && int(n) > maxLen {
		return nil, fmt.Errorf("opaque 长度超限: %d > %d", n, maxLen)
	}
	if int(n) > r.remaining() {
		return nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, n)
	copy(data, r.buf[r.pos:r.pos+int(n)])
	r.pos += int(n)
	// 消费 padding
	if pad := (4 - int(n)%4) % 4; pad > 0 {
		if r.pos+pad > len(r.buf) {
			return nil, io.ErrUnexpectedEOF
		}
		r.pos += pad
	}
	return data, nil
}

// readString 语义等同 opaque。默认限制 1MB，NFS 文件名最多 255 字节，export 路径最多 1024。
func (r *xdrReader) readString(maxLen int) (string, error) {
	if maxLen == 0 {
		maxLen = 1024 * 1024
	}
	b, err := r.readOpaque(maxLen)
	return string(b), err
}

// skip 跳过 n 字节（XDR 结构里遇到未感兴趣的变体时用）。
func (r *xdrReader) skip(n int) error {
	if r.pos+n > len(r.buf) {
		return io.ErrUnexpectedEOF
	}
	r.pos += n
	return nil
}
