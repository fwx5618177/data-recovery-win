package carver

import (
	"sync/atomic"
	"testing"

	"data-recovery/internal/disk"
)

// countingReader 实现 disk.DiskReader，统计 ReadAt 调用次数。
// 用于证明 bufferBackedReader 真的把 N 次小读 collapse 成 0 次底层 IO。
type countingReader struct {
	data      []byte
	readCount atomic.Int64
}

func (c *countingReader) Open() error          { return nil }
func (c *countingReader) Close() error         { return nil }
func (c *countingReader) Size() (int64, error) { return int64(len(c.data)), nil }
func (c *countingReader) SectorSize() int      { return 512 }
func (c *countingReader) DevicePath() string   { return "counting://" }
func (c *countingReader) ReadAt(b []byte, off int64) (int, error) {
	c.readCount.Add(1)
	if off >= int64(len(c.data)) {
		return 0, nil
	}
	n := copy(b, c.data[off:])
	return n, nil
}

// 编译期断言
var _ disk.DiskReader = (*countingReader)(nil)

// TestBufferBackedReader_ZeroIOWhenInBuffer 核心契约：buffer 命中的 ReadAt
// **完全不调底层**（v2.8.45 的本质 perf fix —— detector 用 chunk 内存数据，
// 零额外 disk IO）。
func TestBufferBackedReader_ZeroIOWhenInBuffer(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	c := &countingReader{data: data}
	// 模拟 worker 拷贝过来的 header buffer（offset=0, 长度 512）
	header := append([]byte(nil), data[:512]...)

	br := newBufferBackedReader(c, 0, header)

	// 100 次 1B 读 + 几次更大读，全部在 buffer 范围内
	for i := 0; i < 100; i++ {
		b := make([]byte, 1)
		n, err := br.ReadAt(b, int64(i%512))
		if err != nil || n != 1 || b[0] != data[i%512] {
			t.Fatalf("ReadAt 失败 i=%d n=%d err=%v val=%d 期望=%d",
				i, n, err, b[0], data[i%512])
		}
	}
	for _, size := range []int{2, 4, 8, 16, 64, 256} {
		b := make([]byte, size)
		n, err := br.ReadAt(b, 0)
		if err != nil || n != size {
			t.Fatalf("ReadAt size=%d 失败 n=%d err=%v", size, n, err)
		}
	}

	if got := c.readCount.Load(); got != 0 {
		t.Errorf("buffer 命中应零底层 IO，实得 %d 次 ReadAt（perf fix 失效）", got)
	}
}

// TestBufferBackedReader_FallthroughOutsideBuffer 超出 buffer 必须 fallback
// 底层 reader —— 不能丢数据。
func TestBufferBackedReader_FallthroughOutsideBuffer(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	c := &countingReader{data: data}
	header := append([]byte(nil), data[:512]...) // buffer 只覆盖前 512B

	br := newBufferBackedReader(c, 0, header)

	// 读 [1000, 1008) 区间 —— 超 buffer → 应触发底层 ReadAt
	c.readCount.Store(0)
	b := make([]byte, 8)
	n, err := br.ReadAt(b, 1000)
	if err != nil || n != 8 {
		t.Fatalf("超 buffer 读失败 n=%d err=%v", n, err)
	}
	if c.readCount.Load() != 1 {
		t.Errorf("超 buffer 读应触发恰好 1 次底层 ReadAt，实得 %d", c.readCount.Load())
	}
	for i := 0; i < 8; i++ {
		if b[i] != data[1000+i] {
			t.Errorf("数据错 i=%d val=%d 期望=%d", i, b[i], data[1000+i])
		}
	}
}

// TestBufferBackedReader_NilBufferFallsThrough buffer=nil（worker 没来得及拷贝）
// 时所有 ReadAt 转发底层 —— 行为等价于原始 reader。
func TestBufferBackedReader_NilBufferFallsThrough(t *testing.T) {
	data := []byte("hello world")
	c := &countingReader{data: data}

	br := newBufferBackedReader(c, 0, nil)

	b := make([]byte, 5)
	n, err := br.ReadAt(b, 0)
	if err != nil {
		t.Errorf("nil buffer fallback 不该出错: %v", err)
	}
	if n != 5 || string(b) != "hello" {
		t.Errorf("nil buffer fallback 数据错: n=%d val=%q", n, b)
	}
	if c.readCount.Load() != 1 {
		t.Errorf("nil buffer 应转发 1 次底层 IO，实得 %d", c.readCount.Load())
	}
}

// TestBufferBackedReader_OffsetNotAtZero buffer 起点不为 0（match 在 chunk 中间）
// 的情况：buffer 表示磁盘 offset [bufferOff, bufferOff+len) 的数据。
func TestBufferBackedReader_OffsetNotAtZero(t *testing.T) {
	// 模拟一个 chunk 起始于磁盘 offset=2000，match 也在 2000，header 拷出 256 字节
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	c := &countingReader{data: data}
	header := append([]byte(nil), data[2000:2000+256]...)

	br := newBufferBackedReader(c, 2000, header)

	// 读 offset=2000 → 命中 buffer
	c.readCount.Store(0)
	b := make([]byte, 4)
	n, err := br.ReadAt(b, 2000)
	if err != nil || n != 4 {
		t.Fatalf("命中 buffer 起点失败 n=%d err=%v", n, err)
	}
	if c.readCount.Load() != 0 {
		t.Errorf("命中 buffer 不该走底层，实得 %d 次", c.readCount.Load())
	}
	for i := 0; i < 4; i++ {
		if b[i] != data[2000+i] {
			t.Errorf("数据错 i=%d", i)
		}
	}

	// 读 offset=2255 (buffer 最后 1 字节起 + 越界 1 字节) → 不完整命中 → fallback
	c.readCount.Store(0)
	b = make([]byte, 2)
	n, err = br.ReadAt(b, 2255)
	if err != nil || n != 2 {
		t.Fatalf("跨 buffer 末尾失败 n=%d err=%v", n, err)
	}
	if c.readCount.Load() == 0 {
		t.Errorf("跨 buffer 末尾应 fallback，实得 0 次底层 IO")
	}
}

// TestBufferBackedReader_ForwardsLifecycle Open/Close/Size/SectorSize/DevicePath
// 都得转发到底层。
func TestBufferBackedReader_ForwardsLifecycle(t *testing.T) {
	c := &countingReader{data: []byte("hello world")}
	br := newBufferBackedReader(c, 0, []byte("hel"))

	if br.SectorSize() != 512 {
		t.Errorf("SectorSize 转发错")
	}
	if br.DevicePath() != "counting://" {
		t.Errorf("DevicePath 转发错")
	}
	if sz, _ := br.Size(); sz != 11 {
		t.Errorf("Size 转发错: %d", sz)
	}
	if err := br.Open(); err != nil {
		t.Errorf("Open 转发错: %v", err)
	}
	if err := br.Close(); err != nil {
		t.Errorf("Close 转发错: %v", err)
	}
}
