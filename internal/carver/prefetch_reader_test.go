package carver

import (
	"sync/atomic"
	"testing"

	"data-recovery/internal/disk"
)

// countingReader 实现 disk.DiskReader，统计 ReadAt 调用次数。
// 用于证明 prefetchReader 真的把 N 次小读 collapse 成 1 次大读。
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

// TestPrefetchReader_CollapsesSmallReads 核心契约：100 次 1 字节 ReadAt
// 在 prefetch 窗口内应该只触发底层 1 次 ReadAt（预读那一次）。
// 这是 v2.8.43 的本质 perf fix —— detector 单字节扫 JPEG marker 不再寻道 100 次。
func TestPrefetchReader_CollapsesSmallReads(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	c := &countingReader{data: data}

	pr := newPrefetchReader(c, 0, 512)
	// 预读那一次已经发生
	beforeCount := c.readCount.Load()
	if beforeCount != 1 {
		t.Fatalf("构造时应有 1 次底层 ReadAt（预读），实得 %d", beforeCount)
	}

	// 在 [0, 512) 范围里读 100 次单字节
	for i := 0; i < 100; i++ {
		b := make([]byte, 1)
		n, err := pr.ReadAt(b, int64(i%512))
		if err != nil || n != 1 {
			t.Fatalf("ReadAt 失败 i=%d n=%d err=%v", i, n, err)
		}
		if b[0] != data[i%512] {
			t.Errorf("ReadAt 数据错 i=%d 期望 %d 得 %d", i, data[i%512], b[0])
		}
	}
	// 100 次都命中 cache，底层不应再被调用
	afterCount := c.readCount.Load()
	if afterCount != beforeCount {
		t.Errorf("cache 命中 100 次后底层应仍是 %d 次 ReadAt，实得 %d（每次都穿透 cache，perf fix 失效）",
			beforeCount, afterCount)
	}
}

// TestPrefetchReader_FallthroughOutsideCache 超出 cache 窗口的 ReadAt 必须
// fallback 到底层（不能丢数据）。
func TestPrefetchReader_FallthroughOutsideCache(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	c := &countingReader{data: data}

	pr := newPrefetchReader(c, 0, 512) // 只 cache 前 512 字节

	// 读 [1000, 1008) 区间 —— 超出 cache → 应触发底层 ReadAt
	c.readCount.Store(1) // 重置（构造时 +1）
	b := make([]byte, 8)
	n, err := pr.ReadAt(b, 1000)
	if err != nil || n != 8 {
		t.Fatalf("超 cache 读 err=%v n=%d", err, n)
	}
	if c.readCount.Load() != 2 {
		t.Errorf("超 cache 读应触发 +1 底层 ReadAt，实得 %d", c.readCount.Load())
	}
	for i := 0; i < 8; i++ {
		if b[i] != data[1000+i] {
			t.Errorf("数据错 i=%d", i)
		}
	}
}

// TestPrefetchReader_EmptyCache 底层一字节都读不到时（offset 越界 / IO 错）,
// wrapper 退化成无 cache 模式，所有 ReadAt 转发底层 —— 不能 panic / 丢数据。
func TestPrefetchReader_EmptyCache(t *testing.T) {
	c := &countingReader{data: nil}
	pr := newPrefetchReader(c, 0, 512)
	if pr.cache != nil {
		t.Errorf("底层无数据时 cache 应为 nil，实得 %d 字节", len(pr.cache))
	}
	// ReadAt 应安全转发
	b := make([]byte, 4)
	n, err := pr.ReadAt(b, 0)
	if err != nil {
		t.Errorf("无 cache fallback 不该出错: %v", err)
	}
	if n != 0 {
		t.Errorf("空数据 read 应得 0 字节，实得 %d", n)
	}
}

// TestPrefetchReader_ForwardsLifecycle Open/Close/Size/SectorSize/DevicePath
// 都得转发到底层。
func TestPrefetchReader_ForwardsLifecycle(t *testing.T) {
	c := &countingReader{data: []byte("hello world")}
	pr := newPrefetchReader(c, 0, 16)

	if pr.SectorSize() != 512 {
		t.Errorf("SectorSize 转发错")
	}
	if pr.DevicePath() != "counting://" {
		t.Errorf("DevicePath 转发错")
	}
	if sz, _ := pr.Size(); sz != int64(len("hello world")) {
		t.Errorf("Size 转发错: %d", sz)
	}
	if err := pr.Open(); err != nil {
		t.Errorf("Open 应转发成功: %v", err)
	}
	if err := pr.Close(); err != nil {
		t.Errorf("Close 应转发成功: %v", err)
	}
}
