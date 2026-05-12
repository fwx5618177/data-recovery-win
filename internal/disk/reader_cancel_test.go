package disk

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestImageReader_CancelPoisonsFutureReads 回归 v2.8.22 修复：
// Cancel 后 ReadAt 必须立刻 fail，让 carver Collector / per-format detector 等
// "没 ctx 的 read 循环"瞬间收摊。
//
// 之前的实现：windowsReader.Cancel 只调 CancelIoEx，仅取消"当下那一个" pending
// ReadFile，handle 留着；imageFileReader.Cancel 已经 close handle 所以镜像扫描
// OK，但平台扫描（NVMe 系统盘）的 collector 在 Stop 后还能持续读盘几十秒。
//
// 镜像 reader 的 Cancel 路径之前就走 close，仍然回归一遍：确保"Cancel 之后再读"
// 不会因为某次重构忘了 close 句柄而退化。
func TestImageReader_CancelPoisonsFutureReads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cancel.img")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatalf("写测试文件: %v", err)
	}

	r := NewReader(path)
	if err := r.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()

	// 先正常读一发，确认 baseline 正常
	buf := make([]byte, 4096)
	if _, err := r.ReadAt(buf, 0); err != nil {
		t.Fatalf("baseline ReadAt: %v", err)
	}

	// Cancel
	c, ok := r.(Canceller)
	if !ok {
		t.Fatal("image reader 应该实现 Canceller 接口")
	}
	if err := c.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	// Cancel 之后的 ReadAt 必须 fail（不能再返回数据）
	if _, err := r.ReadAt(buf, 0); err == nil {
		t.Fatal("Cancel 后 ReadAt 仍然成功 —— 漏掉毒化语义，Stop 后扫描会继续读盘")
	}
}

// mockCancellableReader 仿照真实 windowsReader 的 cancel 语义：
//   - 普通 ReadAt 工作
//   - Cancel 后所有 ReadAt 立刻返回 ErrReaderCancelled
//
// 用来跨平台测 disk 包以外的 reader 链（ResilientReader / DecryptingReader 等）
// 是否正确透传 Cancel。
type mockCancellableReader struct {
	mu          sync.Mutex
	data        []byte
	sectorSize  int
	devicePath  string
	cancelled   atomic.Bool
	readCount   atomic.Int64 // 真正打到 backend 的读次数
}

func newMockCancellableReader(size int, sectorSize int) *mockCancellableReader {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	return &mockCancellableReader{
		data:       data,
		sectorSize: sectorSize,
		devicePath: "mock://cancellable",
	}
}

func (m *mockCancellableReader) Open() error  { return nil }
func (m *mockCancellableReader) Close() error { return nil }
func (m *mockCancellableReader) ReadAt(buf []byte, offset int64) (int, error) {
	if m.cancelled.Load() {
		return 0, ErrReaderCancelled
	}
	m.readCount.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if offset < 0 || offset >= int64(len(m.data)) {
		return 0, errors.New("offset 越界")
	}
	n := copy(buf, m.data[offset:])
	return n, nil
}
func (m *mockCancellableReader) Size() (int64, error) { return int64(len(m.data)), nil }
func (m *mockCancellableReader) SectorSize() int      { return m.sectorSize }
func (m *mockCancellableReader) DevicePath() string   { return m.devicePath }
func (m *mockCancellableReader) Cancel() error {
	m.cancelled.Store(true)
	return nil
}

// TestResilientReader_CancelPropagates 验证 ResilientReader → underlying 的 Cancel 链。
func TestResilientReader_CancelPropagates(t *testing.T) {
	mock := newMockCancellableReader(1<<20, 512)
	rr := NewResilientReader(mock, 512, 1)

	// 先读一发
	buf := make([]byte, 4096)
	if _, err := rr.ReadAt(buf, 0); err != nil {
		t.Fatalf("baseline ReadAt: %v", err)
	}
	baseline := mock.readCount.Load()

	// Cancel ResilientReader → 应该透传到 mock
	if err := rr.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if !mock.cancelled.Load() {
		t.Fatal("ResilientReader.Cancel 没透传到底层")
	}

	// Cancel 之后 ResilientReader.ReadAt 应该快速失败（不应该再有大量打到底层的读）。
	// ResilientReader 的 readWithRetry 会逐扇区试一遍，但每个 sector 读都立刻
	// fail（mock 返回 ErrReaderCancelled），整个 4KB 范围最多 8 个 sector 试探 + 跳过模式。
	// 这远比"成功读 4KB 然后继续下一个 chunk"轻量。
	_, _ = rr.ReadAt(buf, 8192) // 不关心结果，关心读次数
	afterCancel := mock.readCount.Load()
	if delta := afterCancel - baseline; delta > 16 {
		t.Errorf("Cancel 后 ReadAt 仍触发 %d 次底层读 —— 期望 ≤16 (readWithRetry sector 扇区扫描上限)", delta)
	}
}

// TestResilientReader_CancelStopsReadLoop 模拟一个"没 ctx 的紧密 read 循环"，
// Cancel 后必须在很短时间内停止（fast-fail 让循环自然退）。
// 这就是 carver Collector 的场景。
func TestResilientReader_CancelStopsReadLoop(t *testing.T) {
	mock := newMockCancellableReader(1<<24, 512) // 16MB
	rr := NewResilientReader(mock, 512, 1)

	var loopReads atomic.Int64
	done := make(chan struct{})

	// 模拟 Collector：紧密读循环，不带 ctx，靠 error 退出
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for offset := int64(0); offset < 1<<24; offset += 4096 {
			n, err := rr.ReadAt(buf, offset)
			loopReads.Add(1)
			if err != nil && n == 0 {
				// fast-fail 让循环自然退（v2.8.22 设计）
				return
			}
		}
	}()

	// 让循环先跑一会儿
	time.Sleep(20 * time.Millisecond)
	beforeCancel := loopReads.Load()
	if beforeCancel == 0 {
		t.Fatal("循环没启动起来 —— 测试设置有问题")
	}

	// Cancel
	if err := rr.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	// 必须很快退（Cancel + fast-fail + ResilientReader 的 retry 也快）
	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Cancel 后 2 秒内循环没退出 —— fast-fail 没生效，回归 v2.8.20 的 bug")
	}
}
