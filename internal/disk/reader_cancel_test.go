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
	mu         sync.Mutex
	data       []byte
	sectorSize int
	devicePath string
	cancelled  atomic.Bool
	readCount  atomic.Int64 // 真正打到 backend 的读次数
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

// slowCancellableReader 仿真 Windows 真盘 IO：每次 ReadAt 睡 sleepPerRead，
// 模拟真实 NVMe 的 4MB 读 ~1ms 节奏。这样测试代码里"循环跑 1TB"不会因为内存
// 太快而自然跑完 —— 必须靠 Cancel 才能停。这是 v2.8.22 第一版测试漏掉的关键：
// mock 太快 → 1<<24 字节的循环 4ms 跑完，Cancel 还没触发就 done 了。
type slowCancellableReader struct {
	cancelled    atomic.Bool
	sleepPerRead time.Duration
	readCount    atomic.Int64
}

func (m *slowCancellableReader) Open() error  { return nil }
func (m *slowCancellableReader) Close() error { return nil }
func (m *slowCancellableReader) ReadAt(buf []byte, offset int64) (int, error) {
	if m.cancelled.Load() {
		return 0, ErrReaderCancelled
	}
	time.Sleep(m.sleepPerRead) // 模拟真盘 IO 耗时
	m.readCount.Add(1)
	for i := range buf {
		buf[i] = 0xAB // 任意非零数据，保证 ReadAt 看起来"成功"
	}
	return len(buf), nil
}
func (m *slowCancellableReader) Size() (int64, error) { return 1 << 40, nil } // 1TB
func (m *slowCancellableReader) SectorSize() int      { return 512 }
func (m *slowCancellableReader) DevicePath() string   { return "mock://slow" }
func (m *slowCancellableReader) Cancel() error {
	m.cancelled.Store(true)
	return nil
}

var _ Canceller = (*slowCancellableReader)(nil)

// TestResilientReader_CancelStopsReadLoop 回归 v2.8.23 核心 bug：
// 一个"没 ctx 的紧密 read 循环"（carver Collector / format detectors / validateAll）
// 在 Cancel 之后必须**很快**停止，不能继续读盘。
//
// v2.8.22 第一次修复后这个测试用法是 buggy 的（mock 太快循环 4ms 自然跑完）。
// 重写：mock 每读 1ms，循环跑 1TB 自然需要数小时，Cancel 必须真的让循环退。
func TestResilientReader_CancelStopsReadLoop(t *testing.T) {
	mock := &slowCancellableReader{sleepPerRead: 1 * time.Millisecond}
	rr := NewResilientReader(mock, 512, 1)

	done := make(chan struct{})
	// 模拟 Collector / format detector：紧密读循环，不带 ctx，靠 error 退出
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		// 1TB / 4KB ≈ 268M iter；mock 每读 1ms → 自然跑完要 3 天。Cancel 必须能停。
		for offset := int64(0); offset < 1<<40; offset += 4096 {
			_, err := rr.ReadAt(buf, offset)
			if err != nil {
				// fast-fail 让循环自然退（v2.8.23 设计：错误必须穿透到调用者）
				return
			}
		}
	}()

	// 让循环先跑 50ms，确保它真的在转
	time.Sleep(50 * time.Millisecond)
	beforeCancel := mock.readCount.Load()
	if beforeCancel == 0 {
		t.Fatal("循环没启动起来 —— 测试设置有问题")
	}

	// Cancel
	if err := rr.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	// 必须在 2 秒内退出
	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatalf("Cancel 后 2 秒内循环没退出 —— v2.8.20/v2.8.22 bug 复发 (mock 总读次数 %d)", mock.readCount.Load())
	}

	// Cancel 后不应该再有任何成功读
	afterDone := mock.readCount.Load()
	t.Logf("Cancel 前 %d 次读，Cancel 后 stop 时累计 %d 次", beforeCancel, afterDone)
}

// TestResilientReader_PropagatesErrReaderCancelled 验证 ResilientReader 必须
// 把 ErrReaderCancelled **透传**给调用方，不能像 v2.8.22 那样当 bad sector 0-fill +
// 返回 (n, nil)。这是 v2.8.23 的关键修复 —— 否则上层 Collector 等"看 err"决定是否
// 继续的循环就被 mask 了，永远不会停。
func TestResilientReader_PropagatesErrReaderCancelled(t *testing.T) {
	mock := &slowCancellableReader{sleepPerRead: 0}
	rr := NewResilientReader(mock, 512, 1)
	_ = rr.Cancel()

	buf := make([]byte, 4096)
	n, err := rr.ReadAt(buf, 0)
	if !IsCancelled(err) {
		t.Fatalf("ResilientReader.ReadAt 必须把 ErrReaderCancelled 透传，实际 n=%d err=%v", n, err)
	}
}
