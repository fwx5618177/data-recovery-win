package bitlocker

import (
	"errors"
	"sync/atomic"
	"testing"

	"data-recovery/internal/disk"
)

// cancellableMockReader 是一个最小化的、支持 Cancel 的 disk.DiskReader 实现。
// 仅在本测试文件用 —— 验证 DecryptingReader.Cancel 透传到底层。
type cancellableMockReader struct {
	data       []byte
	cancelled  atomic.Bool
	cancelHits atomic.Int64
}

func (m *cancellableMockReader) Open() error  { return nil }
func (m *cancellableMockReader) Close() error { return nil }
func (m *cancellableMockReader) ReadAt(buf []byte, offset int64) (int, error) {
	if m.cancelled.Load() {
		return 0, disk.ErrReaderCancelled
	}
	if offset < 0 || offset >= int64(len(m.data)) {
		return 0, errors.New("offset 越界")
	}
	return copy(buf, m.data[offset:]), nil
}
func (m *cancellableMockReader) Size() (int64, error) { return int64(len(m.data)), nil }
func (m *cancellableMockReader) SectorSize() int      { return 512 }
func (m *cancellableMockReader) DevicePath() string   { return "mock://bl-cancellable" }
func (m *cancellableMockReader) Cancel() error {
	m.cancelHits.Add(1)
	m.cancelled.Store(true)
	return nil
}

// 编译期断言：mock 必须实现 disk.Canceller，否则测试白做了
var _ disk.Canceller = (*cancellableMockReader)(nil)

// TestDecryptingReader_CancelPropagates 回归 v2.8.22：
// 之前 DecryptingReader 不实现 disk.Canceller，Engine.Stop 的类型断言静默 false，
// BitLocker 扫描时 CancelIoEx 永远不触发，磁盘 IO 持续到关进程。
//
// 修复后 DecryptingReader.Cancel 透传到 underlying。
func TestDecryptingReader_CancelPropagates(t *testing.T) {
	mock := &cancellableMockReader{data: make([]byte, 4*512)}
	cipher := &countingCipher{} // 复用 reader_cache_test.go 里的
	r, err := NewDecryptingReader(mock, cipher, "test")
	if err != nil {
		t.Fatalf("NewDecryptingReader: %v", err)
	}

	// 断言 DecryptingReader 实现了 Canceller —— 否则 Engine.Stop 的类型断言会漏
	c, ok := disk.DiskReader(r).(disk.Canceller)
	if !ok {
		t.Fatal("DecryptingReader 必须实现 disk.Canceller，否则 BitLocker 扫描 Stop 时 CancelIoEx 不触发")
	}

	if err := c.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if mock.cancelHits.Load() != 1 {
		t.Errorf("Cancel 没透传到 underlying：期望 1 次 hit，实际 %d", mock.cancelHits.Load())
	}

	// Cancel 后读取应该 fail —— 底层 mock 返回 ErrReaderCancelled
	buf := make([]byte, 512)
	if _, err := r.ReadAt(buf, 0); err == nil {
		t.Fatal("Cancel 后 DecryptingReader.ReadAt 仍成功 —— underlying 没毒化或没透传 error")
	}
}
