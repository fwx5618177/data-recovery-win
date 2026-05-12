package luks

import (
	"errors"
	"sync/atomic"
	"testing"

	"data-recovery/internal/disk"
)

// cancellableMockReader 最小化 disk.DiskReader，仅本测试用。
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
func (m *cancellableMockReader) DevicePath() string   { return "mock://luks-cancellable" }
func (m *cancellableMockReader) Cancel() error {
	m.cancelHits.Add(1)
	m.cancelled.Store(true)
	return nil
}

var _ disk.Canceller = (*cancellableMockReader)(nil)

// passthroughCipher 不做真解密，仅满足接口。LUKS DecryptedReader 测试只验证 Cancel
// 透传，不在乎解密内容对不对。
type passthroughCipher struct{ sectorSize int }

func (p passthroughCipher) DecryptSector(buf []byte, _ uint64) error { return nil }
func (p passthroughCipher) SectorSize() int                          { return p.sectorSize }

// TestDecryptedReader_CancelPropagates 回归 v2.8.22：
// 之前 luks.DecryptedReader 不实现 disk.Canceller，LUKS / VeraCrypt 扫描时
// Engine.Stop 的 CancelIoEx 永远不触发，磁盘 IO 持续到关进程。
func TestDecryptedReader_CancelPropagates(t *testing.T) {
	mock := &cancellableMockReader{data: make([]byte, 4*512)}
	r, err := NewDecryptedReader(DecryptedReaderConfig{
		Underlying:  mock,
		Cipher:      passthroughCipher{sectorSize: 512},
		PayloadOff:  0,
		PayloadSize: int64(len(mock.data)),
	})
	if err != nil {
		t.Fatalf("NewDecryptedReader: %v", err)
	}

	c, ok := disk.DiskReader(r).(disk.Canceller)
	if !ok {
		t.Fatal("DecryptedReader 必须实现 disk.Canceller，否则 LUKS/VC 扫描 Stop 时 CancelIoEx 不触发")
	}

	if err := c.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if mock.cancelHits.Load() != 1 {
		t.Errorf("Cancel 没透传到 underlying：期望 1 次 hit，实际 %d", mock.cancelHits.Load())
	}

	buf := make([]byte, 512)
	if _, err := r.ReadAt(buf, 0); err == nil {
		t.Fatal("Cancel 后 DecryptedReader.ReadAt 仍成功")
	}
}
