package disk

import (
	"fmt"
	"io"
	"time"
)

// TimeoutReader 给每次 ReadAt 加 per-read 超时。
//
// 用途：Windows 驱动层 CreateFile 成功但后续 ReadFile 可能在 driver queue 里无限等待
// —— 比如 SATA 控制器遇到 bad sector 会尝试 retry 10 秒再返回，U 盘固件崩溃后
// ReadFile 直接 hang 几分钟。ResilientReader 能对 IO error 重试，但**无法**打断
// 卡在 syscall 里的 goroutine。本 wrapper 把每次 ReadAt 放独立 goroutine，主线程
// 用 timer 等；超时就把结果当 "bad sector" 抛出，让 ResilientReader 兜底 retry。
//
// 配合链：TimeoutReader → ResilientReader → 平台 reader
//
// 注意：超时的 goroutine 仍然泄漏（syscall 本身无 cancel）；靠 Canceller.Cancel()
// 在 StopScan 时 CancelIoEx 强制清理。
type TimeoutReader struct {
	underlying DiskReader
	timeout    time.Duration
}

// NewTimeoutReader 默认每次 ReadAt 超时 8 秒。
// Linux/Mac 上 8s 已经够绝大多数 bad sector retry；再长用户就该感到异常了。
func NewTimeoutReader(underlying DiskReader, timeout time.Duration) *TimeoutReader {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &TimeoutReader{underlying: underlying, timeout: timeout}
}

func (r *TimeoutReader) Open() error          { return r.underlying.Open() }
func (r *TimeoutReader) Close() error         { return r.underlying.Close() }
func (r *TimeoutReader) Size() (int64, error) { return r.underlying.Size() }
func (r *TimeoutReader) SectorSize() int      { return r.underlying.SectorSize() }
func (r *TimeoutReader) DevicePath() string   { return r.underlying.DevicePath() }

type readResult struct {
	n   int
	err error
}

func (r *TimeoutReader) ReadAt(buf []byte, offset int64) (int, error) {
	ch := make(chan readResult, 1)
	go func() {
		n, err := r.underlying.ReadAt(buf, offset)
		ch <- readResult{n: n, err: err}
	}()
	select {
	case res := <-ch:
		return res.n, res.err
	case <-time.After(r.timeout):
		// 把超时当 IO error 抛，让 ResilientReader 按扇区 retry；如果是永久 bad
		// 区，最终被记为 BadSector + 0 填充。underlying goroutine 泄漏直到 syscall
		// 最终返回（或 Canceller.Cancel 强制中断）。
		return 0, fmt.Errorf("ReadAt(offset=%d, size=%d) 超时 %v: %w",
			offset, len(buf), r.timeout, errTimeoutIO)
	}
}

// Cancel 透传给底层（保留 Canceller 能力）
func (r *TimeoutReader) Cancel() error {
	if c, ok := r.underlying.(Canceller); ok {
		return c.Cancel()
	}
	return nil
}

// errTimeoutIO 标记超时为 non-EOF error，让 ResilientReader 走 retry 分支
// （ResilientReader 对 nil/EOF 不 retry，其他一律当坏块）
var errTimeoutIO = fmt.Errorf("disk read timeout")

var _ DiskReader = (*TimeoutReader)(nil)
var _ Canceller = (*TimeoutReader)(nil)

// 确保 io 没被 import-but-unused
var _ = io.EOF
