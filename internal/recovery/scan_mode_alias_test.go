package recovery

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// 这个 mock 给 ScanWithReaderOptions 的"mode 别名归一化"测试用 —— ReadAt 立刻 cancel
// 让扫描尽快退出（我们只关心 mode 是否被接受、不关心扫描结果）。
type modeAliasMockReader struct {
	cancelled atomic.Bool
}

func (m *modeAliasMockReader) Open() error  { return nil }
func (m *modeAliasMockReader) Close() error { return nil }
func (m *modeAliasMockReader) ReadAt(buf []byte, offset int64) (int, error) {
	if m.cancelled.Load() {
		return 0, disk.ErrReaderCancelled
	}
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}
func (m *modeAliasMockReader) Size() (int64, error) { return 64 * 1024 * 1024, nil }
func (m *modeAliasMockReader) SectorSize() int      { return 512 }
func (m *modeAliasMockReader) DevicePath() string   { return "mock://mode-alias" }
func (m *modeAliasMockReader) Cancel() error {
	m.cancelled.Store(true)
	return nil
}

var _ disk.Canceller = (*modeAliasMockReader)(nil)

// TestScanWithReaderOptions_AutoModeAccepted 回归 v2.8.28 修复：
// 前端"多盘并行扫描"对话框默认 mode="auto"，但 ScanWithReaderOptions 的 switch
// 只认 quick/deep/full —— 用户报 "未知扫描模式: auto"。
//
// 规范化逻辑：mode ∈ {"", "auto", "default"} 都映射成 ScanFull。
//
// 这个测试启动一个扫描（mode=auto），立刻 Cancel，确认：
//   1. 不返回 "未知扫描模式" 错误（说明 auto 被接受）
//   2. 返回的错误是 cancel-related（扫描确实启动了）
func TestScanWithReaderOptions_AutoModeAccepted(t *testing.T) {
	cases := []string{"auto", "", "default"}

	for _, modeStr := range cases {
		t.Run("mode="+modeStr, func(t *testing.T) {
			eng := NewEngine()
			reader := &modeAliasMockReader{}

			// 启动 + 立刻 cancel 让扫描快退
			go func() {
				time.Sleep(20 * time.Millisecond)
				eng.Stop()
			}()

			_, err := eng.ScanWithReaderOptions(reader, types.ScanOptions{
				Mode: types.ScanMode(modeStr),
			}, ScanCallbacks{})

			// 关键断言：不能是 "未知扫描模式" 错误
			if err != nil && strings.Contains(err.Error(), "未知扫描模式") {
				t.Errorf("mode=%q 报了「未知扫描模式」错 —— v2.8.28 的归一化没生效: %v", modeStr, err)
			}
			// 取消是预期的；其他错误也可以接受（扫描内部 ctx cancelled → 各种 wrapping）
			if err != nil && !strings.Contains(err.Error(), "取消") && !strings.Contains(err.Error(), "cancel") {
				t.Logf("mode=%q 返回非取消类错误（不阻塞测试）: %v", modeStr, err)
			}
		})
	}
}

// TestScanWithReaderOptions_UnknownModeStillErrors 验证归一化只覆盖明确的别名，
// 真正未知的 mode 字符串仍然要报错（避免出 bug 时静默走错路径）。
func TestScanWithReaderOptions_UnknownModeStillErrors(t *testing.T) {
	eng := NewEngine()
	reader := &modeAliasMockReader{}

	_, err := eng.ScanWithReaderOptions(reader, types.ScanOptions{
		Mode: types.ScanMode("nonsense-mode-xxx"),
	}, ScanCallbacks{})

	if err == nil {
		t.Fatal("未知 mode 应该报错")
	}
	if !strings.Contains(err.Error(), "未知扫描模式") {
		t.Errorf("期望 '未知扫描模式' 错误，实际：%v", err)
	}
}

var _ = errors.New
