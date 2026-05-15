package recovery

import (
	"sync/atomic"
	"testing"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// fakeQuickReader 实现 disk.DiskReader，让 validator.ValidateFast 立刻返回。
// 用于驱动 validateAll 的进度节流测试。
type fakeQuickReader struct{}

func (fakeQuickReader) Open() error                           { return nil }
func (fakeQuickReader) Close() error                          { return nil }
func (fakeQuickReader) ReadAt(p []byte, _ int64) (int, error) { return len(p), nil }
func (fakeQuickReader) Size() (int64, error)                  { return 1 << 30, nil }
func (fakeQuickReader) SectorSize() int                       { return 512 }
func (fakeQuickReader) DevicePath() string                    { return "fake://" }

// TestValidateAll_ProgressThrottle 锁住 v2.8.37 的进度节流契约：
//
// validateAll 不能再像之前那样每个文件 emit 一次 progress —— 10 万文件 = 10 万次
// Wails IPC，前端 React 抖动严重。
//
// 节流规则（v2.8.37）：每 500 文件 OR 每 200ms emit 一次，首尾必发。
//
// 这个测试用 10K 个轻量文件触发 validateAll，断言：
//   - 进度回调次数 << 10K（节流生效）
//   - 至少有 2 次回调（首/尾）
//   - 实测 ~20 次（10000 / 500 = 20）
func TestValidateAll_ProgressThrottle(t *testing.T) {
	eng := NewEngine()

	// 造 10K 个 fake 文件
	const totalFiles = 10000
	files := make([]*types.RecoveredFile, totalFiles)
	for i := range files {
		files[i] = &types.RecoveredFile{
			ID:       "f" + string(rune('a'+i%26)),
			FileName: "test.bin",
			Source:   "carver",
			Size:     int64(i),
			Offset:   int64(i * 1024),
		}
	}

	var callbackCount atomic.Int64
	onProgress := func(p types.ScanProgress) {
		callbackCount.Add(1)
	}

	start := time.Now()
	eng.validateAll(files, fakeQuickReader{}, onProgress)
	elapsed := time.Since(start)

	cnt := callbackCount.Load()
	t.Logf("validateAll 跑 %d 文件耗时 %v，progress emit %d 次（节流前会是 %d 次）",
		totalFiles, elapsed, cnt, totalFiles)

	// 节流前每个文件 emit → totalFiles 次。
	// 节流后 totalFiles/500 ≈ 20 次（加上首/尾边界顶多 ~22 次）。
	// 测试容忍度：必须 < totalFiles/10 = 1000（极宽松，证明节流真生效），且 >= 2（首/尾必发）。
	if cnt > totalFiles/10 {
		t.Errorf("progress 节流没生效：%d 次回调 >= 阈值 %d。期望 ~20 次。", cnt, totalFiles/10)
	}
	if cnt < 2 {
		t.Errorf("至少应发 2 次（首/尾），实际 %d 次", cnt)
	}
}

// 编译期断言：fakeQuickReader 真实现 DiskReader 接口
var _ disk.DiskReader = fakeQuickReader{}
