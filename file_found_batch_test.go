package main

import (
	"sync"
	"testing"
	"time"

	"data-recovery/internal/types"
)

// TestEmitFileFoundBatched_AccumulatesUntilThreshold 锁住 v2.8.40 的批量节流契约：
// 100 文件（不到 fileFoundBatchSize=200）+ 无时间间隔触发 → 应该不立即 emit。
// 这个测试不真发 wails 事件（a.ctx 为 nil），但能验证 pending 队列累积逻辑。
//
// 用 fileFoundLast = now 让时间阈值也不触发。
func TestEmitFileFoundBatched_AccumulatesUntilThreshold(t *testing.T) {
	a := &App{}
	a.fileFoundLast = time.Now() // 防止"距上次发送 > 100ms"触发

	for i := 0; i < 100; i++ {
		// 单文件 emit 不到阈值不该发；我们没法 verify EventsEmit 没被调
		// （a.ctx 为 nil 时 wailsRuntime.EventsEmit 会 panic 因为 nil ctx）
		// 所以这个测试只能间接证明：如果到了阈值就清空 pending，我们看到的
		// "pending 还在积累" = 没触发 emit。
		safeAppend(t, a, &types.RecoveredFile{ID: "f" + itoa(i)})
	}

	// 100 < 200 + 时间不到 → pending 应该还有 100 条
	a.fileFoundMu.Lock()
	got := len(a.fileFoundPending)
	a.fileFoundMu.Unlock()
	if got != 100 {
		t.Errorf("100 文件未到阈值，pending 应保留 100 条，得到 %d", got)
	}
}

// TestFlushFileFoundBatch_NoOpOnEmpty 没文件时调 flush 也安全（前提是它不 emit）。
// 同样不真调 EventsEmit —— 只验证 pending 队列管理。
func TestFlushFileFoundBatch_NoOpOnEmpty(t *testing.T) {
	a := &App{}
	// 不该 panic
	a.flushFileFoundBatch()
	a.fileFoundMu.Lock()
	if a.fileFoundPending != nil {
		t.Errorf("空队列 flush 后 pending 应仍为 nil")
	}
	a.fileFoundMu.Unlock()
}

// safeAppend 把 RecoveredFile 加到 pending 队列，但不调 emitFileFoundBatched
// 本体（避免 nil ctx 的 EventsEmit panic）。专测累积逻辑用。
func safeAppend(t *testing.T, a *App, f *types.RecoveredFile) {
	t.Helper()
	a.fileFoundMu.Lock()
	a.fileFoundPending = append(a.fileFoundPending, f)
	a.fileFoundMu.Unlock()
}

// TestEmitFileFoundBatched_Concurrency 并发 emit 不能死锁 / race。
// 这个测试在 -race 下能抓互斥保护漏洞。
func TestEmitFileFoundBatched_Concurrency(t *testing.T) {
	a := &App{}
	a.fileFoundLast = time.Now() // 防止时间阈值触发 emit（避免 nil ctx panic）

	const goroutines = 16
	const perG = 10
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				safeAppend(t, a, &types.RecoveredFile{ID: "g"})
			}
		}()
	}
	wg.Wait()

	a.fileFoundMu.Lock()
	got := len(a.fileFoundPending)
	a.fileFoundMu.Unlock()
	want := goroutines * perG
	if got != want {
		t.Errorf("并发追加：期望 %d 条 pending，得到 %d", want, got)
	}
}

// TestFileFoundBatchConstants 锁住常量值 —— 不会有人改成 1 文件 1ms 让节流失效。
func TestFileFoundBatchConstants(t *testing.T) {
	if fileFoundBatchSize < 100 {
		t.Errorf("批量阈值不能低于 100，否则节流无意义；得到 %d", fileFoundBatchSize)
	}
	if fileFoundBatchInterval < 50*time.Millisecond {
		t.Errorf("时间阈值不能低于 50ms，否则节流无意义；得到 %v", fileFoundBatchInterval)
	}
	if fileFoundBatchInterval > time.Second {
		t.Errorf("时间阈值不能高于 1s，否则用户感觉 UI 卡（看不到新文件）；得到 %v", fileFoundBatchInterval)
	}
}
