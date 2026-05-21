package scanevent_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"data-recovery/internal/scanevent"
	"data-recovery/internal/types"
)

// TestFileFoundBatcher_AccumulatesUntilThreshold 锁住 v2.8.40 的批量节流契约：
// 100 文件（不到 BatchSize=200）+ 无时间间隔触发 → 应该不立即 emit。
//
// 通过 emit closure 计数确认。
func TestFileFoundBatcher_AccumulatesUntilThreshold(t *testing.T) {
	var emitCount atomic.Int64
	var lastBatchLen atomic.Int64
	b := scanevent.NewFileFoundBatcher(func(batch []*types.RecoveredFile) {
		emitCount.Add(1)
		lastBatchLen.Store(int64(len(batch)))
	})
	// 用极大 interval 让时间阈值不触发；只能靠 size 阈值触发
	b.SetThresholds(scanevent.BatchSize, time.Hour)

	for i := 0; i < 100; i++ {
		b.Add(&types.RecoveredFile{ID: "f"})
	}
	if got := emitCount.Load(); got != 0 {
		t.Errorf("100 文件未到 size 阈值 + interval 极大 → emit 应为 0，得到 %d", got)
	}
	if got := b.PendingCount(); got != 100 {
		t.Errorf("pending 应保留 100，得到 %d", got)
	}
}

// TestFileFoundBatcher_EmitsAtSizeThreshold 达到 BatchSize 立即 emit。
func TestFileFoundBatcher_EmitsAtSizeThreshold(t *testing.T) {
	var emitCount atomic.Int64
	var totalSent atomic.Int64
	b := scanevent.NewFileFoundBatcher(func(batch []*types.RecoveredFile) {
		emitCount.Add(1)
		totalSent.Add(int64(len(batch)))
	})
	b.SetThresholds(scanevent.BatchSize, time.Hour) // 关闭时间阈值

	for i := 0; i < scanevent.BatchSize; i++ {
		b.Add(&types.RecoveredFile{ID: "f"})
	}
	if got := emitCount.Load(); got != 1 {
		t.Errorf("到 size 阈值应 emit 1 次，得到 %d", got)
	}
	if got := totalSent.Load(); got != int64(scanevent.BatchSize) {
		t.Errorf("emit 的 batch 总文件数应是 %d，得到 %d", scanevent.BatchSize, got)
	}
}

// TestFileFoundBatcher_FlushDeliversPending 调 Flush 应把残留全发出。
func TestFileFoundBatcher_FlushDeliversPending(t *testing.T) {
	var emitCount atomic.Int64
	var lastLen atomic.Int64
	b := scanevent.NewFileFoundBatcher(func(batch []*types.RecoveredFile) {
		emitCount.Add(1)
		lastLen.Store(int64(len(batch)))
	})
	b.SetThresholds(scanevent.BatchSize, time.Hour)

	for i := 0; i < 50; i++ {
		b.Add(&types.RecoveredFile{ID: "f"})
	}
	if got := emitCount.Load(); got != 0 {
		t.Fatalf("50 < BatchSize，flush 前不该 emit，得到 %d", got)
	}
	b.Flush()
	if got := emitCount.Load(); got != 1 {
		t.Errorf("Flush 后应 emit 1 次，得到 %d", got)
	}
	if got := lastLen.Load(); got != 50 {
		t.Errorf("Flush 应送 50 文件，得到 %d", got)
	}
	if got := b.PendingCount(); got != 0 {
		t.Errorf("Flush 后 pending 应清空，得到 %d", got)
	}
}

// TestFileFoundBatcher_FlushNoOpOnEmpty 没文件时调 Flush 也安全（前提是它不 emit）。
func TestFileFoundBatcher_FlushNoOpOnEmpty(t *testing.T) {
	var emitCount atomic.Int64
	b := scanevent.NewFileFoundBatcher(func(batch []*types.RecoveredFile) {
		emitCount.Add(1)
	})
	b.Flush()
	if got := emitCount.Load(); got != 0 {
		t.Errorf("空 batcher Flush 不该 emit，得到 %d", got)
	}
}

// TestFileFoundBatcher_Concurrency 并发 Add 不能死锁 / race。
// 这个测试在 -race 下能抓互斥保护漏洞。
func TestFileFoundBatcher_Concurrency(t *testing.T) {
	var totalSent atomic.Int64
	b := scanevent.NewFileFoundBatcher(func(batch []*types.RecoveredFile) {
		totalSent.Add(int64(len(batch)))
	})
	// 极大 interval + 小 size：让多数 goroutine 抢锁，少数触发 emit
	b.SetThresholds(50, time.Hour)

	const goroutines = 16
	const perG = 100
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				b.Add(&types.RecoveredFile{ID: "g"})
			}
		}()
	}
	wg.Wait()
	b.Flush()

	want := int64(goroutines * perG)
	if got := totalSent.Load(); got != want {
		t.Errorf("并发 Add + Flush：期望总送 %d 条，得到 %d", want, got)
	}
}

// TestFileFoundBatcher_Defaults 默认阈值要安全（不能太小让节流失效）
func TestFileFoundBatcher_Defaults(t *testing.T) {
	if scanevent.BatchSize < 100 {
		t.Errorf("BatchSize 不能低于 100（节流意义弱），得到 %d", scanevent.BatchSize)
	}
	if scanevent.BatchInterval < 50*time.Millisecond {
		t.Errorf("BatchInterval 不能 < 50ms，得到 %v", scanevent.BatchInterval)
	}
	if scanevent.BatchInterval > time.Second {
		t.Errorf("BatchInterval 不能 > 1s（用户感觉 UI 卡）得到 %v", scanevent.BatchInterval)
	}
}
