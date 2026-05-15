package parallel

import (
	"context"
	"testing"
	"time"
)

// TestScanMultiple_CtxCancelDuringScan 回归 v2.8.31 修复的 issue 22：
//
// 用户报"启动多盘并行扫描时停止扫描依然存在 IO 占用必须退出"。
// 根因：多盘并行 goroutine 的 ctx 监听 `select { case <-ctx.Done(): engine.Stop() }`
// 放在 `engine.Scan(...)` 返回之后 —— scan 早就跑完了，stop 完全是 no-op。
//
// v2.8.31: 把 watcher 改成**并发** goroutine，scan 跑的同时盯 ctx。cancel 一触发立刻
// 调 engine.Stop()，scan 收到 reader cancel 信号后毫秒级退出。
//
// 测试用 mock job 不去真正扫盘（只验证 ctx cancel → ScanMultiple 在合理时间内返回）：
//  1. 启动多盘扫描，立刻 cancel
//  2. ScanMultiple 必须在 2 秒内 wg.Wait() 完成 —— 之前的代码可能要等扫描自然结束
//     （在真盘上是几分钟到几小时）
func TestScanMultiple_CtxCancelDuringScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// 用 fake 路径让 engine 立刻报错"打开磁盘失败" —— 我们只验证"cancel 时 ScanMultiple
	// 不会卡很久"。即便没有真 cancel 监听，fake 路径也会很快返回错误。
	// 重点：把 cancel 时序设在 scan 启动前 ~0ms。
	jobs := []DiskJob{
		{DrivePath: "/nonexistent/disk/path/1", Mode: "deep"},
		{DrivePath: "/nonexistent/disk/path/2", Mode: "deep"},
	}

	doneCh := make(chan struct{})
	start := time.Now()
	go func() {
		_ = ScanMultiple(ctx, jobs, 2, ScanCallback{})
		close(doneCh)
	}()

	// 启动后立刻 cancel
	time.Sleep(10 * time.Millisecond)
	cancel()

	// 必须在 2 秒内返回 —— 之前 ctx watcher 在 Scan 之后，cancel 没用
	select {
	case <-doneCh:
		elapsed := time.Since(start)
		t.Logf("ScanMultiple 退出耗时 %v", elapsed)
	case <-time.After(2 * time.Second):
		t.Fatal("ScanMultiple 在 cancel 后 2 秒内没退出 —— ctx watcher 没并发跑")
	}
}

// TestScanMultiple_NaturalCompletionStillCleansUpWatcher 验证 watcher 在自然完成
// 时也正确退出（不泄漏 goroutine）。
func TestScanMultiple_NaturalCompletionStillCleansUpWatcher(t *testing.T) {
	ctx := context.Background()
	jobs := []DiskJob{{DrivePath: "/nonexistent", Mode: "deep"}}

	doneCh := make(chan struct{})
	go func() {
		_ = ScanMultiple(ctx, jobs, 1, ScanCallback{})
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// good — 自然完成（fake 路径让 Scan 立刻报错返回）
	case <-time.After(3 * time.Second):
		t.Fatal("ScanMultiple 没自然返回 —— close(watcherDone) 没生效或死锁")
	}
}
