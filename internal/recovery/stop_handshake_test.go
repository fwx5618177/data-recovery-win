package recovery

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// stuckCancellableReader 模拟一个"被取消时立刻 fail"的 reader（如 v2.8.23 后的 windowsReader）。
// 用于验证 Engine.Stop 的 done-channel 同步。
type stuckCancellableReader struct {
	cancelled atomic.Bool
	reads     atomic.Int64
}

func (r *stuckCancellableReader) Open() error  { return nil }
func (r *stuckCancellableReader) Close() error { return nil }
func (r *stuckCancellableReader) ReadAt(buf []byte, offset int64) (int, error) {
	if r.cancelled.Load() {
		return 0, disk.ErrReaderCancelled
	}
	r.reads.Add(1)
	// 模拟真实 NVMe IO 节奏：每 4MB 读 ~1ms
	time.Sleep(1 * time.Millisecond)
	for i := range buf {
		buf[i] = 0xAB
	}
	return len(buf), nil
}
func (r *stuckCancellableReader) Size() (int64, error) { return 1 << 40, nil } // 1TB
func (r *stuckCancellableReader) SectorSize() int      { return 512 }
func (r *stuckCancellableReader) DevicePath() string   { return "mock://stuck" }
func (r *stuckCancellableReader) Cancel() error {
	r.cancelled.Store(true)
	return nil
}

var _ disk.Canceller = (*stuckCancellableReader)(nil)

// TestEngineStop_DoneChannelHandshake 验证 v2.8.24 的结构性修复：
// Stop 不再 poll-timeout 撒谎，而是同步等 scanDone close。
//
// v2.8.20-v2.8.23 的所有"修了又没修"都因为同一个根因：Stop 等 10s 就强制返回，
// 即便 scan goroutine 还活着持续读盘。前端看到"已停"，但 IO 持续直到杀进程。
//
// v2.8.24 改成：Stop 同步等 ScanWithReaderOptions 的 defer close(scanDone)。
// done close 意味着所有子 goroutine 真退了 —— 才返回。
func TestEngineStop_DoneChannelHandshake(t *testing.T) {
	eng := NewEngine()
	reader := &stuckCancellableReader{}

	// 启动一个长时间扫描（用 deep 模式跳过 NTFS 等需要真实数据的 phase）
	scanDone := make(chan error, 1)
	go func() {
		_, err := eng.ScanWithReader(reader, types.ScanDeep, ScanCallbacks{})
		scanDone <- err
	}()

	// 等扫描真正启动（reads > 0）
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reader.reads.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reader.reads.Load() == 0 {
		t.Fatal("扫描没真正启动 —— 测试环境问题")
	}

	// 关键断言：Stop 必须同步等到扫描 goroutine 真退出
	stopStart := time.Now()
	eng.Stop()
	stopDuration := time.Since(stopStart)

	// Stop 返回时，scanDone 必须已经 ready —— 因为 Stop 内部等了它
	select {
	case <-scanDone:
		// good — scan goroutine 已退出
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Stop 返回后 100ms 内 scan goroutine 仍未退出 —— v2.8.20 假死 bug 复发（Stop 耗时 %v）", stopDuration)
	}

	// 同时验证：reader 收到了 Cancel
	if !reader.cancelled.Load() {
		t.Error("Stop 没把 Cancel 传到 reader —— 链路断了")
	}

	t.Logf("Stop 耗时 %v；扫描期间读了 %d 次", stopDuration, reader.reads.Load())
}

// TestEngineStop_NoScanInProgress 验证 Stop 在没扫描时是 no-op（不能 panic / 死锁）
func TestEngineStop_NoScanInProgress(t *testing.T) {
	eng := NewEngine()
	// 之前没有任何扫描启动过 —— 既无 scanCancel 也无 scanDone
	done := make(chan struct{})
	go func() {
		eng.Stop()
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop 在没扫描时挂住了 —— nil channel select bug")
	}
}

// TestEngineStop_DoubleStopSafe 验证重复 Stop 不会乱套（用户可能连点 stop 按钮）
func TestEngineStop_DoubleStopSafe(t *testing.T) {
	eng := NewEngine()
	reader := &stuckCancellableReader{}

	go func() {
		_, _ = eng.ScanWithReader(reader, types.ScanDeep, ScanCallbacks{})
	}()

	// 等启动
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reader.reads.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	// 连续两次 Stop
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			eng.Stop()
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("两个并发 Stop 死锁了")
	}
}

// TestEngineStop_StopDoesNotLieAboutCompletion 这是用户最关心的语义：
// "Stop 返回 = 扫描真停 = 没有 ReadAt 在继续"
//
// 之前的 10s timeout 会破坏这个不变量。这个测试直接锁死它。
func TestEngineStop_StopDoesNotLieAboutCompletion(t *testing.T) {
	eng := NewEngine()
	reader := &stuckCancellableReader{}

	scanCtx, scanCancel := context.WithCancel(context.Background())
	_ = scanCtx
	defer scanCancel()

	go func() {
		_, _ = eng.ScanWithReader(reader, types.ScanDeep, ScanCallbacks{})
	}()

	// 等扫描跑起来
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reader.reads.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	// Stop
	eng.Stop()

	// Stop 返回后再观察 reader.reads —— 之后不能再增长
	readsAtStop := reader.reads.Load()
	time.Sleep(100 * time.Millisecond)
	readsAfter := reader.reads.Load()

	if readsAfter > readsAtStop {
		t.Errorf("Stop 返回后 reader 仍被读 %d 次（前 %d → 后 %d）—— Stop 撒谎了，扫描没真停",
			readsAfter-readsAtStop, readsAtStop, readsAfter)
	}
}

// TestEngineStop_RaceFreeStartup 把 v2.8.24 残留的初始化 race 锁死。
//
// v2.8.24 的 ScanWithReaderOptions 是这样初始化的：
//
//	e.mu.Lock(); e.scanning = true; e.scanDone = make(...); e.mu.Unlock()
//	... 中间没锁的 ms 级窗口 ...
//	e.mu.Lock(); e.scanCancel = cancel; e.mu.Unlock()
//
// 用户在中间窗口点 stop → Stop 看到 done 非 nil 但 cancel 仍 nil。
// Stop 会走 <-done 但谁都没调 cancel()，扫描一路跑到自然结束 —— 表现为
// "我点了停止键但磁盘 IO 仍在持续，关掉才停"。
//
// v2.8.25 把这两个 mu 段合并成一个，cancel/done/scanning 同时可见。这个测试
// 启动 100 次 scan，每次在 nanosecond 级 sleep 后立刻调 Stop，覆盖所有可能的
// 初始化时序。如果 race 仍在，至少有一次 Stop 会阻塞 → 测试超时。
func TestEngineStop_RaceFreeStartup(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		eng := NewEngine()
		reader := &stuckCancellableReader{}

		scanReturned := make(chan struct{})
		go func() {
			defer close(scanReturned)
			_, _ = eng.ScanWithReader(reader, types.ScanDeep, ScanCallbacks{})
		}()

		// 用纳秒级延迟覆盖各种时序点：从 0（赶在 mu.Lock 之前）到 ~ms
		// 不用 deterministic interleaving 因为 Go race detector + 100 次迭代
		// 已经能稳定暴露原 race。
		time.Sleep(time.Duration(iter*7) * time.Microsecond)

		stopReturned := make(chan struct{})
		go func() {
			defer close(stopReturned)
			eng.Stop()
		}()

		// Stop 必须在 500ms 内返回。race 时它会卡在 <-done 等永远不会 cancel 的扫描
		select {
		case <-stopReturned:
			// good
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("iter=%d: Stop 卡住 —— 初始化 race 让 cancel/done 不一致", iter)
		}

		// 扫描 goroutine 也必须收尾
		select {
		case <-scanReturned:
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("iter=%d: scan goroutine 在 Stop 返回后仍未退出", iter)
		}
	}
}

// TestEngineStop_ZeroReadsAfterStop 把"暂停扫描即停止资源占用"的承诺
// 用最严格的方式锁死：Stop 返回的那一刻起，reader.ReadAt 必须零调用。
//
// 不像 TestEngineStop_StopDoesNotLieAboutCompletion 给 100ms 缓冲检查趋势，
// 这里直接 atomic snapshot：Stop 之前 N 次，Stop 之后必须仍是 N 次。
func TestEngineStop_ZeroReadsAfterStop(t *testing.T) {
	eng := NewEngine()
	reader := &stuckCancellableReader{}

	go func() { _, _ = eng.ScanWithReader(reader, types.ScanDeep, ScanCallbacks{}) }()

	// 等读起来
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reader.reads.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if reader.reads.Load() == 0 {
		t.Fatal("扫描没启动")
	}

	eng.Stop()
	immediatelyAfterStop := reader.reads.Load()

	// Stop 返回后再观察 5 次 / 共 250ms。读次数必须严格不变。
	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		now := reader.reads.Load()
		if now != immediatelyAfterStop {
			t.Fatalf("Stop 返回后第 %d 次采样仍在读：%d → %d (新增 %d 次)",
				i+1, immediatelyAfterStop, now, now-immediatelyAfterStop)
		}
	}
}

var _ = errors.New // avoid unused
