package scanevent

import (
	"sync"
	"time"

	"data-recovery/internal/types"
)

// BatchSize / BatchInterval 是 FileFoundBatcher 的默认阈值。
// 公开导出方便外部测试断言 + 文档化。
const (
	BatchSize     = 200                    // 攒到这么多文件就发
	BatchInterval = 100 * time.Millisecond // 或者过了这么久就发
)

// FileFoundBatcher 把 scan:fileFound 事件从"每文件 1 次 IPC"批量节流成
// "每 200 文件 OR 每 100ms 1 次 IPC"。
//
// 背景（v2.8.40）：单个深度扫描典型发现 10K-100K 个文件碎片。如果每个都
// 同步 EventsEmit 一次，Wails IPC buffer 会撑爆 + 前端 React 频繁重渲染
// 直接卡死 UI。批量节流后 100K 文件 → 500 次 IPC（200×），前端只在批次
// 边界更新一次列表，CPU 占用降一个数量级。
//
// 用法：
//
//	b := scanevent.NewFileFoundBatcher(func(batch []*types.RecoveredFile) {
//	    wailsRuntime.EventsEmit(ctx, "scan:fileFound", batch)
//	})
//	for _, f := range files { b.Add(f) }
//	b.Flush() // scan 完成 / 错误时调
//
// 线程安全：Add / Flush 可被多 goroutine 并发调用（worker pool 场景）。
//
// v2.8.46 从 app.go 抽出来：原本是 *App 的成员方法 emitFileFoundBatched /
// flushFileFoundBatch，包私有字段（fileFoundMu / fileFoundPending /
// fileFoundLast）让测试不得不放在 package main 里。抽出独立类型后测试
// 可以放在 tests/ 子目录甚至外部包。
type FileFoundBatcher struct {
	emit func([]*types.RecoveredFile)

	mu       sync.Mutex
	pending  []*types.RecoveredFile
	lastEmit time.Time

	// 阈值可覆盖；零值用默认常量。测试场景下可以调小做快测。
	batchSize     int
	batchInterval time.Duration
}

// NewFileFoundBatcher 构造一个新的批量器。emit 在阈值触发或 Flush 时回调，
// 收到一份独立的 []*types.RecoveredFile slice（调用方可自由持有）。
//
// lastEmit 初始化为 time.Now() 防 zero-time 让首个 Add 看到"距上次 emit
// 已经无穷久"立即触发空批。
func NewFileFoundBatcher(emit func([]*types.RecoveredFile)) *FileFoundBatcher {
	return &FileFoundBatcher{
		emit:          emit,
		batchSize:     BatchSize,
		batchInterval: BatchInterval,
		lastEmit:      time.Now(),
	}
}

// SetThresholds 覆盖 size + interval 阈值（仅测试用，生产用默认）。
// size <= 0 或 interval <= 0 时该字段保留默认。
func (b *FileFoundBatcher) SetThresholds(size int, interval time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if size > 0 {
		b.batchSize = size
	}
	if interval > 0 {
		b.batchInterval = interval
	}
}

// Add 把一个文件加进 pending；达阈值则同步触发 emit。f 为 nil 时静默忽略。
func (b *FileFoundBatcher) Add(f *types.RecoveredFile) {
	if f == nil {
		return
	}
	b.mu.Lock()
	b.pending = append(b.pending, f)
	needEmit := len(b.pending) >= b.batchSize ||
		time.Since(b.lastEmit) >= b.batchInterval
	if !needEmit {
		b.mu.Unlock()
		return
	}
	batch := b.pending
	b.pending = nil
	b.lastEmit = time.Now()
	b.mu.Unlock()
	if b.emit != nil {
		b.emit(batch)
	}
}

// Flush 把 pending 里的剩余文件全部发出去。
// scan:completed / scan:error / cancel 路径必须调一次以免丢尾巴文件。
func (b *FileFoundBatcher) Flush() {
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.pending
	b.pending = nil
	b.lastEmit = time.Now()
	b.mu.Unlock()
	if b.emit != nil {
		b.emit(batch)
	}
}

// PendingCount 当前 pending 队列长度。仅测试 / 诊断用，不要在热路径调（拿锁）。
func (b *FileFoundBatcher) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}
