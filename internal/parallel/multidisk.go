// Package parallel 提供"多盘并行扫描"helper —— 取证 / NAS 用户常常有 4-8 块盘要扫，
// 串行半天。多 engine + goroutine 并行扫，结果合并到一个事件流。
//
// 不复用 GUI 的 App，也不依赖 Wails；纯 Go 接口给 CLI / 测试 / 第三方集成用。
package parallel

import (
	"context"
	"sync"

	"data-recovery/internal/recovery"
	"data-recovery/internal/types"
)

// DiskJob 单盘扫描任务
type DiskJob struct {
	DrivePath string
	Mode      types.ScanMode
}

// JobResult 单盘扫完的结果
type JobResult struct {
	DrivePath string
	Result    *types.ScanResult
	Err       error
}

// ScanCallback 多盘并行模式下的 progress + file events
type ScanCallback struct {
	OnDiskStart   func(DiskJob)
	OnDiskProgress func(DiskJob, types.ScanProgress)
	OnFileFound   func(DiskJob, *types.RecoveredFile)
	OnDiskDone    func(JobResult)
}

// ScanMultiple 把 jobs 列表里的盘并行扫，最多 maxParallel 个同时跑（默认 = len(jobs)）。
//
// 注意：每个并行 goroutine 用一个独立 Engine（engine 内部全局状态，不能共享）。
// 内存占用会乘以并行度 — 对扫 4 块盘 + 每盘 200MB MFT 缓存来说 < 1GB，可接受。
func ScanMultiple(ctx context.Context, jobs []DiskJob, maxParallel int, cb ScanCallback) []JobResult {
	if maxParallel <= 0 || maxParallel > len(jobs) {
		maxParallel = len(jobs)
	}
	results := make([]JobResult, len(jobs))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup

	for i, job := range jobs {
		i, job := i, job
		wg.Add(1)
		sem <- struct{}{} // 占一个并行槽
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if cb.OnDiskStart != nil {
				cb.OnDiskStart(job)
			}
			engine := recovery.NewEngine()
			defer engine.Shutdown()

			scb := recovery.ScanCallbacks{
				OnProgress: func(p types.ScanProgress) {
					if cb.OnDiskProgress != nil {
						cb.OnDiskProgress(job, p)
					}
				},
				OnFileFound: func(f *types.RecoveredFile) {
					if cb.OnFileFound != nil {
						cb.OnFileFound(job, f)
					}
				},
			}
			res, err := engine.Scan(job.DrivePath, job.Mode, scb)
			results[i] = JobResult{DrivePath: job.DrivePath, Result: res, Err: err}
			if cb.OnDiskDone != nil {
				cb.OnDiskDone(results[i])
			}

			// ctx 取消时 engine.Stop 让本 goroutine 早退
			select {
			case <-ctx.Done():
				engine.Stop()
			default:
			}
		}()
	}

	wg.Wait()
	return results
}
