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

// DiskJob 单盘扫描任务。
//
// v2.8.34 加 JSON tag —— DiskJob 也作为"parallel:diskStart"事件 payload，
// 前端读 job.drivePath / job.mode 之前都是 undefined。同时入参反序列化
// Go 默认是 case-insensitive 所以前端发 camelCase 也能工作（之前），但事件 emit
// 输出走严格匹配，必须有 tag。
type DiskJob struct {
	DrivePath string         `json:"drivePath"`
	Mode      types.ScanMode `json:"mode"`
}

// JobResult 单盘扫完的结果。
//
// v2.8.34 加 JSON tag —— 之前作为 parallel:allDone 事件 payload，前端读
// r.drivePath / r.result 全 undefined。`Err` 字段是 error 接口（不能序列化），
// 改用 ErrMessage 字符串 + json:"-" 让上层显式转。
type JobResult struct {
	DrivePath string             `json:"drivePath"`
	Result    *types.ScanResult  `json:"result"`
	Err       error              `json:"-"`
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

			// v2.8.31: ctx 监听必须**并发**跑 —— 之前的代码把 `<-ctx.Done() { engine.Stop() }`
			// 放在 `engine.Scan` 返回之后，那时候扫描早就结束了，stop 完全没用。用户报
			// "多盘并行扫描时停止扫描依然存在 IO 占用必须退出" 的真正原因。
			// 现在开 watcher 在 Scan 跑的同时盯 ctx，触发就调 engine.Stop()。
			watcherDone := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					engine.Stop()
				case <-watcherDone:
				}
			}()

			res, err := engine.Scan(job.DrivePath, job.Mode, scb)
			close(watcherDone) // 通知 watcher 退出（如果是自然完成而非被 cancel）
			results[i] = JobResult{DrivePath: job.DrivePath, Result: res, Err: err}
			if cb.OnDiskDone != nil {
				cb.OnDiskDone(results[i])
			}
		}()
	}

	wg.Wait()
	return results
}
