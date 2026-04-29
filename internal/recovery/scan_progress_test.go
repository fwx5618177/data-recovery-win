package recovery

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/testutil"
	"data-recovery/internal/types"
)

// 这一组集成测试是 v2.8.10 加的，专门防止 v2.8.7 之前的 bug 重现：
//   - 进度卡 14.3% 不动（FS 阶段 brute-force 占大头）
//   - 末端速度 180 B/s（坏扇区死亡螺旋）
//   - 总耗时 14h（3 次全盘读）
//
// 单元测试（FindPartitions / ResilientReader）验证组件契约；这里的集成测试验证
// 整个 ScanWithReaderOptions 流程**端到端**地满足三大用户合同：
//   1. 默认模式必须走到 carver 阶段（FS 阶段 ≤ 9% 预算）
//   2. 进度单调递增直到 100%
//   3. FS 阶段不触发 brute-force（除非用户显式取证模式）

// TestScan_DefaultMode_ReachesCarver 锁住 v2.8.8 核心架构契约：
//
// 默认模式（IncludeDeletedPartitions=false）下，FS 阶段必须毫秒级走完，进度迅速越过 9%
// 进入 carver。如果 brute-force 漏到默认路径，FS 阶段会消耗几小时 + 进度卡 < 9%。
//
// 防止 14.3% 卡死 bug 复现。
func TestScan_DefaultMode_ReachesCarver(t *testing.T) {
	const imgSize = 8 * 1024 * 1024 // 8MB（足够 carver 跑出几个进度 tick）
	img := make([]byte, imgSize)
	reader := testutil.NewMemReader(img)
	engine := NewEngine()

	var (
		mu              sync.Mutex
		sawCarverPhase  bool
		maxBeforeCarver float64
		maxOverall      float64
		phasesSeen      = make(map[string]bool)
		bruteForceMsg   bool
	)

	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			mu.Lock()
			defer mu.Unlock()
			phasesSeen[p.Phase] = true
			if p.Phase == "carving" {
				sawCarverPhase = true
			}
			if !sawCarverPhase && p.Percent < 100 && p.Percent > maxBeforeCarver {
				maxBeforeCarver = p.Percent
			}
			if p.Percent > maxOverall {
				maxOverall = p.Percent
			}
			// 默认模式下不应出现 "正在查找已删除 X 分区..." 文案（取证模式专属）
			if strings.Contains(p.CurrentFile, "已删除") {
				bruteForceMsg = true
			}
		},
	}

	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{
		Mode: types.ScanFull,
		// IncludeDeletedPartitions: false (default)
	}, callbacks)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if bruteForceMsg {
		t.Error("默认模式不应触发 brute-force（出现了'正在查找已删除...'文案）")
	}
	if maxBeforeCarver > 10 {
		t.Errorf("FS 阶段消耗了 %.2f 进度预算（应 <= 10）—— v2.8.7 以前的 14.3 卡死会让这条 fail", maxBeforeCarver)
	}
	if !sawCarverPhase {
		t.Error("carver 阶段必须运行（默认模式 80%+ 预算给它）")
	}
	if maxOverall < 95 {
		t.Errorf("最终进度应 ≥ 95%%，实际 %.2f%%", maxOverall)
	}
}

// TestScan_ProgressMonotonic 锁住进度单调性：phase 切换时 percent 不能倒退。
// 前端 App.tsx 有兜底单调 guard，但后端也应该保证 —— 否则前端 guard 失败时会卡。
func TestScan_ProgressMonotonic(t *testing.T) {
	const imgSize = 4 * 1024 * 1024
	img := make([]byte, imgSize)
	reader := testutil.NewMemReader(img)
	engine := NewEngine()

	var (
		mu       sync.Mutex
		lastPct  float64
		regressN int
	)

	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			mu.Lock()
			defer mu.Unlock()
			// "complete" phase 是 100% 收尾，不参与单调性检查（之前可能在 95-99% 之间）
			if p.Phase == "complete" {
				return
			}
			if p.Percent < lastPct-0.5 { // 容忍 0.5% 浮点抖动
				regressN++
				t.Logf("进度倒退: phase=%s %.2f%% -> %.2f%% (lastPhase 见上一条)", p.Phase, lastPct, p.Percent)
			}
			if p.Percent > lastPct {
				lastPct = p.Percent
			}
		},
	}

	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, callbacks)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if regressN > 0 {
		t.Errorf("进度倒退 %d 次，违反单调契约", regressN)
	}
}

// TestScan_PhaseBudgetsRespected 锁住 v2.8.8 双套预算表的契约：
//
// 默认模式下：
//   - ntfs 阶段 percent 必须 ≤ 2%
//   - exfat 阶段 percent 必须在 ≤ 4%
//   - fat 阶段 percent 必须 ≤ 5%
//   - carver 占 9-95%
//
// 这条 fail 意味着 phaseRange / budget 表配错了，或某 FS 没用 budget。
func TestScan_PhaseBudgetsRespected(t *testing.T) {
	const imgSize = 4 * 1024 * 1024
	img := make([]byte, imgSize)
	reader := testutil.NewMemReader(img)
	engine := NewEngine()

	var (
		mu       sync.Mutex
		maxByPhase = make(map[string]float64)
	)

	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			mu.Lock()
			defer mu.Unlock()
			if p.Percent > maxByPhase[p.Phase] {
				maxByPhase[p.Phase] = p.Percent
			}
		},
	}

	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, callbacks)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// 默认 fast budget 表的硬上限（含 0.5% 浮点容忍）
	limits := map[string]float64{
		"ntfs":     2.5,
		"exfat":    4.5,
		"fat":      5.5,
		"ext":      6.5,
		"apfs":     7.5,
		"hfsplus":  8.5,
		"btrfs":    9.5,
		"carving":  95.5, // carver 上限是 95
	}
	for phase, limit := range limits {
		if got, ok := maxByPhase[phase]; ok {
			if got > limit {
				t.Errorf("phase=%s 默认预算超限: %.2f%% > %.2f%%（默认模式下不应突破 fast budget 表）", phase, got, limit)
			}
		}
	}
}

// TestScan_ForensicMode_TriggersBruteForce 锁住 forensic 入口契约：
//
// IncludeDeletedPartitions=true 必须真触发 brute-force —— 否则取证场景失败。
// 验证：CurrentFile 文案出现"正在查找已删除"标识。
func TestScan_ForensicMode_TriggersBruteForce(t *testing.T) {
	const imgSize = 4 * 1024 * 1024
	img := make([]byte, imgSize)
	reader := testutil.NewMemReader(img)
	engine := NewEngine()

	var (
		mu                  sync.Mutex
		bruteForceTriggered bool
	)

	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			mu.Lock()
			defer mu.Unlock()
			if strings.Contains(p.CurrentFile, "已删除") {
				bruteForceTriggered = true
			}
		},
	}

	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{
		Mode:                     types.ScanFull,
		IncludeDeletedPartitions: true,
	}, callbacks)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if !bruteForceTriggered {
		t.Error("取证模式下 brute-force 应触发（应出现'正在查找已删除...'CurrentFile）—— 否则 IncludeDeletedPartitions 没透传")
	}
}

// TestScan_ProgressEmitted 锁最低底线：scan 必须**至少**发一次 onProgress。
// 没这条，前端永远卡 indeterminate 模式 + "即将开始"（v2.8.7 之前的 bug）。
func TestScan_ProgressEmitted(t *testing.T) {
	const imgSize = 1 * 1024 * 1024 // 1MB 即可，主要看是否有 emit
	img := make([]byte, imgSize)
	reader := testutil.NewMemReader(img)
	engine := NewEngine()

	var emitCount atomic.Int64

	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			emitCount.Add(1)
		},
	}
	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, callbacks)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if emitCount.Load() == 0 {
		t.Fatal("scan 没有 emit 任何 onProgress —— 前端会永远卡 indeterminate")
	}
}

// TestScan_CompletesQuickly_OnEmptyImage 锁住时间预算：4MB 空镜像应 ≤ 5s 跑完。
//
// 这是端到端"14h → ~1h"主张的最低保障 —— 单元 IO 不慢的话整个流程不应慢。
// 真实用户会在 USB 上跑 125GB，但 wall-clock IO 是 disk 决定，不是引擎决定；引擎
// 自己只要快就行。这条测试确保我们的引擎流程没有意外的串行阻塞。
func TestScan_CompletesQuickly_OnEmptyImage(t *testing.T) {
	const (
		imgSize    = 4 * 1024 * 1024 // 4MB
		timeBudget = 5 * time.Second
	)
	img := make([]byte, imgSize)
	reader := testutil.NewMemReader(img)
	engine := NewEngine()

	start := time.Now()
	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, ScanCallbacks{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if elapsed > timeBudget {
		t.Errorf("4MB 空镜像 scan 耗时 %.2fs > %.2fs 预算（架构有意外阻塞）", elapsed.Seconds(), timeBudget.Seconds())
	}
	t.Logf("4MB 空镜像 scan 用时 %.2fs", elapsed.Seconds())
}

// slowDiskMock 模拟"健康头 + 末端坏区"USB 盘 —— 用户实际场景的最小再现。
// 健康区瞬间返回数据；坏区每次 ReadAt 失败前 sleep failureDelay（模拟 8s timeout）。
type slowDiskMock struct {
	data         []byte
	badStart     int64 // 坏区起始偏移
	failureDelay time.Duration
	readCount    atomic.Int64
}

func (m *slowDiskMock) Open() error  { return nil }
func (m *slowDiskMock) Close() error { return nil }
func (m *slowDiskMock) ReadAt(buf []byte, off int64) (int, error) {
	m.readCount.Add(1)
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	end := off + int64(len(buf))
	// 任何越过坏区的读都失败
	if end > m.badStart && off < int64(len(m.data)) {
		// 健康+坏 跨界，OS 语义返回 0（整 chunk fail）
		if off < m.badStart {
			time.Sleep(m.failureDelay)
			return 0, errors.New("simulated bad sector cross-boundary")
		}
		// 完全在坏区
		time.Sleep(m.failureDelay)
		return 0, errors.New("simulated bad sector")
	}
	return copy(buf, m.data[off:]), nil
}
func (m *slowDiskMock) Size() (int64, error) { return int64(len(m.data)), nil }
func (m *slowDiskMock) SectorSize() int      { return 512 }
func (m *slowDiskMock) DevicePath() string   { return "mock://slow-disk" }

// 让 slowDiskMock 满足 Canceller 接口（disk.Engine 依赖）
func (m *slowDiskMock) Cancel() error { return nil }

var _ disk.DiskReader = (*slowDiskMock)(nil)

// TestScan_BadSectorEndOfDisk_TimeBudget 锁住 v2.8.9 ResilientReader fast-skip 在
// 实际 engine.Scan 流程里**端到端有效**。
//
// 用户场景最小再现：8MB 磁盘 = 4MB 健康头 + 4MB 末端坏区 + 50ms-per-failure delay。
//
// 没有 fast-skip：4MB 健康（瞬间）+ 4MB 坏区 8192 sector × 50ms = 410 秒
// 有 fast-skip：4MB 健康（~毫秒）+ ~20 calls × 50ms = ~1 秒
//
// 测试断言：scan 完成时间 ≤ 10 秒（给 carver / FS 阶段留余量）。
//
// 这条 fail = ResilientReader fast-skip 没透到 engine 流程里 = 用户的 14h 复现。
func TestScan_BadSectorEndOfDisk_TimeBudget(t *testing.T) {
	const (
		diskSize     = 8 * 1024 * 1024 // 8MB
		badStart     = 4 * 1024 * 1024 // 4MB 后开始坏
		failureDelay = 50 * time.Millisecond
		timeBudget   = 10 * time.Second
	)
	mock := &slowDiskMock{
		data:         make([]byte, diskSize),
		badStart:     badStart,
		failureDelay: failureDelay,
	}
	// 用真实链：disk.NewResilientReader → mock（不裹 TimeoutReader 因为已经在 mock 里模拟超时）
	reader := disk.NewResilientReader(mock, 512, 0) // maxRetry=0 → 用默认 1
	engine := NewEngine()

	start := time.Now()
	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, ScanCallbacks{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if elapsed > timeBudget {
		t.Errorf("8MB 盘（含 4MB 末端坏区）扫描耗时 %.2fs > %.2fs 预算（fast-skip 没透到 engine 流程）",
			elapsed.Seconds(), timeBudget.Seconds())
	}
	t.Logf("8MB 盘 4MB 健康+4MB 坏 扫描完成: %.2fs (read calls=%d)", elapsed.Seconds(), mock.readCount.Load())
}

// TestScan_ScanOptionsBackwardCompat 锁住 ScanWithReader（老 API）走 fast budget。
// 这保证 BitLocker 等老 caller 没跑入 forensic 路径意外慢化。
func TestScan_ScanOptionsBackwardCompat(t *testing.T) {
	const imgSize = 1 * 1024 * 1024
	img := make([]byte, imgSize)
	reader := testutil.NewMemReader(img)
	engine := NewEngine()

	var (
		mu                  sync.Mutex
		bruteForceTriggered bool
	)
	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			mu.Lock()
			defer mu.Unlock()
			if strings.Contains(p.CurrentFile, "已删除") {
				bruteForceTriggered = true
			}
		},
	}

	// 老 API：不接受 ScanOptions，应走默认 fast budget
	_, err := engine.ScanWithReader(reader, types.ScanFull, callbacks)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if bruteForceTriggered {
		t.Error("老 API ScanWithReader 不应触发 brute-force（默认应是 fast path）")
	}
}
