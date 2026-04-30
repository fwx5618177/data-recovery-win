package recovery

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// 这一组测试是 v2.8.11 加的，专门防止"v2.8.8 只修了 ntfs/exfat/fat 但 ext/apfs/
// hfsplus/btrfs 的 brute-force 还在偷跑全盘 IO"这个 bug 复现。
//
// 用户实测：v2.8.10 在 128GB U 盘上扫描卡 11.5 小时，根因就是 ext4 brute-force 在
// fast path 之外**永远跑**全盘扫描。修复后所有 FS scanner 一致 opt-in。

// countingMock 跟踪 underlying.ReadAt 调用次数 + 阻塞模拟。
type countingMock struct {
	data      []byte
	readCount atomic.Int64
}

func (m *countingMock) Open() error  { return nil }
func (m *countingMock) Close() error { return nil }
func (m *countingMock) ReadAt(buf []byte, off int64) (int, error) {
	m.readCount.Add(1)
	if off >= int64(len(m.data)) {
		return 0, nil
	}
	return copy(buf, m.data[off:]), nil
}
func (m *countingMock) Size() (int64, error) { return int64(len(m.data)), nil }
func (m *countingMock) SectorSize() int      { return 512 }
func (m *countingMock) DevicePath() string   { return "mock://counting" }

var _ disk.DiskReader = (*countingMock)(nil)

// TestScan_DefaultMode_NoFullDiskBruteForce 锁住 v2.8.11 核心架构契约：
//
// 默认模式（IncludeDeletedPartitions=false）下，对一个 32MB 的全 0 镜像，**所有** FS scanner
// 都不应该做全盘 brute-force。如果哪个 FS 还在偷跑全盘扫，underlying.ReadAt 调用次数会爆。
//
// 没有 brute-force：每个 FS 只读 ~1KB（offset 0 superblock/boot sector）+ carver 一次顺序扫
//   总计 ~7 个小读 + carver 的 ~32MB / 4MB = 8 个块读 = 15-30 次 ReadAt
//
// 如果有任何 FS 偷跑全盘 brute-force：32MB / 1MB step = 32 次 × N 个 FS = 100+ 次 ReadAt
//
// 这个测试设上限 80 次 underlying ReadAt。失败 = 某个 FS 没有 gating（比如新加的）。
func TestScan_DefaultMode_NoFullDiskBruteForce(t *testing.T) {
	const imgSize = 32 * 1024 * 1024 // 32MB
	mock := &countingMock{data: make([]byte, imgSize)}
	reader := disk.NewResilientReader(mock, 512, 0)
	engine := NewEngine()

	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, ScanCallbacks{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	calls := mock.readCount.Load()
	// Carver 占大头：32MB / 4MB block + ~64KB last partial = 8-9 reads
	// 各 FS fast-path: 大约 1-3 reads each（ParseBootSector / Detect）
	// 7 个 FS × 3 reads = 21 reads + carver 9 = ~30
	// 给 80 次的余量；超 80 = 某个 FS 在偷跑 brute-force。
	const limit = 80
	if calls > limit {
		t.Errorf("默认模式下 underlying.ReadAt 被调用 %d 次（应 ≤ %d）—— 某 FS scanner 在偷跑全盘 brute-force", calls, limit)
		t.Logf("提示：v2.8.11 加了 ext4 / apfs / hfsplus / btrfs 的 BruteForce 门控。如果以后加新 FS scanner，记得套同样的 FindOptions{BruteForce} 模式。")
	}
}

// TestScan_ForensicMode_TriggersAllFSBruteForce 锁住反向契约：
//
// 取证模式（IncludeDeletedPartitions=true）下，**每个** 支持 brute-force 的 FS 都应该真触发
// brute-force。这条 fail = forensic 模式名存实亡，IncludeDeletedPartitions 没透传到该 FS。
func TestScan_ForensicMode_TriggersAllFSBruteForce(t *testing.T) {
	const imgSize = 4 * 1024 * 1024
	mock := &countingMock{data: make([]byte, imgSize)}
	reader := disk.NewResilientReader(mock, 512, 0)
	engine := NewEngine()

	var (
		mu             sync.Mutex
		bruteForcePhasesSeen = make(map[string]bool)
	)
	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			mu.Lock()
			defer mu.Unlock()
			if strings.Contains(p.CurrentFile, "已删除") {
				bruteForcePhasesSeen[p.Phase] = true
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

	// 期望 brute-force 触发的 FS（在 mock 逻辑盘上）：exfat / fat / ext / apfs / hfsplus / btrfs
	// NTFS 除外：NTFS brute-force 在 resolveNTFSPartitions 里有额外的 isPhysicalDrivePath() 守卫，
	// 因为逻辑卷没有 MBR/GPT 可丢；这个守卫本身是 v2.8.7 之前就存在的设计，不是 v2.8.11 的事。
	mustHave := []string{"exfat", "fat", "ext", "apfs", "hfsplus", "btrfs"}
	for _, phase := range mustHave {
		if !bruteForcePhasesSeen[phase] {
			t.Errorf("取证模式下 %s 阶段没触发 brute-force —— IncludeDeletedPartitions 没透传到 run%sScan", phase, strings.ToUpper(phase[:1])+phase[1:])
		}
	}
}

// TestScan_DefaultMode_TimeBudget_NoBruteForce 锁住"默认模式不会因为 FS scanner 全盘扫而拖慢"。
//
// 模拟用户场景：32MB 镜像，每次 ReadAt 加 5ms 延迟（模拟较慢 USB 盘）。
//
// 没 brute-force：~30 reads × 5ms = 150ms + carver scan 时间 ≈ 总 1-3s
// 任何 FS 偷跑 32MB brute-force：每 FS = 32MB / 1MB step × 5ms = 160ms × 5 个 FS = 800ms+
//
// 设 5 秒上限，失败 = 整体架构有 FS 在背后偷跑全盘 IO。
func TestScan_DefaultMode_TimeBudget_NoBruteForce(t *testing.T) {
	const (
		imgSize    = 32 * 1024 * 1024
		readDelay  = 5 * time.Millisecond
		timeBudget = 5 * time.Second
	)
	mock := &delayedMock{data: make([]byte, imgSize), delay: readDelay}
	reader := disk.NewResilientReader(mock, 512, 0)
	engine := NewEngine()

	start := time.Now()
	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, ScanCallbacks{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if elapsed > timeBudget {
		t.Errorf("默认模式 32MB 镜像 (5ms-per-read) 耗时 %.2fs > %.2fs 预算 —— 某 FS 在偷跑 brute-force",
			elapsed.Seconds(), timeBudget.Seconds())
	}
	t.Logf("默认模式 32MB 镜像扫描 %.2fs (read calls=%d)", elapsed.Seconds(), mock.readCount.Load())
}

// TestScan_NonRegressing_UserScenario_128GBLogicalDrive 模拟用户实际场景：
// 128MB 逻辑卷（缩比版，因测试不能真用 128GB 内存）+ 完全不像任何 FS 的内容。
//
// 这是用户报 bug 那个场景的 1000× 缩比版。如果用户真的 12 小时卡死，缩比版会显
// 示出该问题。
//
// 期望：≤ 30 秒完成（默认模式不做全盘 brute-force；race 模式下 carver 慢 ~30×）
// 用户实测如果 12 小时卡死 → 这个测试会卡几秒到几分钟，明显异常。
func TestScan_NonRegressing_UserScenario_128GBLogicalDrive(t *testing.T) {
	const (
		imgSize    = 128 * 1024 * 1024 // 128MB（128GB 的 1000× 缩比）
		timeBudget = 30 * time.Second
	)
	mock := &countingMock{data: make([]byte, imgSize)}
	reader := disk.NewResilientReader(mock, 512, 0)
	engine := NewEngine()

	start := time.Now()
	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, ScanCallbacks{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if elapsed > timeBudget {
		t.Errorf("128MB 镜像扫描耗时 %.2fs > %.2fs 预算 —— 用户场景缩比版仍可能卡死", elapsed.Seconds(), timeBudget.Seconds())
	}
	t.Logf("128MB 镜像扫描 %.2fs (read calls=%d)", elapsed.Seconds(), mock.readCount.Load())
}

// delayedMock 在每次 ReadAt 上加固定延迟，模拟慢盘
type delayedMock struct {
	data      []byte
	delay     time.Duration
	readCount atomic.Int64
}

func (m *delayedMock) Open() error  { return nil }
func (m *delayedMock) Close() error { return nil }
func (m *delayedMock) ReadAt(buf []byte, off int64) (int, error) {
	m.readCount.Add(1)
	time.Sleep(m.delay)
	if off >= int64(len(m.data)) {
		return 0, nil
	}
	return copy(buf, m.data[off:]), nil
}
func (m *delayedMock) Size() (int64, error) { return int64(len(m.data)), nil }
func (m *delayedMock) SectorSize() int      { return 512 }
func (m *delayedMock) DevicePath() string   { return "mock://delayed" }

// 编译期断言：确保两个 mock 都满足 DiskReader 接口
var (
	_ disk.DiskReader = (*countingMock)(nil)
	_ disk.DiskReader = (*delayedMock)(nil)
)
