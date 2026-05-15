package disk

import (
	"bytes"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// flakyReader 模拟"某些扇区每次读都失败"的盘
type unstableMock struct {
	data      []byte
	badRanges [][2]int64 // [start, end) 区间的扇区永远 fail
	readCount atomic.Int64
}

func (m *unstableMock) Open() error  { return nil }
func (m *unstableMock) Close() error { return nil }
func (m *unstableMock) ReadAt(buf []byte, off int64) (int, error) {
	m.readCount.Add(1)
	end := off + int64(len(buf))
	// 真实 OS 行为：请求范围 overlap 任何坏扇区就整体 fail
	for _, r := range m.badRanges {
		if off < r[1] && end > r[0] {
			return 0, errors.New("simulated bad sector")
		}
	}
	if off >= int64(len(m.data)) {
		return 0, errors.New("EOF")
	}
	n := copy(buf, m.data[off:])
	return n, nil
}
func (m *unstableMock) Size() (int64, error) { return int64(len(m.data)), nil }
func (m *unstableMock) SectorSize() int      { return 512 }
func (m *unstableMock) DevicePath() string   { return "mock://unstable" }

func TestResilientReader_SkipsBadSectorsWithZeros(t *testing.T) {
	disk := make([]byte, 4096)
	for i := range disk {
		disk[i] = byte(i)
	}
	mock := &unstableMock{
		data:      disk,
		badRanges: [][2]int64{{1024, 1536}}, // 第 2 扇区永远坏
	}
	r := NewResilientReader(mock, 512, 2)

	got := make([]byte, 4096)
	n, err := r.ReadAt(got, 0)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != 4096 {
		t.Errorf("应读全 4096 字节, 实际 %d", n)
	}
	// 健康区域字节应一致
	if !bytes.Equal(got[0:1024], disk[0:1024]) {
		t.Error("健康区[0:1024] 不一致")
	}
	// 坏扇区应是 0
	for i := 1024; i < 1536; i++ {
		if got[i] != 0 {
			t.Errorf("坏扇区位置 %d 应为 0，实际 %d", i, got[i])
			break
		}
	}
	// 坏扇区之后的健康区
	if !bytes.Equal(got[1536:], disk[1536:]) {
		t.Error("坏扇区后的健康区不一致")
	}
	// BadSectors 列表应有 1 条
	bad := r.BadSectors()
	if len(bad) != 1 || bad[0].Offset != 1024 || bad[0].Size != 512 {
		t.Errorf("BadSectors=%+v", bad)
	}
}

func TestResilientReader_PassThroughOnHealthyDisk(t *testing.T) {
	disk := make([]byte, 4096)
	for i := range disk {
		disk[i] = byte(i ^ 0x55)
	}
	mock := &unstableMock{data: disk}
	r := NewResilientReader(mock, 512, 2)

	got := make([]byte, 4096)
	n, err := r.ReadAt(got, 0)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 4096 || !bytes.Equal(got, disk) {
		t.Error("健康盘应直接透传")
	}
	if len(r.BadSectors()) != 0 {
		t.Error("健康盘不应有 bad sectors")
	}
}

// TestResilientReader_FastSkipOnLargeBadRegion 锁住 v2.8.9 ddrescue-style fast-skip 性能契约：
//
// 大块全坏区域（多个 MB）不应逐扇区试 N 次 —— 那是死亡螺旋。adaptive doubling 后
// underlying.ReadAt 调用次数应是 O(log N) 级别（chunk 倍增），不是 O(N) 级别。
//
// 不验证"健康数据无丢失"—— ddrescue fast pass 接受边界粒度损失换速度。
// 真正强一致的边界恢复要走 trim/scrape pass（v2.9+ 单独实现）。
func TestResilientReader_FastSkipOnLargeBadRegion(t *testing.T) {
	const (
		diskSize   = 4 * 1024 * 1024 // 4MB
		badStart   = 64 * 1024       // 64KB 健康头
		badEnd     = 4 * 1024 * 1024 // 余下全坏
		badSectorN = (badEnd - badStart) / 512
	)
	disk := make([]byte, diskSize)
	for i := range disk {
		disk[i] = byte(i)
	}
	mock := &unstableMock{
		data:      disk,
		badRanges: [][2]int64{{badStart, badEnd}},
	}
	r := NewResilientReader(mock, 512, 1)

	got := make([]byte, diskSize)
	n, err := r.ReadAt(got, 0)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != diskSize {
		t.Errorf("应读全 %d 字节，实际 %d", diskSize, n)
	}

	// 健康头区必须完整（坏区之前的数据，0 边界丢失）
	if !bytes.Equal(got[0:badStart], disk[0:badStart]) {
		t.Error("坏区前健康头区损坏")
	}

	// 关键性能契约：调用次数应是 O(log N)，不是 O(N)
	// 无 fast-skip：>= badSectorN（每扇区 1 次）= 7936 次
	// 有 fast-skip（自适应倍增到 1MB 上限）：4 sector 试探 + ~12 chunk probe ≈ 16-30 次
	// + 8KB 健康头 = 16 次 healthy chunk reads（4MB block 一次性读 + 切扇区）
	// 容忍上限设 200 —— 给 mock + 健康区留余量
	if calls := mock.readCount.Load(); calls > 200 {
		t.Errorf("fast-skip 失效：underlying.ReadAt 调用 %d 次，应 ≤ 200（坏区 %d 扇区）", calls, badSectorN)
	}
}

// slowBadMock 在每次失败的 ReadAt 上加 fixed delay —— 模拟 TimeoutReader 的 8s 超时
// 在真实磁盘上的开销。用来给 fast-skip 算法做"实际墙钟时间"预算测试。
type slowBadMock struct {
	*unstableMock
	failureDelay time.Duration
}

func (m *slowBadMock) ReadAt(buf []byte, off int64) (int, error) {
	n, err := m.unstableMock.ReadAt(buf, off)
	if err != nil && !errors.Is(err, errEOFMarker) {
		time.Sleep(m.failureDelay)
	}
	return n, err
}

var errEOFMarker = errors.New("EOF") // 区分 EOF（无 sleep）和 bad sector（有 sleep）

// TestResilientReader_FastSkipBoundedTime 锁住 v2.8.9 fast-skip 的真实墙钟时间预算：
//
// 这是端到端**性能证明**：如果用模拟 TimeoutReader 50ms-per-failure 的 mock 读 4MB 全坏区，
// 没有 fast-skip：8192 次 ReadAt × 50ms = 410 秒
// 有 fast-skip （自适应倍增）：~20 次 ReadAt × 50ms = 1 秒
//
// 测试断言：墙钟时间 ≤ 30 秒（慢 CI 余量；本地实测 1s）。fail = fast-skip 退化
// （maxRetry 改回 2 / adaptive doubling 失效）—— 那就是 ~7 分钟级别的退化。
func TestResilientReader_FastSkipBoundedTime(t *testing.T) {
	const (
		diskSize     = 4 * 1024 * 1024 // 4MB
		failureDelay = 50 * time.Millisecond
		timeBudget   = 30 * time.Second
	)
	disk := make([]byte, diskSize)
	mock := &slowBadMock{
		unstableMock: &unstableMock{
			data:      disk,
			badRanges: [][2]int64{{0, diskSize}}, // 4MB 全坏
		},
		failureDelay: failureDelay,
	}
	r := NewResilientReader(mock, 512, 1)

	got := make([]byte, diskSize)
	start := time.Now()
	_, err := r.ReadAt(got, 0)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ReadAt should not error (0-fill bad sectors): %v", err)
	}
	if elapsed > timeBudget {
		t.Errorf("fast-skip 时间预算失败: %.2fs > %.2fs（4MB 全坏，每错 %v 延迟）",
			elapsed.Seconds(), timeBudget.Seconds(), failureDelay)
	}
	t.Logf("4MB 全坏区域耗时 %.2fs（fast-skip 工作正常，calls=%d）", elapsed.Seconds(), mock.readCount.Load())
}

// TestResilientReader_FastSkipMixedRegions 模拟用户场景：125GB 盘大部分健康 +
// 末端 10MB 坏。验证总扫描时间不会被坏区拖死。
//
// Mini 版：4MB 健康头 + 4MB 全坏尾。预算 30s（慢 CI 余量；本地实测 1s）。
// 如果坏区死亡螺旋：4MB 健康（瞬间）+ 4MB × 8192sec/MB = 32K 秒
// 如果 fast-skip 工作：4MB 健康 + 4MB / 1MB × delay = ~4 calls × delay
func TestResilientReader_FastSkipMixedRegions(t *testing.T) {
	const (
		diskSize     = 8 * 1024 * 1024 // 8MB
		badStart     = 4 * 1024 * 1024
		failureDelay = 50 * time.Millisecond
		timeBudget   = 30 * time.Second
	)
	disk := make([]byte, diskSize)
	for i := range disk {
		disk[i] = byte(i)
	}
	mock := &slowBadMock{
		unstableMock: &unstableMock{
			data:      disk,
			badRanges: [][2]int64{{badStart, diskSize}},
		},
		failureDelay: failureDelay,
	}
	r := NewResilientReader(mock, 512, 1)

	got := make([]byte, diskSize)
	start := time.Now()
	_, err := r.ReadAt(got, 0)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if elapsed > timeBudget {
		t.Errorf("混合健康+坏区时间预算失败: %.2fs > %.2fs", elapsed.Seconds(), timeBudget.Seconds())
	}
	// 健康头必须完整恢复
	if !bytes.Equal(got[0:badStart], disk[0:badStart]) {
		t.Error("健康头区损坏 —— fast-skip 误把健康区填了 0")
	}
	t.Logf("4MB 健康 + 4MB 全坏耗时 %.2fs，read calls=%d", elapsed.Seconds(), mock.readCount.Load())
}

// TestResilientReader_DefaultMaxRetryIsOne 锁住 v2.8.9 改默认 maxRetry 2→1 的契约。
// 这是死亡螺旋的核心修复 —— inline retry 极少救回真坏扇区，反而让坏扇区代价 ×2。
func TestResilientReader_DefaultMaxRetryIsOne(t *testing.T) {
	r := NewResilientReader(&unstableMock{}, 0, 0) // 全用 default
	if r.maxRetry != 1 {
		t.Errorf("v2.8.9: NewResilientReader 默认 maxRetry 应为 1（曾为 2，是死亡螺旋的源头），实际 %d", r.maxRetry)
	}
	if r.consecutiveFailureThreshold <= 0 {
		t.Errorf("consecutiveFailureThreshold 必须 > 0，实际 %d", r.consecutiveFailureThreshold)
	}
	if r.maxSkipChunkBytes <= 0 {
		t.Errorf("maxSkipChunkBytes 必须 > 0，实际 %d", r.maxSkipChunkBytes)
	}
}

// TestResilientReader_SkipModeRecoversWhenHealthyResumes 锁住跳过模式的 probe 退出契约：
//
// 跳过模式必须能在坏区结束后**通过 probe 成功**自动恢复到正常模式。否则后续大块健康区
// 会被全部 0 填充。这条比"无边界损失"弱 —— 接受跳过模式 chunk 内的边界损失，但
// chunk 之间能正确分辨健康区。
func TestResilientReader_SkipModeRecoversWhenHealthyResumes(t *testing.T) {
	const (
		diskSize = 4 * 1024 * 1024 // 4MB
		badStart = 1 * 1024 * 1024 // 1MB 健康头
		badEnd   = 2 * 1024 * 1024 // 1MB 坏区
		// 后 2MB 全健康
	)
	disk := make([]byte, diskSize)
	for i := range disk {
		disk[i] = byte(i ^ 0xAA)
	}
	mock := &unstableMock{
		data:      disk,
		badRanges: [][2]int64{{badStart, badEnd}},
	}
	r := NewResilientReader(mock, 512, 1)

	got := make([]byte, diskSize)
	_, err := r.ReadAt(got, 0)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}

	// 健康头区（1MB）必须完整
	if !bytes.Equal(got[0:badStart], disk[0:badStart]) {
		t.Error("坏区前健康头区损坏")
	}

	// 健康尾区（2MB）大部分必须正确恢复 —— 不要求 100%（边界粒度损失），但 ≥ 95% 字节匹配
	tailLen := diskSize - badEnd
	matching := 0
	for i := badEnd; i < diskSize; i++ {
		if got[i] == disk[i] {
			matching++
		}
	}
	if matching*100/tailLen < 95 {
		t.Errorf("尾区健康恢复不足：%d/%d 字节匹配（< 95%%），skip mode 没退出", matching, tailLen)
	}
}
