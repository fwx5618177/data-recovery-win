package disk

import (
	"bytes"
	"errors"
	"sync/atomic"
	"testing"
)

// flakyReader 模拟"某些扇区每次读都失败"的盘
type unstableMock struct {
	data       []byte
	badRanges  [][2]int64 // [start, end) 区间的扇区永远 fail
	readCount  atomic.Int64
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

// TestResilientReader_SkipModeRecoversWhenHealthyResumes 锁住跳过模式的 probe 退出契约：
//
// 跳过模式必须能在坏区结束后**通过 probe 成功**自动恢复到正常模式。否则后续大块健康区
// 会被全部 0 填充。这条比"无边界损失"弱 —— 接受跳过模式 chunk 内的边界损失，但
// chunk 之间能正确分辨健康区。
func TestResilientReader_SkipModeRecoversWhenHealthyResumes(t *testing.T) {
	const (
		diskSize   = 4 * 1024 * 1024 // 4MB
		badStart   = 1 * 1024 * 1024 // 1MB 健康头
		badEnd     = 2 * 1024 * 1024 // 1MB 坏区
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
