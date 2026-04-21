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
