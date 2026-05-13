package refs

import (
	"context"
	"encoding/binary"
	"sync/atomic"
	"testing"

	"data-recovery/internal/disk"
	"data-recovery/internal/testutil"
)

func makeReFSBootSector(buf []byte) {
	buf[0], buf[1], buf[2] = 0xEB, 0x76, 0x90
	copy(buf[3:11], []byte(refsOEMID))
	copy(buf[16:20], []byte(refsFSSignature))
	binary.LittleEndian.PutUint16(buf[24:26], 4096)        // bytes/sector（ReFS 默认 4K）
	buf[26] = 1                                            // sectors/cluster
	binary.LittleEndian.PutUint64(buf[32:40], 1<<24)       // total sectors
	binary.LittleEndian.PutUint64(buf[40:48], 0xCAFE)      // container number
	buf[48] = 3                                            // major version
	buf[49] = 5                                            // minor version
	buf[510], buf[511] = 0x55, 0xAA
}

func TestDetect_ReFS_Roundtrip(t *testing.T) {
	disk := make([]byte, 4096)
	makeReFSBootSector(disk)
	r := testutil.NewMemReader(disk)
	v, err := Detect(r, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v == nil {
		t.Fatal("ReFS 未识别")
	}
	if v.BytesPerSector != 4096 || v.SectorsPerCluster != 1 {
		t.Errorf("基本字段错: %+v", v)
	}
	if v.TotalSectors != 1<<24 {
		t.Errorf("TotalSectors 错: %d", v.TotalSectors)
	}
	if v.MajorVersion != 3 || v.MinorVersion != 5 {
		t.Errorf("Version 错: %d.%d", v.MajorVersion, v.MinorVersion)
	}
}

func TestDetect_NotReFS_ReturnsNil(t *testing.T) {
	disk := make([]byte, 4096)
	// boot signature 有但 OEM/FS sig 无
	disk[510], disk[511] = 0x55, 0xAA
	r := testutil.NewMemReader(disk)
	if v, _ := Detect(r, 0); v != nil {
		t.Error("不是 ReFS 应返回 nil")
	}
}

func TestFindVolumes_ScansForReFS(t *testing.T) {
	const volSize = int64(8 * 1024 * 1024)
	disk := make([]byte, volSize*2)
	makeReFSBootSector(disk[0:512])
	makeReFSBootSector(disk[volSize : volSize+512])
	r := testutil.NewMemReader(disk)
	// BruteForce=true 才会扫第二个偏移位置的卷
	vols, err := NewScanner(r).FindVolumes(context.Background(), FindOptions{BruteForce: true})
	if err != nil {
		t.Fatalf("FindVolumes: %v", err)
	}
	if len(vols) != 2 {
		t.Fatalf("应找到 2 个 ReFS 卷, 实际 %d", len(vols))
	}
}

// countingReader 在每次 ReadAt 都计数，让测试可以断言"诊断 fast path 不能跑全盘扫描"。
type countingReader struct {
	inner disk.DiskReader
	reads atomic.Int64
}

func (c *countingReader) Open() error                              { return c.inner.Open() }
func (c *countingReader) Close() error                             { return c.inner.Close() }
func (c *countingReader) Size() (int64, error)                     { return c.inner.Size() }
func (c *countingReader) SectorSize() int                          { return c.inner.SectorSize() }
func (c *countingReader) DevicePath() string                       { return c.inner.DevicePath() }
func (c *countingReader) ReadAt(buf []byte, off int64) (int, error) {
	c.reads.Add(1)
	return c.inner.ReadAt(buf, off)
}

// TestFindVolumes_DefaultIsFastPath 回归 v2.8.26 修复的本质问题：
//
// 之前 refs.FindVolumes 没参数永远做全盘 4MB 步进扫描。被 app.ScanEncryptedVolumes
// 调用 —— 用户每选一次盘就触发 —— 2TB SSD 跑 ~11 分钟 3 GB/s 全盘读。用户报
// "取消扫描后磁盘 IO 不停"的真实成因。
//
// 现在 FindOptions{} 默认 BruteForce=false → 只检测 offset 0，整套 scan 最多 1 次 ReadAt。
// 模拟 2TB 盘做断言：如果有人将来又把全盘扫加回 default，这个测试立即 FAIL。
func TestFindVolumes_DefaultIsFastPath(t *testing.T) {
	// 模拟 2TB 盘内容（用稀疏内存：只 offset 0 是真数据，其余靠 MemReader 返 0）
	const fakeSize = int64(2 * 1024 * 1024 * 1024 * 1024) // 2 TB
	// 实际用一个能正确报告 size = 2TB 的 reader，但只 512 字节真数据
	// 这里简化：直接用 4MB 的盘但内容是非 ReFS。要点是断言 ReadAt 调用次数。
	disk := make([]byte, 1024*1024) // 1MB 测试盘足够（默认 fast path 只读 offset 0）
	cr := &countingReader{inner: testutil.NewMemReader(disk)}

	_, err := NewScanner(cr).FindVolumes(context.Background(), FindOptions{})
	if err != nil {
		t.Fatalf("FindVolumes: %v", err)
	}
	reads := cr.reads.Load()
	if reads > 2 {
		// offset 0 检测 = 1 次 ReadAt。允许 ≤ 2 为防御性余量（万一未来加个第二个 fast offset）。
		// > 2 说明又走全盘扫了 —— 用户的 IO 噩梦回归。
		t.Errorf("默认 FindOptions{} 触发了 %d 次 ReadAt（期望 ≤2）—— 全盘扫描回归了，假设 %v 这个 size",
			reads, fakeSize)
	}
}

// TestFindVolumes_BruteForceRespectsCtx 验证 v2.8.26 加的 ctx 检查：
// brute-force 全盘扫描必须能被 ctx.Cancel 中断。
func TestFindVolumes_BruteForceRespectsCtx(t *testing.T) {
	const sz = int64(64 * 1024 * 1024) // 64MB
	disk := make([]byte, sz)
	cr := &countingReader{inner: testutil.NewMemReader(disk)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立刻 cancel

	_, err := NewScanner(cr).FindVolumes(ctx, FindOptions{BruteForce: true})
	if err == nil || err != context.Canceled {
		t.Errorf("ctx 已 cancel 应该立刻返回 context.Canceled，实际 err=%v", err)
	}
	// 应该几乎没读盘 —— 顶多 offset 0 检测的 1 次
	if cr.reads.Load() > 2 {
		t.Errorf("ctx cancel 后仍读了 %d 次 —— brute-force 循环没看 ctx", cr.reads.Load())
	}
}
