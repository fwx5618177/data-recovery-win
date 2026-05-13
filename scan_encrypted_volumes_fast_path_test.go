package main

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"data-recovery/internal/apfs"
	"data-recovery/internal/bitlocker"
	"data-recovery/internal/btrfs"
	"data-recovery/internal/disk"
	"data-recovery/internal/hfsplus"
	"data-recovery/internal/luks"
	"data-recovery/internal/refs"
	"data-recovery/internal/veracrypt"
	"data-recovery/internal/volmgr"
)

// 这个测试文件锁住 ScanEncryptedVolumes 整条管线的"快速诊断不读盘"契约。
//
// 用户报的本质问题（v2.8.20~v2.8.25 都没修对）：在 welcome 页选盘时，
// app.ScanEncryptedVolumes 会跑一遍所有加密 / 容器卷探测。每个 scanner 都应该
// **默认 fast path**（只查 offset 0 或几个固定位置），但 v2.8.25 之前 ReFS
// 是唯一的例外 —— 无条件全盘扫，对 2TB SSD 跑 11 分钟 3 GB/s read storm。
//
// 用户的视角："我点了取消扫描磁盘还在读" —— 因为 ReFS 全盘扫和 scan engine 完全
// 独立，它在用户点选磁盘那一刻就开始了，scan engine 的 Stop 不可能停它。
//
// v2.8.26 给 ReFS 加了 FindOptions / BruteForce / ctx，对齐其他 scanner。本测试
// 锁死整条管线：在模拟 2TB 盘上，所有诊断 scanner 加起来必须 < 100 次 ReadAt，
// 完成时间 < 1 秒。任何未来引入"默认就全盘扫"的 scanner 都会让这个测试 FAIL。

// hugeMockDevice 模拟 2TB 物理盘 ——
//   - Size() 报 2 TB
//   - ReadAt 任意 offset 返回零数据（够触发签名 miss 让所有 scanner 走完）
//   - 每次 ReadAt 累加 reads 计数器，让测试断言"读盘次数"
//
// 关键：必须实现 disk.DiskReader 完整接口（Open/Close/ReadAt/Size/SectorSize/DevicePath）。
type hugeMockDevice struct {
	size  int64
	reads atomic.Int64
}

func (m *hugeMockDevice) Open() error  { return nil }
func (m *hugeMockDevice) Close() error { return nil }
func (m *hugeMockDevice) ReadAt(buf []byte, offset int64) (int, error) {
	m.reads.Add(1)
	if offset < 0 || offset >= m.size {
		return 0, io.EOF
	}
	// 返回零字节让所有签名 miss —— scanner 不会"误以为发现"卷然后做额外读
	for i := range buf {
		buf[i] = 0
	}
	end := offset + int64(len(buf))
	if end > m.size {
		return int(m.size - offset), io.EOF
	}
	return len(buf), nil
}
func (m *hugeMockDevice) Size() (int64, error) { return m.size, nil }
func (m *hugeMockDevice) SectorSize() int      { return 512 }
func (m *hugeMockDevice) DevicePath() string   { return "mock://2tb-disk" }

const fakeTwoTB = int64(2) * 1024 * 1024 * 1024 * 1024 // 2 TB

// TestScanEncryptedVolumes_PipelineIsFastOnHugeDevice 锁住整条诊断管线的"快速性"。
//
// 在模拟 2TB 盘上跑 app.ScanEncryptedVolumes 调用的全部 scanner（默认 opts），
// 断言：总 ReadAt 次数 < 100；总耗时 < 1 秒。
//
// 这一条龙跑完正是用户在 welcome 页点选磁盘时后端做的事 —— 慢一秒用户就感觉得到，
// 慢一分钟用户就会以为程序卡死/挂了。
//
// 历史 FAIL 案例：
//   v2.8.25- 之前：refs.FindVolumes 无脑全盘扫 → ReadAt 几十万次 → 11 分钟，FAIL
//   v2.8.26+ 起：所有 scanner 都默认 fast path → < 50 次 ReadAt → 毫秒级，PASS
//
// 任何新引入"默认就全盘扫"的 scanner（比如 future ZFS / NTFS volume-discovery /
// 等等被加进 ScanEncryptedVolumes 的）会让这个测试立刻 FAIL，保证 bug 不复活。
func TestScanEncryptedVolumes_PipelineIsFastOnHugeDevice(t *testing.T) {
	dev := &hugeMockDevice{size: fakeTwoTB}
	ctx := context.Background()

	start := time.Now()

	// 完全复刻 app.go ScanEncryptedVolumes 调的所有 scanner（同顺序、同 opts）
	// 任何改动 app.go 那个函数应该也改这里 —— 否则测试覆盖不到新加的 scanner
	_, _ = bitlocker.NewScanner(dev).FindVolumesFast()
	_, _ = hfsplus.NewScanner(dev).FindVolumes(ctx, hfsplus.FindOptions{})
	_, _ = refs.NewScanner(dev).FindVolumes(ctx, refs.FindOptions{})
	_, _ = apfs.NewScanner(dev).FindContainers(ctx, apfs.FindOptions{})
	_, _ = luks.Detect(dev, 0)
	_, _ = veracrypt.Detect(dev, 0)
	_ = volmgr.DetectAll(dev)

	elapsed := time.Since(start)
	reads := dev.reads.Load()

	// 慢一秒就是回归 —— 真盘上会被用户感知
	if elapsed > time.Second {
		t.Errorf("整套诊断耗时 %v（期望 < 1s）—— 某个 scanner 又开始全盘扫了", elapsed)
	}
	// 100 次 ReadAt 阈值留余量：当前实测 ~30 次。回归（比如有人忘了 BruteForce 开关）
	// 会瞬间窜到几十万 / 几百万。
	if reads > 100 {
		t.Errorf("整套诊断触发了 %d 次 ReadAt（期望 < 100）—— 全盘扫描回归", reads)
	}

	t.Logf("诊断管线性能：%d 次 ReadAt，耗时 %v", reads, elapsed)
}

// TestScanEncryptedVolumes_BruteForceModesRespectCtx 全套 scanner 的 brute-force
// 模式都必须能被 ctx.Cancel 立刻中断。这是用户场景里"我想停就停"的硬性要求。
//
// 历史问题：refs.FindVolumes 在 v2.8.25 没 ctx 参数，brute-force 路径无法被中断。
func TestScanEncryptedVolumes_BruteForceModesRespectCtx(t *testing.T) {
	type scannerCase struct {
		name string
		run  func(ctx context.Context, dev disk.DiskReader) error
	}

	cases := []scannerCase{
		{
			name: "ReFS",
			run: func(ctx context.Context, dev disk.DiskReader) error {
				_, err := refs.NewScanner(dev).FindVolumes(ctx, refs.FindOptions{BruteForce: true})
				return err
			},
		},
		{
			name: "APFS",
			run: func(ctx context.Context, dev disk.DiskReader) error {
				_, err := apfs.NewScanner(dev).FindContainers(ctx, apfs.FindOptions{BruteForce: true})
				return err
			},
		},
		{
			name: "HFS+",
			run: func(ctx context.Context, dev disk.DiskReader) error {
				_, err := hfsplus.NewScanner(dev).FindVolumes(ctx, hfsplus.FindOptions{BruteForce: true})
				return err
			},
		},
		{
			name: "Btrfs",
			run: func(ctx context.Context, dev disk.DiskReader) error {
				_, err := btrfs.NewScanner(dev).FindVolumes(ctx, btrfs.FindOptions{BruteForce: true})
				return err
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dev := &hugeMockDevice{size: fakeTwoTB}
			ctx, cancel := context.WithCancel(context.Background())
			cancel() // 立刻取消

			start := time.Now()
			err := c.run(ctx, dev)
			elapsed := time.Since(start)

			if err == nil {
				t.Errorf("%s: ctx 已 cancel 但 scanner 没返回 error", c.name)
			}
			if !errors.Is(err, context.Canceled) {
				// 有的 scanner 可能 return ctx.Err()，那是 context.Canceled
				// 这里宽松点：只要 err != nil 且 elapsed 很短就 OK
				t.Logf("%s: 返回 %v（接受任何非 nil 错误）", c.name, err)
			}
			// 即便允许提前 fast-path detect 一次，整体应在 100ms 内退（cancel 立刻生效）
			if elapsed > 100*time.Millisecond {
				t.Errorf("%s: ctx cancel 后耗时 %v 才返回 —— brute-force 没看 ctx", c.name, elapsed)
			}
			if dev.reads.Load() > 5 {
				t.Errorf("%s: ctx cancel 后仍读了 %d 次 —— brute-force 循环没在每轮看 ctx",
					c.name, dev.reads.Load())
			}
		})
	}
}

// TestScanEncryptedVolumes_NoScannerDefaultsToBruteForce 元测试 —— 显式检查每个
// scanner 的 default FindOptions{} 是否触发了"很多读"。这是把"默认 fast path"
// 当成全局不变量来锁。
//
// 如果将来有人加新 scanner 进 app.ScanEncryptedVolumes 但忘了 fast path 默认 ——
// 这里加一个 case 就能立刻爆出来。
func TestScanEncryptedVolumes_NoScannerDefaultsToBruteForce(t *testing.T) {
	type defaultCase struct {
		name string
		run  func(dev disk.DiskReader) error
	}

	cases := []defaultCase{
		{
			name: "BitLocker.FindVolumesFast",
			run: func(dev disk.DiskReader) error {
				_, err := bitlocker.NewScanner(dev).FindVolumesFast()
				return err
			},
		},
		{
			name: "HFS+.FindVolumes(default)",
			run: func(dev disk.DiskReader) error {
				_, err := hfsplus.NewScanner(dev).FindVolumes(context.Background(), hfsplus.FindOptions{})
				return err
			},
		},
		{
			name: "ReFS.FindVolumes(default)",
			run: func(dev disk.DiskReader) error {
				_, err := refs.NewScanner(dev).FindVolumes(context.Background(), refs.FindOptions{})
				return err
			},
		},
		{
			name: "APFS.FindContainers(default)",
			run: func(dev disk.DiskReader) error {
				_, err := apfs.NewScanner(dev).FindContainers(context.Background(), apfs.FindOptions{})
				return err
			},
		},
		{
			name: "Btrfs.FindVolumes(default)",
			run: func(dev disk.DiskReader) error {
				_, err := btrfs.NewScanner(dev).FindVolumes(context.Background(), btrfs.FindOptions{})
				return err
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dev := &hugeMockDevice{size: fakeTwoTB}
			if err := c.run(dev); err != nil {
				// 部分 scanner 可能 return 真错误（如 size 太大 etc）—— 不阻塞
				t.Logf("%s: err=%v（不关心，只关心读次数）", c.name, err)
			}
			reads := dev.reads.Load()
			// 一个真正的 fast path 应该 < 20 次 ReadAt（offset 0 + 可能几个固定位置）
			if reads > 20 {
				t.Errorf("%s 默认触发了 %d 次 ReadAt —— 不是 fast path！\n"+
					"如果这是新加的 scanner 必须给 FindOptions 加 BruteForce 默认 false",
					c.name, reads)
			}
		})
	}
}
