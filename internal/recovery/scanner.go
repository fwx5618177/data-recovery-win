package recovery

import (
	"context"

	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// FilesystemScanner 是每个文件系统扫描器必须实现的契约。
//
// 设计动机：原来 engine.go 单个 2219 行文件里塞了 NTFS / exFAT / FAT / ext4 /
// APFS / HFS+ 六套 scan + cache + recover 方法，每加一个 FS 主文件都要膨胀一次。
// 把每种 FS 的实现拆到自己的 ntfs_scan.go / exfat_scan.go / ... 后，Engine 只
// 充当协调器，增加新 FS 的成本 = 新增一个 *_scan.go 文件 + 在 ScanWithReader 里
// 多一段调用。符合 Open/Closed。
//
// 注意：当前实现并不强制 runtime 的 interface satisfaction（Engine 把每个 FS 的
// 方法当成自己的 method 一样调用），但接口本身记录了契约，方便 review / 新增 FS
// 时对照。未来如果要做依赖注入或测试替身，直接 `var _ FilesystemScanner = (*ntfsScanner)(nil)`
// 就行。
//
// 方法契约：
//
//   - Name() 给诊断日志用的短名，如 "ntfs"/"exfat"/"apfs"
//
//   - Scan() 枚举一个 FS 上的可恢复文件。必须：
//     ① 调用 onProgress 至少一次（哪怕只是 0%）保证前端进度条启动
//     ② 在发现每个文件时调用 onFound，同步 Engine 结果列表
//     ③ 把 "恢复源对象"（DataRun/extent 列表等）缓存到 Engine 的对应 map，
//     否则 Recover 阶段无法按来源找到文件的真实数据位置
//     ④ 遇到 ctx.Cancelled 要立刻返回已经收集到的部分 + ctx.Err()
//     ⑤ 若该磁盘上根本没有对应文件系统，返回 (nil, nil) 而不是错误
//
//   - Recover() 根据 file.ID 从缓存找到恢复源，把文件内容解压/拼段后写到
//     outputPath。失败返回普通 error；Partial（大小不匹配等）返回
//     *PartialWriteError 以便上层归入"低可靠"桶。
type FilesystemScanner interface {
	Name() string
	Scan(
		ctx context.Context,
		reader disk.DiskReader,
		onProgress func(types.ScanProgress),
		onFound func(*types.RecoveredFile),
	) ([]*types.RecoveredFile, error)
	Recover(file *types.RecoveredFile, outputPath string) error
}

// ——— 下面的 compile-time 断言保证各 FS 实现不会悄悄漂离接口 ———
//
// 原来 APFS / HFS+ 已经在独立文件里了，但 engine.go 里的 NTFS / exFAT / FAT /
// ext4 还没拆。本批次（Batch 1）把后四个也拆出去，并通过 adapter 满足此接口。
//
// 现阶段 adapter 是零成本的 thin-wrapper（内部直接委托到 Engine 上对应的 runXxx
// / recoverXxxFile 方法），目的是先把接口契约立起来，避免未来重构时实现漂移。

type ntfsScannerAdapter struct{ e *Engine }
type exfatScannerAdapter struct{ e *Engine }
type fatScannerAdapter struct{ e *Engine }
type extScannerAdapter struct{ e *Engine }
type apfsScannerAdapter struct{ e *Engine }
type hfsplusScannerAdapter struct{ e *Engine }

// 注：adapter 对外接口里没有 IncludeDeletedPartitions 参数；adapter 用的是默认（fast path only）
// 行为，跟 v2.8.8+ 默认模式一致。引擎主路径不走 adapter，走 ScanWithReader 直接调
// runXxxScan，那条路径才传 includeDeletedPartitions。

func (a *ntfsScannerAdapter) Name() string { return "ntfs" }
func (a *ntfsScannerAdapter) Scan(ctx context.Context, r disk.DiskReader, op func(types.ScanProgress), of func(*types.RecoveredFile)) ([]*types.RecoveredFile, error) {
	return a.e.runNTFSScan(ctx, r, 0, false, op, of)
}
func (a *ntfsScannerAdapter) Recover(file *types.RecoveredFile, out string) error {
	return a.e.recoverNTFSFile(file, out)
}

func (a *exfatScannerAdapter) Name() string { return "exfat" }
func (a *exfatScannerAdapter) Scan(ctx context.Context, r disk.DiskReader, op func(types.ScanProgress), of func(*types.RecoveredFile)) ([]*types.RecoveredFile, error) {
	return a.e.runEXFATScan(ctx, r, false, op, of)
}
func (a *exfatScannerAdapter) Recover(file *types.RecoveredFile, out string) error {
	return a.e.recoverEXFATFile(file, out)
}

func (a *fatScannerAdapter) Name() string { return "fat" }
func (a *fatScannerAdapter) Scan(ctx context.Context, r disk.DiskReader, op func(types.ScanProgress), of func(*types.RecoveredFile)) ([]*types.RecoveredFile, error) {
	return a.e.runFATScan(ctx, r, false, op, of)
}
func (a *fatScannerAdapter) Recover(file *types.RecoveredFile, out string) error {
	return a.e.recoverFATFile(file, out)
}

func (a *extScannerAdapter) Name() string { return "ext" }
func (a *extScannerAdapter) Scan(ctx context.Context, r disk.DiskReader, op func(types.ScanProgress), of func(*types.RecoveredFile)) ([]*types.RecoveredFile, error) {
	return a.e.runEXTScan(ctx, r, op, of)
}
func (a *extScannerAdapter) Recover(file *types.RecoveredFile, out string) error {
	return a.e.recoverEXTFile(file, out)
}

func (a *apfsScannerAdapter) Name() string { return "apfs" }
func (a *apfsScannerAdapter) Scan(ctx context.Context, r disk.DiskReader, op func(types.ScanProgress), of func(*types.RecoveredFile)) ([]*types.RecoveredFile, error) {
	return a.e.runAPFSScan(ctx, r, op, of)
}
func (a *apfsScannerAdapter) Recover(file *types.RecoveredFile, out string) error {
	return a.e.recoverAPFSFile(file, out)
}

func (a *hfsplusScannerAdapter) Name() string { return "hfsplus" }
func (a *hfsplusScannerAdapter) Scan(ctx context.Context, r disk.DiskReader, op func(types.ScanProgress), of func(*types.RecoveredFile)) ([]*types.RecoveredFile, error) {
	return a.e.runHFSPlusScan(ctx, r, op, of)
}
func (a *hfsplusScannerAdapter) Recover(file *types.RecoveredFile, out string) error {
	return a.e.recoverHFSPlusFile(file, out)
}

// Compile-time 保证六个 adapter 都满足接口；某个 FS 的方法签名漂了 build 就红。
var (
	_ FilesystemScanner = (*ntfsScannerAdapter)(nil)
	_ FilesystemScanner = (*exfatScannerAdapter)(nil)
	_ FilesystemScanner = (*fatScannerAdapter)(nil)
	_ FilesystemScanner = (*extScannerAdapter)(nil)
	_ FilesystemScanner = (*apfsScannerAdapter)(nil)
	_ FilesystemScanner = (*hfsplusScannerAdapter)(nil)
)

