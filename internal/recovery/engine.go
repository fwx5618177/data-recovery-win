package recovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"data-recovery/internal/carver"
	"data-recovery/internal/disk"
	"data-recovery/internal/exfat"
	"data-recovery/internal/ext4"
	"data-recovery/internal/fat"
	"data-recovery/internal/logging"
	"data-recovery/internal/ntfs"
	"data-recovery/internal/signature"
	"data-recovery/internal/types"
	"data-recovery/internal/validator"
)

// logger 为本包的结构化 logger，所有日志统一加 component=engine 便于过滤。
var logger = logging.L().With("component", "engine")

// ScanCallbacks 扫描回调函数集合
type ScanCallbacks struct {
	OnProgress  func(types.ScanProgress)
	OnFileFound func(*types.RecoveredFile)
}

// RecoverCallbacks 恢复回调函数集合
type RecoverCallbacks struct {
	OnProgress func(types.RecoveryProgress)
}

// FileRecoveryState 单个文件的恢复最终状态。
type FileRecoveryState string

const (
	RecoveryStateSuccess FileRecoveryState = "success"
	RecoveryStateFailed  FileRecoveryState = "failed"
	RecoveryStatePartial FileRecoveryState = "partial"
	RecoveryStateSkipped FileRecoveryState = "skipped"
)

// FileRecoveryRecord 记录一次恢复操作中单个文件的落地情况，
// 用于前端展示失败清单和"只重试失败文件"功能。
type FileRecoveryRecord struct {
	FileID      string            `json:"fileId"`
	FileName    string            `json:"fileName"`
	Category    string            `json:"category"`
	Size        int64             `json:"size"`
	SizeHuman   string            `json:"sizeHuman"`
	State       FileRecoveryState `json:"state"`
	OutputPath  string            `json:"outputPath,omitempty"`
	Message     string            `json:"message,omitempty"`
	DurationMs  int64             `json:"durationMs"`
	CompletedAt time.Time         `json:"completedAt"`
}

// RecoveryResult 恢复操作的结果汇总。
type RecoveryResult struct {
	Succeeded     int `json:"success"`       // 完整恢复 + validator 判 valid
	LowConfidence int `json:"lowConfidence"` // 走 _low_confidence/ 子目录（validator 判不完全可靠）
	Partial       int `json:"partial"`       // 大小不完整恢复
	Failed        int `json:"failed"`        // 写盘失败 / 读源盘出错
	Skipped       int `json:"skipped"`       // validator 判 invalid → 拒绝交付
	Duplicates    int `json:"duplicates"`    // 跨源 SHA-256 去重数量
	Total         int `json:"total"`
	Records       []*FileRecoveryRecord `json:"records"`
}

type ntfsRecoverySource struct {
	Entry           *ntfs.MFTEntry
	Boot            *ntfs.BootSector
	PartitionOffset int64
}

// exfatRecoverySource 保存 exFAT 文件恢复所需的一切：
// 起始簇 / 分区偏移 / boot sector（算 cluster→byte 要）。
type exfatRecoverySource struct {
	Entry           exfat.DirEntry
	Boot            *exfat.BootSector
	PartitionOffset int64
}

// fatRecoverySource 保存 FAT12/16/32 文件恢复所需
type fatRecoverySource struct {
	Entry           fat.DirEntry
	Boot            *fat.BootSector
	PartitionOffset int64
}

// extRecoverySource 保存 ext2/3/4 文件恢复所需 —— inode + 超块 + 块组描述符
type extRecoverySource struct {
	Inode      *ext4.Inode
	SuperBlock *ext4.SuperBlock
	GroupDescs []ext4.GroupDesc
}

// Engine 恢复引擎 — 整个系统的顶层协调器
type Engine struct {
	mu sync.RWMutex

	sigDB     *signature.SignatureDB
	reader    disk.DiskReader
	carverEng *carver.Engine
	ntfsScn   *ntfs.Scanner
	valid     *validator.Validator
	writer    *SafeWriter

	// NTFS 扫描缓存，用于恢复阶段
	ntfsSources map[string]ntfsRecoverySource

	// exFAT 扫描缓存，用于恢复阶段
	exfatSources map[string]exfatRecoverySource

	// FAT12/16/32 扫描缓存，用于恢复阶段
	fatSources map[string]fatRecoverySource

	// ext2/3/4 扫描缓存
	extSources map[string]extRecoverySource

	// APFS 扫描缓存（每个文件按 extent 列表恢复）
	apfsSources map[string]apfsRecoverySource

	// FileVault VEK：volume UUID → VEK 字节，用户 unlock 后注入让 FileVault 卷也能枚举
	apfsVEKs map[[16]byte][]byte

	// HFS+ 扫描缓存（每个文件按 fork extents 恢复）
	hfsplusSources map[string]hfsplusRecoverySource

	// Btrfs 扫描缓存（每个文件按 extent 列表 + chunk catalog 恢复）
	btrfsSources map[string]btrfsRecoverySource

	// 加密卷 reader 的 sector cache 引用（如果当前扫描走加密卷链路）。
	// ScanWithReader 时通过类型断言填充；EncryptedReaderCacheStats() 给前端
	// 取实时命中率展示。
	cacheStatsReader cacheStatsProvider

	results    []*types.RecoveredFile
	scanning   bool
	recovering bool

	// 最近一次恢复操作的每文件结果，供前端展示失败清单和执行重试
	lastRecovery []*FileRecoveryRecord

	scanCancel    context.CancelFunc
	recoverCancel context.CancelFunc

	// scanDone 是当前扫描的"真正退出"信号。v2.8.24 加 —— 结构性修复：
	// 之前 Engine.Stop 只 poll e.scanning flag 10s 超时返回，把"扫描已停"假象
	// 报给前端但 goroutine 还活着持续读盘。现在 ScanWithReaderOptions 启动时
	// 创建这个 channel，defer 时 close 之；Stop 同步等它 close。无 timeout —
	// 卡死时宁可 IPC 挂起让用户看到"停止中..."，也不能撒谎说"已停"实际还在读。
	//
	// 为 nil 时表示当前没有扫描在跑（初始 / 上次 Done 后未清）。
	scanDone chan struct{}

	// resilientReader 当前扫描会话用的带坏块保护的 reader（由 Scan 自动包装）
	// 用来在扫完后汇报 BadSectors 给前端"坏扇区清单"UI
	resilientReader *disk.ResilientReader

	// 本次扫描的 carver 起点（0 = 全盘扫，>0 = 断点续扫）
	// persistLoop 靠 CurrentCarverOffset() 拉当前 carver 位置写 session
	carverStartOffset int64

	// 下次 Scan 启动时 carver 起点，消费一次即清零（SetResumeCarverOffset 设置）
	// 避免重复使用同一个 resume 点
	nextResumeCarverOffset int64

	// NAS 会话池：Batch 2 新增的 SMB/NFS 扫描持有的远端会话
	// Shutdown 时统一 Close；Recover 阶段按 nasSources[id] 查 session 拷文件
	nasSMBSessions []*netfsSMBSession // type alias：见 nas_scan.go 的 import
	nasNFSSessions []*netfsNFSSession
	nasSources     map[string]NASRecoverySource

	// iOS 备份会话池（Batch 3）：一次扫描对应一个 *ios.Session；Shutdown 时 Close（删临时明文 Manifest.db）
	iosSessions []*iosSessionAlias
	iosSources  map[string]iosRecoverySource

	// Android `.ab` 备份池（Batch 4）。Backup 不持有 fd（每次 reopen），但持有 master key 内存
	// Shutdown 时清密钥
	androidBackups []*androidBackupAlias
	androidSources map[string]androidRecoverySource
}

// NewEngine 创建新的恢复引擎实例
func NewEngine() *Engine {
	return &Engine{
		sigDB: signature.NewSignatureDB(),
	}
}

// SetAPFSVEK 注入 FileVault 卷的 VEK；volumeUUID 是 apfs_superblock.uuid（大端 GUID 字节）。
// 调用时机：用户在 UI 输入密码后、App 用 keybag 解出 VEK → 调这个方法把 VEK 挂到 engine，
// 随后 engine 的 APFS scan 路径自动对该 UUID 卷启用 EncryptedReader。
func (e *Engine) SetAPFSVEK(volumeUUID [16]byte, vek []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.apfsVEKs == nil {
		e.apfsVEKs = make(map[[16]byte][]byte)
	}
	e.apfsVEKs[volumeUUID] = vek
}

func (e *Engine) getAPFSVEK(volumeUUID [16]byte) []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.apfsVEKs[volumeUUID]
}

// IsScanning 返回当前是否正在扫描
func (e *Engine) IsScanning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.scanning
}

// phaseBudget 各阶段在总进度条上的起止百分比。
//
// 为什么需要双套预算：默认模式（fast path only）下 FS scan 是毫秒级，carver 是真实 IO 大头；
// 取证模式（brute-force on）下 ntfs/exfat/fat 各跑一遍全盘 IO，预算需要让 brute-force 阶段
// 占大部分。v2.8.7 之前用单套预算（FAT 只占 0.5%）→ 用户看到 14% 卡死十几小时。
type phaseBudget struct {
	ntfsStart, ntfsEnd         float64
	exfatStart, exfatEnd       float64
	fatStart, fatEnd           float64
	extStart, extEnd           float64
	apfsStart, apfsEnd         float64
	hfsplusStart, hfsplusEnd   float64
	btrfsStart, btrfsEnd       float64
	carverStart, carverEnd     float64
	validateStart, validateEnd float64
}

// fastBudget：默认模式（不做 brute-force）。FS scan 都是毫秒级，carver 占 86% 的进度条
// 因为它确实占 ~95% 的实际耗时。
var fastBudget = phaseBudget{
	ntfsStart: 0, ntfsEnd: 2,
	exfatStart: 2, exfatEnd: 4,
	fatStart: 4, fatEnd: 5,
	extStart: 5, extEnd: 6,
	apfsStart: 6, apfsEnd: 7,
	hfsplusStart: 7, hfsplusEnd: 8,
	btrfsStart: 8, btrfsEnd: 9,
	carverStart: 9, carverEnd: 95,
	validateStart: 95, validateEnd: 100,
}

// forensicBudget：取证模式（IncludeDeletedPartitions=true）。
// ntfs/exfat/fat 各做一遍全盘 brute-force IO + carver 第四遍全盘 IO，所以四块平均分预算。
var forensicBudget = phaseBudget{
	ntfsStart: 0, ntfsEnd: 25,
	exfatStart: 25, exfatEnd: 50,
	fatStart: 50, fatEnd: 70,
	extStart: 70, extEnd: 72,
	apfsStart: 72, apfsEnd: 74,
	hfsplusStart: 74, hfsplusEnd: 76,
	btrfsStart: 76, btrfsEnd: 78,
	carverStart: 78, carverEnd: 95,
	validateStart: 95, validateEnd: 100,
}

// Scan 主扫描方法，根据扫描模式协调各子模块完成磁盘扫描
//
// 参数:
//   - drivePath:  磁盘设备路径
//   - mode:       扫描模式 (quick/deep/full)
//   - callbacks:  扫描回调函数集合
//
// 默认 IncludeDeletedPartitions=false（行业标准 Quick scan 行为）。
// 想要 forensic 模式找已删除分区的 caller 用 ScanWithOptions / ScanWithReaderOptions。
//
// 返回扫描结果汇总和可能的错误
func (e *Engine) Scan(
	drivePath string,
	mode types.ScanMode,
	callbacks ScanCallbacks,
) (*types.ScanResult, error) {
	return e.ScanWithOptions(drivePath, types.ScanOptions{Mode: mode}, callbacks)
}

// ScanWithOptions 是 Scan 的完整版，支持 ScanOptions 细粒度控制（比如 forensic 模式）。
func (e *Engine) ScanWithOptions(
	drivePath string,
	opts types.ScanOptions,
	callbacks ScanCallbacks,
) (*types.ScanResult, error) {
	base := disk.NewReader(drivePath)
	if err := base.Open(); err != nil {
		return nil, fmt.Errorf("打开磁盘设备失败: %w", err)
	}
	// 包两层保护：
	//   1. TimeoutReader: 单次 ReadAt 超时 8s → 把 driver 层 hang 当坏块
	//   2. ResilientReader: 遇坏块按扇区切分重试 2 次，仍失败就 0 填充 + 记录
	// 链路：Engine → ResilientReader → TimeoutReader → 平台 reader
	reader := disk.NewResilientReader(disk.NewTimeoutReader(base, 0), int64(base.SectorSize()), 0)
	defer func() {
		if err := base.Close(); err != nil {
			logger.Warn("关闭磁盘设备失败", "err", err)
		}
	}()
	e.mu.Lock()
	e.resilientReader = reader
	e.mu.Unlock()
	return e.ScanWithReaderOptions(reader, opts, callbacks)
}

// ScanWithReader 与 Scan 相同，但 DiskReader 由调用方提供（已打开）。
//
// 给"需要在原始磁盘之上再套一层"的场景用，典型的是 BitLocker：
//
//	物理盘 → bitlocker.DecryptingReader（透明解密）→ ScanWithReader
//
// 调用方负责 reader 的生命周期（Open/Close 都由调用方掌控）。
//
// 默认 IncludeDeletedPartitions=false（同 Scan）。Forensic 模式用 ScanWithReaderOptions。
func (e *Engine) ScanWithReader(
	reader disk.DiskReader,
	mode types.ScanMode,
	callbacks ScanCallbacks,
) (*types.ScanResult, error) {
	return e.ScanWithReaderOptions(reader, types.ScanOptions{Mode: mode}, callbacks)
}

// ScanWithReaderOptions 是 ScanWithReader 的完整版，支持 ScanOptions。
func (e *Engine) ScanWithReaderOptions(
	reader disk.DiskReader,
	opts types.ScanOptions,
	callbacks ScanCallbacks,
) (*types.ScanResult, error) {
	mode := opts.Mode
	if reader == nil {
		return nil, fmt.Errorf("reader 不能为 nil")
	}
	// v2.8.28: 前端"多盘并行扫描"对话框默认 mode="auto"（"自动（推荐）"），但
	// switch case 只认 quick/deep/full —— 用户报"未知扫描模式: auto"。
	// "auto" / "" / "default" 都规范成 full（业界默认值，所有 FS 全跑 + 深度雕刻）。
	switch string(mode) {
	case "", "auto", "default":
		mode = types.ScanFull
	}

	// v2.8.25: 把"宣布扫描启动"的所有状态字段（scanning / scanDone / scanCancel /
	// reader）放进同一个 mu 临界区原子初始化。这关掉了 v2.8.24 留下的 race：
	//   - 之前 scanning=true 和 scanCancel 是两个独立 mu 段
	//   - 用户在这两段之间点 stop → Stop 看到 done 非 nil 但 cancel 仍 nil
	//   - Stop 走 <-done 但没人调过 cancel()，扫描会一路跑到自然结束
	//   - 现象：偶发的"点停止没反应"——和用户报的 bug 一致
	ctx, cancel := context.WithCancel(context.Background())
	scanDone := make(chan struct{})

	e.mu.Lock()
	if e.scanning {
		e.mu.Unlock()
		cancel() // 不会启动了，立刻释放 ctx
		return nil, fmt.Errorf("已有扫描任务正在进行中")
	}
	e.scanning = true
	e.scanDone = scanDone
	e.scanCancel = cancel
	e.reader = reader
	if cs, ok := reader.(cacheStatsProvider); ok {
		e.cacheStatsReader = cs
	} else {
		e.cacheStatsReader = nil
	}
	e.results = nil
	e.ntfsSources = make(map[string]ntfsRecoverySource)
	e.exfatSources = make(map[string]exfatRecoverySource)
	e.fatSources = make(map[string]fatRecoverySource)
	e.extSources = make(map[string]extRecoverySource)
	e.apfsSources = make(map[string]apfsRecoverySource)
	e.hfsplusSources = make(map[string]hfsplusRecoverySource)
	e.btrfsSources = make(map[string]btrfsRecoverySource)
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.scanning = false
		e.scanCancel = nil
		// 不清 e.scanDone —— Stop 可能正在 select 等它，清掉会让等待变 nil-channel 永久阻塞。
		// close 即可，e.scanDone 留着，下次扫描启动时覆盖。
		e.mu.Unlock()
		close(scanDone) // 信号：扫描 goroutine 已真正退出
	}()

	defer cancel()

	startTime := time.Now()

	// 安全的进度回调包装（防止 nil panic）
	safeProgress := func(p types.ScanProgress) {
		if callbacks.OnProgress != nil {
			callbacks.OnProgress(p)
		}
	}

	// 立刻 emit 一个带 TotalBytes 的 init 进度，让前端 UI 显示磁盘大小（"0 B / 128 GB"
	// 而不是 v2.8.11 之前的"0 B / 0 B"）。后续 dispatcher 即使 emit 不带 TotalBytes，
	// app.go 的 mergeScanProgress 会保留这个值。
	totalDiskBytes, _ := reader.Size()
	safeProgress(types.ScanProgress{
		Phase:       "init",
		Percent:     0.5,
		TotalBytes:  totalDiskBytes,
		CurrentFile: "正在初始化扫描...",
	})

	// 安全的发现回调包装，同时收集结果
	safeFound := func(f *types.RecoveredFile) {
		if f == nil {
			return
		}
		e.mu.Lock()
		e.results = append(e.results, f)
		e.mu.Unlock()
		if callbacks.OnFileFound != nil {
			callbacks.OnFileFound(f)
		}
	}

	// 选预算表：默认 fast（FS 阶段毫秒级，carver 占 86%）；取证模式 forensic（每个 brute-force
	// FS 占 ~25% 反映真实耗时）。
	budget := fastBudget
	if opts.IncludeDeletedPartitions {
		budget = forensicBudget
	}

	// phaseRange 把 phase-internal 0-100% 映射到全局进度条上 [start, end] 区间。
	// 替代之前散落各处的 `p.Percent = base + p.Percent * span` 硬编码，统一来源。
	phaseRange := func(start, end float64) func(types.ScanProgress) {
		span := end - start
		return func(p types.ScanProgress) {
			p.Percent = start + p.Percent*span/100.0
			safeProgress(p)
		}
	}

	var allFiles []*types.RecoveredFile

	// 根据模式执行不同的扫描策略
	switch mode {
	case types.ScanQuick:
		// 快速模式：仅 NTFS MFT 扫描
		logger.Info("扫描模式", "mode", "quick", "forensic", opts.IncludeDeletedPartitions)
		files, err := e.runNTFSScan(ctx, reader, 0, opts.IncludeDeletedPartitions, phaseRange(0, 95), safeFound)
		if err != nil {
			return nil, fmt.Errorf("NTFS 扫描失败: %w", err)
		}
		allFiles = append(allFiles, files...)

	case types.ScanDeep:
		// 深度模式：仅深度扫描
		logger.Info("扫描模式", "mode", "deep")
		files, err := e.runCarverScan(ctx, reader, e.popResumeCarverOffset(), phaseRange(0, 95), safeFound)
		if err != nil {
			return nil, fmt.Errorf("深度扫描失败: %w", err)
		}
		allFiles = append(allFiles, files...)

	case types.ScanFull:
		// 完整模式：所有 FS scan + 深度扫描 + 验证
		logger.Info("扫描模式", "mode", "full", "forensic", opts.IncludeDeletedPartitions)

		// 阶段1: NTFS 扫描
		ntfsFiles, err := e.runNTFSScan(ctx, reader, 0, opts.IncludeDeletedPartitions, phaseRange(budget.ntfsStart, budget.ntfsEnd), safeFound)
		if err != nil {
			// NTFS 扫描失败不中断（磁盘本身可能是 exFAT / 只有 exFAT 分区）
			logger.Warn("NTFS 扫描失败 (继续后续 FS + 深度扫描)", "err", err)
		} else {
			allFiles = append(allFiles, ntfsFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.5: exFAT 扫描 —— 对 U 盘 / SD 卡 / 移动硬盘关键
		exfatFiles, exfatErr := e.runEXFATScan(ctx, reader, opts.IncludeDeletedPartitions, phaseRange(budget.exfatStart, budget.exfatEnd), safeFound)
		if exfatErr != nil {
			logger.Warn("exFAT 扫描失败或未发现 exFAT 分区", "err", exfatErr)
		} else {
			allFiles = append(allFiles, exfatFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.6: FAT12/16/32 扫描 —— 老 U 盘 / 老 SD 卡 / 老相机
		fatFiles, fatErr := e.runFATScan(ctx, reader, opts.IncludeDeletedPartitions, phaseRange(budget.fatStart, budget.fatEnd), safeFound)
		if fatErr != nil {
			logger.Warn("FAT 扫描失败或未发现 FAT 分区", "err", fatErr)
		} else {
			allFiles = append(allFiles, fatFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.7: ext2/3/4 扫描 —— Linux/Android 设备
		extFiles, extErr := e.runEXTScan(ctx, reader, opts.IncludeDeletedPartitions, phaseRange(budget.extStart, budget.extEnd), safeFound)
		if extErr != nil {
			logger.Warn("ext 扫描失败或未发现 ext 分区", "err", extErr)
		} else {
			allFiles = append(allFiles, extFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.8: APFS 卷文件枚举（macOS / iOS 系统盘）
		apfsFiles, apfsErr := e.runAPFSScan(ctx, reader, opts.IncludeDeletedPartitions, phaseRange(budget.apfsStart, budget.apfsEnd), safeFound)
		if apfsErr != nil {
			logger.Warn("APFS 扫描失败或未发现 APFS", "err", apfsErr)
		} else {
			allFiles = append(allFiles, apfsFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.9: HFS+ 卷文件枚举（老 macOS / Time Machine）
		hfsFiles, hfsErr := e.runHFSPlusScan(ctx, reader, opts.IncludeDeletedPartitions, phaseRange(budget.hfsplusStart, budget.hfsplusEnd), safeFound)
		if hfsErr != nil {
			logger.Warn("HFS+ 扫描失败或未发现 HFS+", "err", hfsErr)
		} else {
			allFiles = append(allFiles, hfsFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.95: Btrfs 卷文件枚举（Linux 较新发行版 / Synology / Facebook）
		btrFiles, btrErr := e.runBtrfsScan(ctx, reader, opts.IncludeDeletedPartitions, phaseRange(budget.btrfsStart, budget.btrfsEnd), safeFound)
		if btrErr != nil {
			logger.Warn("Btrfs 扫描失败或未发现 Btrfs", "err", btrErr)
		} else {
			allFiles = append(allFiles, btrFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段2: 深度扫描 (默认 9-95% / forensic 78-95%)
		carverFiles, err := e.runCarverScan(ctx, reader, e.popResumeCarverOffset(), phaseRange(budget.carverStart, budget.carverEnd), safeFound)
		if err != nil {
			logger.Warn("深度扫描失败", "err", err)
		} else {
			allFiles = append(allFiles, carverFiles...)
		}

		// 检查是否已取消
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段3: 验证所有文件 (95-100%)
		e.validateAll(allFiles, reader, phaseRange(budget.validateStart, budget.validateEnd))

	default:
		return nil, fmt.Errorf("未知扫描模式: %s", mode)
	}

	// 对 quick/deep 模式也进行验证 (95-100%)
	if mode != types.ScanFull {
		e.validateAll(allFiles, reader, phaseRange(budget.validateStart, budget.validateEnd))
	}

	// 构建扫描结果
	duration := time.Since(startTime).Seconds()
	totalScanned, _ := reader.Size()

	stats := make(map[string]int)
	for _, f := range allFiles {
		stats[string(f.Category)]++
	}

	result := &types.ScanResult{
		Files:        allFiles,
		Duration:     duration,
		TotalScanned: totalScanned,
		Stats:        stats,
	}

	// 发送 100% 进度
	safeProgress(types.ScanProgress{
		Phase:        "complete",
		Percent:      100.0,
		TotalBytes:   totalScanned,
		BytesScanned: totalScanned,
		FilesFound:   len(allFiles),
		Elapsed:      types.FormatDuration(duration),
	})

	logger.Info("扫描完成", "duration_seconds", duration, "files", len(allFiles))
	return result, nil
}

// runCarverScan 执行深度扫描
//
// 使用 carver.NewEngine(reader, sigDB, cfg) 创建引擎，
// 调用 carver.Scan(ctx, start, end, onProgress, onFound) 执行扫描，
// 其中 onProgress 的类型为 func(types.ScanProgress)。
//
// startOffset > 0 时走断点续扫：跳过前 startOffset 字节直接从那里开始 ——
// 适用于用户上次扫到一半关机，重启后从 session 里读出进度点继续。
func (e *Engine) runCarverScan(
	ctx context.Context,
	reader disk.DiskReader,
	startOffset int64,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {

	logger.Info("开始深度扫描", "startOffset", startOffset)

	// 获取磁盘总大小
	totalSize, err := reader.Size()
	if err != nil {
		return nil, fmt.Errorf("获取磁盘大小失败: %w", err)
	}
	if startOffset < 0 {
		startOffset = 0
	}
	if startOffset >= totalSize {
		// 断点锚点已超过盘大小（扫描已完成？换盘了？）—— 从头重来
		startOffset = 0
	}

	// 创建 carver.Engine，传入默认配置
	cfg := carver.DefaultConfig()
	carverEngine := carver.NewEngine(reader, e.sigDB, cfg)
	e.mu.Lock()
	e.carverEng = carverEngine
	e.carverStartOffset = startOffset
	e.mu.Unlock()

	// 调用 carver.Scan —— onProgress 类型为 func(types.ScanProgress)
	var files []*types.RecoveredFile
	var filesMu sync.Mutex

	err = carverEngine.Scan(ctx, startOffset, totalSize,
		func(p types.ScanProgress) {
			// 直接透传 carver 的进度（调用者负责映射百分比）
			onProgress(p)
		},
		func(f *types.RecoveredFile) {
			if f == nil {
				return
			}
			filesMu.Lock()
			files = append(files, f)
			filesMu.Unlock()
			onFound(f)
		},
	)

	if err != nil {
		return files, fmt.Errorf("深度扫描失败: %w", err)
	}

	logger.Info("深度扫描完成", "files", len(files))
	return files, nil
}

// validateAll 验证所有找到的文件
//
// 创建 validator.Validator，遍历所有文件调用 Validate，
// 设置每个文件的 IsValid、Confidence、ValidationMsg，
// 进度由调用者映射到 95-100%。
func (e *Engine) validateAll(
	files []*types.RecoveredFile,
	reader disk.DiskReader,
	onProgress func(types.ScanProgress),
) {
	if len(files) == 0 {
		return
	}

	logger.Info("开始验证文件", "files", len(files))

	v := validator.NewValidator(reader)
	e.mu.Lock()
	e.valid = v
	e.mu.Unlock()

	total := len(files)
	validCount := 0

	for i, file := range files {
		var result validator.Result
		residentHandled := false

		if file != nil && file.Source == "ntfs" {
			e.mu.RLock()
			source, ok := e.ntfsSources[file.ID]
			e.mu.RUnlock()

			if ok && source.Entry != nil && source.Entry.IsResident && len(source.Entry.ResidentData) > 0 {
				result = validator.Result{
					IsValid:    true,
					Confidence: 0.95,
					Message:    "MFT 驻留数据，可直接恢复",
				}
				residentHandled = true
			}
		}

		if !residentHandled {
			// 扫描阶段批量验证走 Fast：10 万级文件从分钟级降到秒级。
			// 真解码交给 Recover 阶段（见 recoverValidator.ValidateDeep）。
			result = v.ValidateFast(file)
		}

		// Validate 内部已设置 file 的字段，但这里确保一致性
		file.IsValid = result.IsValid
		file.Confidence = result.Confidence
		file.ValidationMsg = result.Message

		if result.IsValid {
			validCount++
		}

		// 更新进度 (0-100% 映射由调用者处理)
		if onProgress != nil {
			percent := float64(i+1) / float64(total) * 100.0
			onProgress(types.ScanProgress{
				Phase:       "validating",
				Percent:     percent,
				FilesFound:  total,
				CurrentFile: fmt.Sprintf("验证文件 %d/%d", i+1, total),
			})
		}
	}

	logger.Info("验证完成", "valid", validCount, "total", total)
}

// RecoverOptions 恢复选项，暴露给前端细粒度控制的开关。
type RecoverOptions struct {
	// AllowSameDisk=true 时跳过"恢复目录与源盘同一物理磁盘"的安全检查。
	// 业界标准实践是拒绝同盘恢复（可能覆盖源扇区）。仅在用户显式勾选"我已了解风险"时才启用。
	AllowSameDisk bool
	// ArchiveByExifDate=true 时图片按 EXIF 拍摄日期分子目录（YYYY/MM/）。
	// 用户找回 5 万张照片后最大需求是分类。
	ArchiveByExifDate bool
}

// Recover 恢复选中的文件到输出目录
//
// 参数:
//   - fileIDs:    要恢复的文件 ID 列表
//   - outputDir:  输出目录路径
//   - callbacks:  恢复回调函数集合
func (e *Engine) Recover(
	fileIDs []string,
	outputDir string,
	callbacks RecoverCallbacks,
) (*RecoveryResult, error) {
	return e.RecoverWithOptions(fileIDs, outputDir, RecoverOptions{}, callbacks)
}

// RecoverWithOptions 是 Recover 的扩展版本，接受 RecoverOptions。
// 保留 Recover 兼容老调用点；新调用点优先走这个。
func (e *Engine) RecoverWithOptions(
	fileIDs []string,
	outputDir string,
	opts RecoverOptions,
	callbacks RecoverCallbacks,
) (*RecoveryResult, error) {
	e.mu.Lock()
	if e.recovering {
		e.mu.Unlock()
		return nil, fmt.Errorf("已有恢复任务正在进行中")
	}
	e.recovering = true
	reader := e.reader
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.recovering = false
		e.recoverCancel = nil
		e.mu.Unlock()
	}()

	if reader == nil {
		return nil, fmt.Errorf("磁盘读取器未初始化，请先执行扫描")
	}

	devicePath := reader.DevicePath()
	if devicePath == "" {
		return nil, fmt.Errorf("恢复源磁盘路径为空，请重新扫描后再试")
	}
	if err := disk.ValidateRecoveryTarget(devicePath, outputDir); err != nil {
		if opts.AllowSameDisk {
			logger.Warn("用户已确认风险，跳过同盘安全检查",
				"source", devicePath,
				"output", outputDir,
				"blocked_reason", err.Error())
		} else {
			return nil, err
		}
	}

	// Scan() 结束时会关闭扫描阶段使用的 reader，因此恢复阶段需要重新打开一个新的 reader。
	recoverReader := disk.NewReader(devicePath)
	if err := recoverReader.Open(); err != nil {
		return nil, fmt.Errorf("打开恢复源磁盘失败: %w", err)
	}
	defer func() {
		if err := recoverReader.Close(); err != nil {
			logger.Warn("关闭恢复阶段 reader 失败", "err", err)
		}
	}()

	// 创建可取消的 context
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.recoverCancel = cancel
	e.mu.Unlock()
	defer cancel()

	// 从 results 中找到对应 ID 的文件
	e.mu.RLock()
	idSet := make(map[string]bool, len(fileIDs))
	for _, id := range fileIDs {
		idSet[id] = true
	}

	var targetFiles []*types.RecoveredFile
	for _, f := range e.results {
		if idSet[f.ID] {
			targetFiles = append(targetFiles, f)
		}
	}
	e.mu.RUnlock()

	if len(targetFiles) == 0 {
		return nil, fmt.Errorf("未找到要恢复的文件 (请求 %d 个 ID)", len(fileIDs))
	}

	// 跨源去重优先级：NTFS 先于 carver 落地。
	// 同一内容（SHA-256 一致）时保留带元数据（原路径/时间戳）的 NTFS 版本，
	// 丢弃后到达的 carver 版本。
	sort.SliceStable(targetFiles, func(i, j int) bool {
		return ntfsFirstLess(targetFiles[i].Source, targetFiles[j].Source)
	})

	// 创建 SafeWriter
	writer := NewSafeWriter(recoverReader, outputDir)
	e.mu.Lock()
	e.writer = writer
	e.mu.Unlock()

	// 恢复前即时验证：用于扫描过程中"立即恢复"场景，尽量拦截明显无效文件
	recoverValidator := validator.NewValidator(recoverReader)

	// 跨源 SHA-256 去重表：写入成功后登记；若后续文件命中同 hash 则跳过。
	// 排序已保证 NTFS 先于 carver（ntfs_ 字典序在 carve_ 前），因此命中时丢弃的
	// 一定是后来的、元数据更少的 carver 文件。
	seenHashes := make(map[string]string) // sha256 -> 已保留的输出路径

	total := len(targetFiles)
	successCount := 0
	partialCount := 0
	failedCount := 0
	skippedCount := 0       // validator 判 invalid 的被拒文件
	lowConfCount := 0       // 走 _low_confidence/ 的被保留但标低可靠
	duplicateCount := 0
	bytesWritten := int64(0)
	records := make([]*FileRecoveryRecord, 0, total)

	appendRecord := func(file *types.RecoveredFile, state FileRecoveryState, outputPath, msg string, started time.Time) {
		records = append(records, &FileRecoveryRecord{
			FileID:      file.ID,
			FileName:    file.FileName,
			Category:    string(file.Category),
			Size:        file.Size,
			SizeHuman:   types.FormatSize(file.Size),
			State:       state,
			OutputPath:  outputPath,
			Message:     msg,
			DurationMs:  time.Since(started).Milliseconds(),
			CompletedAt: time.Now(),
		})
	}

	safeProgress := func(p types.RecoveryProgress) {
		if callbacks.OnProgress != nil {
			callbacks.OnProgress(p)
		}
	}

	safeProgress(types.RecoveryProgress{
		Current:      0,
		Total:        total,
		BytesWritten: 0,
	})

	// 设计决策 —— 恢复阶段严格单线程顺序写。
	//
	// 业界（R-Studio / ddrescue / DMDE）都是单线程写，原因：
	//   1. disk IO 是瓶颈：HDD 并发 seek 会让吞吐暴跌（thrashing）
	//   2. 写盘争用 reader：validator / sha256 也要读源盘，并发 + 共享 reader =
	//      每次都要 seek 回去
	//   3. 进度条语义清晰：N/Total 单调递增，用户不会看到"完成 3，跳 5"
	//   4. 失败回溯：错误不需要跨 goroutine 传，records 有序
	//
	// 如未来要加并发，应该只并发 *不争用源 reader 的阶段* —— 比如 exif 解析、
	// SHA-256 计算（基于已写好的目标文件），不并发 Write 本身。
	for i, file := range targetFiles {
		// 检查是否已取消
		if ctx.Err() != nil {
			// 把已经跑过的记录保存下来，便于用户看到取消时的状态
			e.mu.Lock()
			e.lastRecovery = records
			e.mu.Unlock()
			return nil, fmt.Errorf("恢复操作已取消")
		}

		started := time.Now()

		// 对深度扫描来源文件做即时验证，避免导出明显不可用的数据片段。
		// 这里走 ValidateDeep 做权威判定——用户真要落盘的每一个文件都值得 10-50ms 的真解码。
		var jpegRepair *validator.RepairOutcome // 非 nil 表示走了 partial 修复路径
		if file.Source == "carver" {
			verify := recoverValidator.ValidateDeep(file)
			file.IsValid = verify.IsValid
			file.Confidence = verify.Confidence
			file.ValidationMsg = verify.Message

			if !verify.IsValid {
				// **JPEG 兜底**：ValidateDeep 失败但是 jpg/jpeg → 跑 DeepRepair
				// 链路（边界修复 / DHT 注入 / RST stitching / partial decode）。
				// 70% 中段损坏的 JPEG 这条路能救出可识别图像。
				// R-Studio 同款 "deep recovery" 哲学：宁要 X% 像素也不丢全图。
				if file.Extension == "jpg" || file.Extension == "jpeg" {
					out := recoverValidator.RepairJPEGFromOffset(file)
					if out.Repaired {
						jpegRepair = &out
						file.IsValid = true
						file.Confidence = out.Coverage * 0.5 // 修复版置信度 ≤ 0.5
						file.ValidationMsg = out.HumanReadable
						logger.Info("JPEG 部分修复成功", "file", file.FileName,
							"strategy", out.Strategy, "coverage", out.Coverage)
						// 不 continue — 走下面的写入路径，但用 jpegRepair.RepairedBytes
					}
				}
				if jpegRepair == nil {
					// validator 判 invalid 且无救 = 文件打不开 → "skipped" 而非 "failed"
					skippedCount++
					appendRecord(file, RecoveryStateSkipped, "", "校验失败: "+verify.Message, started)
					logger.Info("跳过低可靠文件", "file", file.FileName, "reason", verify.Message)
					safeProgress(types.RecoveryProgress{
						Current:      successCount + partialCount + failedCount + skippedCount,
						Total:        total,
						CurrentFile:  file.FileName,
						BytesWritten: bytesWritten,
						Success:      successCount,
						Partial:      partialCount,
						Failed:       failedCount,
					})
					continue
				}
			}
		}

		// 生成输出路径（新版会按置信度/批次分目录；扩展名非法时返回错误直接跳过）
		// 如果开了 ArchiveByExifDate + 是图片：preview 字节走 EXIF 解析 → 把 outputDir 改成 yyyy/MM 子目录
		effectiveOutDir := outputDir
		if opts.ArchiveByExifDate && string(file.Category) == "image" {
			if sub := exifArchiveSubdir(e.reader, file); sub != "" {
				effectiveOutDir = filepath.Join(outputDir, sub)
			}
		}
		outputPath, pathErr := writer.GenerateOutputPath(file, effectiveOutDir)
		if pathErr != nil {
			skippedCount++
			appendRecord(file, RecoveryStateSkipped, "", "生成输出路径失败: "+pathErr.Error(), started)
			logger.Warn("跳过输出路径生成失败的文件", "file", file.FileName, "err", pathErr)
			safeProgress(types.RecoveryProgress{
				Current:      successCount + partialCount + failedCount,
				Total:        total,
				CurrentFile:  file.FileName,
				BytesWritten: bytesWritten,
				Success:      successCount,
				Partial:      partialCount,
				Failed:       failedCount,
			})
			continue
		}

		safeProgress(types.RecoveryProgress{
			Current:      i,
			Total:        total,
			CurrentFile:  file.FileName,
			BytesWritten: bytesWritten,
			Success:      successCount,
			Partial:      partialCount,
			Failed:       failedCount,
		})

		// 执行写入 —— 根据来源选择写入方式
		var writeErr error

		switch file.Source {
		case "ntfs":
			writeErr = e.recoverNTFSFile(file, outputPath)
		case "exfat":
			writeErr = e.recoverEXFATFile(file, outputPath)
		case "fat":
			writeErr = e.recoverFATFile(file, outputPath)
		case "ext":
			writeErr = e.recoverEXTFile(file, outputPath)
		case "apfs":
			writeErr = e.recoverAPFSFile(file, outputPath)
		case "hfsplus":
			writeErr = e.recoverHFSPlusFile(file, outputPath)
		case "btrfs":
			writeErr = e.recoverBtrfsFile(file, outputPath)
		case "smb", "nfs":
			// NAS 来源（Batch 2）：走 NASRecoverySource 缓存里的 session 拷贝文件
			writeErr = e.recoverNASFile(file, outputPath)
		case "ios":
			// iOS 备份来源（Batch 3）：未加密直接拷；加密走 class key → file key → AES-CBC
			writeErr = e.recoverIOSFile(file, outputPath)
		case "android":
			// Android `.ab` 备份（Batch 4）：tar 流式提取（重扫流到目标 entry）
			writeErr = e.recoverAndroidFile(file, outputPath)
		default:
			// Carver 来源
			if jpegRepair != nil {
				// 走 JPEG 修复路径：写修复后的 bytes（不读原 offset）
				writeErr = os.WriteFile(outputPath, jpegRepair.RepairedBytes, 0o644) // #nosec G306
			} else {
				// 直接偏移读取
				writeErr = writer.WriteFile(file, outputPath)
			}
		}

		// 写入成功后做跨源 SHA-256 去重：同 hash 已落地过则删掉当前副本
		if writeErr == nil && file.SHA256 != "" {
			if prevPath, dup := seenHashes[file.SHA256]; dup {
				if rmErr := os.Remove(outputPath); rmErr != nil {
					logger.Warn("删除重复文件失败", "path", outputPath, "err", rmErr)
				}
				duplicateCount++
				appendRecord(file, RecoveryStateSkipped, "",
					fmt.Sprintf("与已恢复文件内容重复 (SHA256=%s...)，已去重：保留 %s",
						file.SHA256[:12], prevPath), started)
				logger.Info("跨源去重", "file", file.FileName, "keep", prevPath)
				safeProgress(types.RecoveryProgress{
					Current:      successCount + partialCount + failedCount + duplicateCount,
					Total:        total,
					CurrentFile:  file.FileName,
					BytesWritten: bytesWritten,
					Success:      successCount,
					Partial:      partialCount,
					Failed:       failedCount,
				})
				continue
			}
			seenHashes[file.SHA256] = outputPath
		}

		var partialErr *PartialWriteError
		switch {
		case writeErr == nil:
			// JPEG 修复路径：标 Partial 而不是 Success（用户/manifest 可见这是部分恢复）
			if jpegRepair != nil {
				partialCount++
				bytesWritten += int64(len(jpegRepair.RepairedBytes))
				appendRecord(file, RecoveryStatePartial, outputPath,
					fmt.Sprintf("[JPEG 部分恢复 %.0f%% via %s] %s",
						jpegRepair.Coverage*100, jpegRepair.Strategy, jpegRepair.HumanReadable),
					started)
				logger.Info("JPEG 部分恢复落盘", "file", file.FileName, "output", outputPath,
					"strategy", jpegRepair.Strategy, "coverage", jpegRepair.Coverage)
			} else {
				successCount++
				bytesWritten += file.Size
				// 输出路径含 _low_confidence 子目录 = validator 标低可靠（走 writer.GenerateOutputPath 规则）
				if strings.Contains(outputPath, "_low_confidence") {
					lowConfCount++
				}
				appendRecord(file, RecoveryStateSuccess, outputPath, "", started)
				logger.Info("恢复文件成功", "file", file.FileName, "output", outputPath)
			}
		case errors.As(writeErr, &partialErr):
			// 严格模式：部分恢复视为失败，删除不完整输出，避免导出不可用文件
			if rmErr := os.Remove(partialErr.OutputPath); rmErr != nil {
				logger.Warn("清理部分恢复文件失败", "path", partialErr.OutputPath, "err", rmErr)
			}
			failedCount++
			appendRecord(file, RecoveryStateFailed, "", fmt.Sprintf("部分恢复已清理: %s", partialErr.Error()), started)
			logger.Warn("文件恢复失败(不完整，已清理)", "file", file.FileName, "err", partialErr)
		default:
			failedCount++
			appendRecord(file, RecoveryStateFailed, "", writeErr.Error(), started)
			logger.Warn("恢复文件失败", "file", file.FileName, "err", writeErr)
		}

		safeProgress(types.RecoveryProgress{
			Current:      successCount + partialCount + failedCount + duplicateCount,
			Total:        total,
			CurrentFile:  file.FileName,
			BytesWritten: bytesWritten,
			Success:      successCount,
			Partial:      partialCount,
			Failed:       failedCount,
		})
	}

	// 最终进度
	safeProgress(types.RecoveryProgress{
		Current:      total,
		Total:        total,
		BytesWritten: bytesWritten,
		Success:      successCount,
		Partial:      partialCount,
		Failed:       failedCount,
	})

	// 缓存每文件记录，供 GetLastRecoveryResult / ExportRecoveryReport / RetryFailedRecovery 使用
	e.mu.Lock()
	e.lastRecovery = records
	e.mu.Unlock()

	// 写入 JSON manifest（机读元数据）。失败只记日志，不阻塞恢复流程。
	if manifestPath, err := ExportManifestJSON(records, targetFiles, outputDir); err != nil {
		logger.Warn("导出 manifest.json 失败", "err", err)
	} else {
		logger.Info("manifest 已导出", "path", manifestPath)
	}

	logger.Info("恢复完成",
		"success", successCount,
		"low_confidence", lowConfCount,
		"partial", partialCount,
		"failed", failedCount,
		"skipped", skippedCount,
		"duplicates", duplicateCount)
	return &RecoveryResult{
		Succeeded:     successCount,
		LowConfidence: lowConfCount,
		Partial:       partialCount,
		Failed:        failedCount,
		Skipped:       skippedCount,
		Duplicates:    duplicateCount,
		Total:         total,
		Records:       records,
	}, nil
}

// ReadFilePreview 返回指定 fileID 在源盘上的前 maxBytes 字节，供前端做图片缩略图/预览。
//
// 读取策略：
//   - NTFS resident data：直接从 MFT 的内存拷贝里截取
//   - NTFS 非 resident（有 DataRuns）：只读第一个 DataRun 的头部（预览够了，不跟随碎片）
//   - Carver 来源：按 file.Offset 顺序读取
//
// maxBytes 会被夹到 [1KB, 8MB] 区间，避免前端误请求把整个多 GB 文件拉回来。
func (e *Engine) ReadFilePreview(fileID string, maxBytes int) ([]byte, error) {
	const (
		minPreview = 1024
		maxPreview = 8 * 1024 * 1024
	)
	if maxBytes <= 0 {
		maxBytes = 1 << 20 // 默认 1MB，够大部分缩略图
	}
	if maxBytes < minPreview {
		maxBytes = minPreview
	}
	if maxBytes > maxPreview {
		maxBytes = maxPreview
	}

	e.mu.RLock()
	var file *types.RecoveredFile
	for _, f := range e.results {
		if f != nil && f.ID == fileID {
			file = f
			break
		}
	}
	var devicePath string
	if e.reader != nil {
		devicePath = e.reader.DevicePath()
	}
	source, hasNTFS := e.ntfsSources[fileID]
	e.mu.RUnlock()

	if file == nil {
		return nil, fmt.Errorf("未找到文件 ID=%s（可能扫描已被清空）", fileID)
	}

	// NTFS resident：数据在 MFT 内存里，直接截取
	if hasNTFS && source.Entry != nil && source.Entry.IsResident && len(source.Entry.ResidentData) > 0 {
		data := source.Entry.ResidentData
		if len(data) > maxBytes {
			data = data[:maxBytes]
		}
		return append([]byte(nil), data...), nil
	}

	if devicePath == "" {
		return nil, fmt.Errorf("源盘路径不可用，请重新扫描后再试")
	}

	// 为预览单独开一个 reader（Windows FILE_SHARE_READ 允许并发），避免与扫描/恢复 reader 相互阻塞。
	// 关键：必须包 TimeoutReader —— 否则 bad sector 会让 Windows ReadFile 在 driver queue 里无限 hang，
	// preview goroutine 永远不返回，前端表现为"卡死"。preview 走 fail-fast 策略（3s/read + 5s Open），
	// 让用户看到明确"超时"而不是一张坏掉的图。
	reader, err := openPreviewReader(devicePath)
	if err != nil {
		return nil, fmt.Errorf("打开源盘失败/超时: %w", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			logger.Warn("关闭预览 reader 失败", "err", err)
		}
	}()

	readSize := int64(maxBytes)
	if file.Size > 0 && file.Size < readSize {
		readSize = file.Size
	}

	// NTFS 非 resident：只读第一个 DataRun 的头部（预览不需要跟碎片）
	if hasNTFS && source.Entry != nil && len(source.Entry.DataRuns) > 0 && source.Boot != nil {
		firstRun := source.Entry.DataRuns[0]
		if firstRun.Sparse {
			return make([]byte, readSize), nil
		}
		bytesPerCluster := int64(source.Boot.BytesPerSector) * int64(source.Boot.SectorsPerCluster)
		runOffset := source.PartitionOffset + firstRun.ClusterOffset*bytesPerCluster
		runLen := firstRun.ClusterCount * bytesPerCluster
		if readSize > runLen {
			readSize = runLen
		}
		buf := make([]byte, readSize)
		n, err := reader.ReadAt(buf, runOffset)
		if err != nil && n == 0 {
			return nil, fmt.Errorf("读取预览数据失败: %w", err)
		}
		return buf[:n], nil
	}

	// Carver 或兜底：从 file.Offset 顺序读
	buf := make([]byte, readSize)
	n, err := reader.ReadAt(buf, file.Offset)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("读取预览数据失败: %w", err)
	}
	return buf[:n], nil
}

// GetLastRecoveryResult 返回最近一次恢复的每文件记录（按失败在前排序便于前端展示）。
func (e *Engine) GetLastRecoveryResult() []*FileRecoveryRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.lastRecovery) == 0 {
		return nil
	}
	out := make([]*FileRecoveryRecord, len(e.lastRecovery))
	copy(out, e.lastRecovery)
	return out
}

// FailedRecoveryFileIDs 返回最近一次恢复中状态为 failed / partial / skipped 的文件 ID。
func (e *Engine) FailedRecoveryFileIDs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var ids []string
	for _, r := range e.lastRecovery {
		if r.State == RecoveryStateFailed || r.State == RecoveryStatePartial || r.State == RecoveryStateSkipped {
			ids = append(ids, r.FileID)
		}
	}
	return ids
}

func (e *Engine) ValidateRecoveryTarget(outputDir string) error {
	if strings.TrimSpace(outputDir) == "" {
		return fmt.Errorf("未指定输出目录")
	}

	e.mu.RLock()
	reader := e.reader
	e.mu.RUnlock()

	if reader == nil {
		return fmt.Errorf("磁盘读取器未初始化，请先执行扫描")
	}

	devicePath := strings.TrimSpace(reader.DevicePath())
	if devicePath == "" {
		return fmt.Errorf("恢复源磁盘路径为空，请重新扫描后再试")
	}

	return disk.ValidateRecoveryTarget(devicePath, outputDir)
}

// recoverNTFSFile 使用 NTFS MFT 数据恢复文件
//
// 从缓存的 NTFS 恢复源中按 ID 查找对应条目，
// 然后使用 WriteNTFSFile 按 DataRuns 读取。若缓存缺失则直接失败，
// 不再回退到按 Offset 的 WriteFile——因为碎片化文件的后续段在那里会被忽略。


// BadSectors 返回本次扫描期间 ResilientReader 跳过的坏扇区清单
// （没扫描过或 Scan 用自定义 reader 时返回 nil）。
func (e *Engine) BadSectors() []disk.BadSector {
	e.mu.RLock()
	rr := e.resilientReader
	e.mu.RUnlock()
	if rr == nil {
		return nil
	}
	return rr.BadSectors()
}

// SetResumeCarverOffset 设置下一次 Scan 启动时 carver 的起始偏移。
// 典型用途：用户点击 WelcomePage 的"从断点继续扫描"按钮，App 层读 session.json
// 里的 CarverResumeOffset 调此方法 → 然后 StartScan，engine 会消费一次。
func (e *Engine) SetResumeCarverOffset(offset int64) {
	if offset < 0 {
		offset = 0
	}
	e.mu.Lock()
	e.nextResumeCarverOffset = offset
	e.mu.Unlock()
}

// popResumeCarverOffset 读出并清零下次 Scan 的 carver 起点（消费一次）
func (e *Engine) popResumeCarverOffset() int64 {
	e.mu.Lock()
	off := e.nextResumeCarverOffset
	e.nextResumeCarverOffset = 0
	e.mu.Unlock()
	return off
}

// CurrentCarverOffset 返回本次扫描 carver 当前读到的绝对磁盘偏移（断点续扫锚点）。
// 扫描中每 5s 被 app.persistLoop 读取写入 session.json；用户下次打开可从此位置继续。
// 未在 carver 阶段时返回 0。
func (e *Engine) CurrentCarverOffset() int64 {
	e.mu.RLock()
	c := e.carverEng
	start := e.carverStartOffset
	e.mu.RUnlock()
	if c == nil {
		return 0
	}
	return start + c.BytesScanned()
}

// Stop 取消正在进行的扫描，并**同步等待**扫描 goroutine 真正退出。
//
// v2.8.24 结构性重写 —— 弃掉 v2.8.20 的"poll e.scanning 10s timeout"模式。
// 那种模式的致命缺陷：timeout 触发后 Stop 返回成功，前端 await 解锁、UI 显示"已停"，
// 但 scan goroutine 还活着持续读盘。用户看到的就是"暂停后磁盘仍 3.4 GB/s 直到杀进程"。
//
// 新模式 —— 用 done channel 做硬同步：
//  1. cancel context — 通知所有 ctx.Done() 监听者
//  2. reader.Cancel() — 强制关 handle，让所有 in-flight 和未来的 ReadFile 都 fail
//  3. **<-scanDone** — 等到 ScanWithReaderOptions 的 defer 真正跑完才返回
//
// 没有隐式 timeout：如果 goroutine 真卡死，Stop 也卡住、前端 IPC 也挂起 ——
// 用户会看到 UI "停止中..." 而不是被骗成"已停"。这比谎报状态好得多。
//
// 配合 v2.8.23 的 windowsReader.Cancel 关 handle + ResilientReader 透传 ErrReaderCancelled，
// goroutine 实际会在毫秒级退出 —— done channel 立刻 close，Stop 立刻返回。timeout
// 不该发生；如果真发生了，本身就是要修的 bug，不能被 fallback 静默吞掉。
func (e *Engine) Stop() {
	// v2.8.25: 单次 RLock 读所有"扫描启动"状态字段，由 ScanWithReaderOptions 保证
	// 它们在同一个 mu 段内原子初始化 —— 不存在 cancel/done 部分可见的中间态。
	cancel, reader, done := e.snapshotScanState()

	// 防御性 50ms 等待：调用方（典型是 app.go startScanInternal）应该等 IsScanning
	// 后再返回再让用户能点 Stop —— 但如果有人直接绕 app 层调 Engine.Stop（CLI / 测试 /
	// 未来的新接口），仍可能落在 scan goroutine 还没跑到第一个 mu.Lock 的窗口里。
	// 那种情况 done=nil；这里 50ms 内 poll 一下，让 scan 有机会登记。
	//
	// 注意：这跟 v2.8.20 那个 10s timeout 撒谎 fallback 不是一码事。这里是"等扫描启动"
	// 不是"等扫描结束"；结束仍然走 <-done 无 timeout。
	if done == nil {
		deadline := time.Now().Add(50 * time.Millisecond)
		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
			cancel, reader, done = e.snapshotScanState()
			if done != nil {
				break
			}
		}
		if done == nil {
			// 真没扫描在跑 —— 用户在没 scan 的状态点了 stop（合法 no-op）
			return
		}
	}

	if cancel != nil {
		logger.Info("正在取消扫描")
		cancel()
	}
	if c, ok := reader.(disk.Canceller); ok {
		_ = c.Cancel()
	}

	// 同步等扫描 goroutine 真正退出 —— done close = ScanWithReaderOptions defer 跑完
	// = 所有子 goroutine（carver IO / workers / collector / progress / validate / etc.）都退了
	// = 没有任何代码还在调 reader.ReadAt
	//
	// 没 timeout。卡住 = 我们有 bug 要修，不能假装 OK。
	<-done
	logger.Info("Stop: 扫描已真正退出")
}

// snapshotScanState 在一次 RLock 里读出"启动状态"三件套，保证三者来自同一时间点。
// 由 ScanWithReaderOptions 的"单 mu 段原子初始化"保证：要么全 nil、要么全非 nil。
func (e *Engine) snapshotScanState() (context.CancelFunc, disk.DiskReader, chan struct{}) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.scanCancel, e.reader, e.scanDone
}

// StopRecovery 取消正在进行的恢复操作
func (e *Engine) StopRecovery() {
	e.mu.RLock()
	cancel := e.recoverCancel
	e.mu.RUnlock()

	if cancel != nil {
		logger.Info("正在取消恢复操作")
		cancel()
	}
}

// Results 返回当前扫描结果
func (e *Engine) Results() *types.ScanResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.results) == 0 {
		return &types.ScanResult{
			Files: []*types.RecoveredFile{},
			Stats: make(map[string]int),
		}
	}

	stats := make(map[string]int)
	for _, f := range e.results {
		stats[string(f.Category)]++
	}

	return &types.ScanResult{
		Files: e.results,
		Stats: stats,
	}
}

// Shutdown 关闭引擎，释放所有资源
func (e *Engine) Shutdown() {
	logger.Info("正在关闭引擎")

	// 取消所有正在进行的操作
	e.Stop()
	e.StopRecovery()

	e.mu.Lock()
	defer e.mu.Unlock()

	// 关闭磁盘读取器
	if e.reader != nil {
		if err := e.reader.Close(); err != nil {
			logger.Warn("关闭磁盘读取器失败", "err", err)
		}
		e.reader = nil
	}

	// 清理引用
	e.carverEng = nil
	e.ntfsScn = nil
	e.valid = nil
	e.writer = nil
	e.results = nil
	e.cacheStatsReader = nil

	// 所有文件系统 sources 释放（防止 Engine 复用时的内存泄漏）。
	// 这些 map 持有 *MFTEntry / *Inode / *FSTreeFile 等较重的解析对象，
	// 一次扫描可能积累几十万条；Shutdown 不清空 = 整个 process 生命期都驻留。
	e.ntfsSources = nil
	e.exfatSources = nil
	e.fatSources = nil
	e.extSources = nil
	e.apfsSources = nil
	e.hfsplusSources = nil
	e.btrfsSources = nil

	// FileVault VEK 是用户密码解出的卷加密密钥 —— 必须显式置 nil，
	// 否则即便 process exit 也可能在 swap / coredump 里泄露。
	for k := range e.apfsVEKs {
		// 先把字节零化再 delete，防止 GC 之前从 dump 里拣回来
		if k2 := e.apfsVEKs[k]; k2 != nil {
			for i := range k2 {
				k2[i] = 0
			}
		}
		delete(e.apfsVEKs, k)
	}
	e.apfsVEKs = nil

	// 关闭所有 NAS 会话（Batch 2：SMB/NFS）
	e.closeNASSessions()
	e.nasSources = nil

	// 关闭所有 iOS 备份会话（Batch 3；删临时明文 Manifest.db）
	e.closeIOSSessions()
	e.iosSources = nil

	// 关闭所有 Android backup（Batch 4；清 master key 内存）
	e.closeAndroidBackups()
	e.androidSources = nil

	logger.Info("引擎已关闭")
}
// categorizeByExtension 根据文件扩展名推断分类
func categorizeByExtension(ext string) types.FileCategory {
	switch ext {
	case "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "webp", "svg", "ico",
		"raw", "cr2", "cr3", "nef", "arw", "dng", "orf", "rw2", "raf", "pef",
		"psd", "heic", "heif", "avif":
		return types.CategoryImage
	case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "odt", "ods", "odp",
		"csv", "md", "html", "htm", "xml", "json", "epub", "eml", "msg":
		return types.CategoryDocument
	case "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg", "3gp", "3g2", "ts", "vob":
		return types.CategoryVideo
	case "mp3", "wav", "flac", "aac", "ogg", "wma", "m4a", "m4b", "opus", "aiff", "ape", "mid", "midi":
		return types.CategoryAudio
	case "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso", "dmg", "cab", "zst":
		return types.CategoryArchive
	case "db", "sqlite", "sqlite3", "mdb", "accdb", "sql", "dbf":
		return types.CategoryDatabase
	default:
		return types.CategoryOther
	}
}

// cacheStatsProvider 是任何带 sector cache 的 reader 的能力契约。
// luks.DecryptedReader / bitlocker.DecryptingReader 都实现了这个签名。
type cacheStatsProvider interface {
	CacheStats() disk.CacheStats
}

// EncryptedReaderCacheStats 返回当前扫描所用加密 reader 的 sector 缓存命中率。
// 当前 reader 不是加密类型（NTFS 直扫物理盘等）时返回 (CacheStats{}, false)。
//
// 给前端 UI 显示"加密卷扫描缓存命中率 87%（4MB / 32MB 容量）"用。
func (e *Engine) EncryptedReaderCacheStats() (disk.CacheStats, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.cacheStatsReader == nil {
		return disk.CacheStats{}, false
	}
	return e.cacheStatsReader.CacheStats(), true
}
