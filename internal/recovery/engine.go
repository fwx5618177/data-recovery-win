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
	"sync/atomic"
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

	results    []*types.RecoveredFile
	scanning   bool
	recovering bool

	// 最近一次恢复操作的每文件结果，供前端展示失败清单和执行重试
	lastRecovery []*FileRecoveryRecord

	scanCancel    context.CancelFunc
	recoverCancel context.CancelFunc

	// resilientReader 当前扫描会话用的带坏块保护的 reader（由 Scan 自动包装）
	// 用来在扫完后汇报 BadSectors 给前端"坏扇区清单"UI
	resilientReader *disk.ResilientReader

	// 本次扫描的 carver 起点（0 = 全盘扫，>0 = 断点续扫）
	// persistLoop 靠 CurrentCarverOffset() 拉当前 carver 位置写 session
	carverStartOffset int64

	// 下次 Scan 启动时 carver 起点，消费一次即清零（SetResumeCarverOffset 设置）
	// 避免重复使用同一个 resume 点
	nextResumeCarverOffset int64
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

// Scan 主扫描方法，根据扫描模式协调各子模块完成磁盘扫描
//
// 参数:
//   - drivePath:  磁盘设备路径
//   - mode:       扫描模式 (quick/deep/full)
//   - callbacks:  扫描回调函数集合
//
// 返回扫描结果汇总和可能的错误
func (e *Engine) Scan(
	drivePath string,
	mode types.ScanMode,
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
	return e.ScanWithReader(reader, mode, callbacks)
}

// ScanWithReader 与 Scan 相同，但 DiskReader 由调用方提供（已打开）。
//
// 给"需要在原始磁盘之上再套一层"的场景用，典型的是 BitLocker：
//
//	物理盘 → bitlocker.DecryptingReader（透明解密）→ ScanWithReader
//
// 调用方负责 reader 的生命周期（Open/Close 都由调用方掌控）。
func (e *Engine) ScanWithReader(
	reader disk.DiskReader,
	mode types.ScanMode,
	callbacks ScanCallbacks,
) (*types.ScanResult, error) {
	if reader == nil {
		return nil, fmt.Errorf("reader 不能为 nil")
	}

	e.mu.Lock()
	if e.scanning {
		e.mu.Unlock()
		return nil, fmt.Errorf("已有扫描任务正在进行中")
	}
	e.scanning = true
	e.results = nil
	e.ntfsSources = make(map[string]ntfsRecoverySource)
	e.exfatSources = make(map[string]exfatRecoverySource)
	e.fatSources = make(map[string]fatRecoverySource)
	e.extSources = make(map[string]extRecoverySource)
	e.apfsSources = make(map[string]apfsRecoverySource)
	e.hfsplusSources = make(map[string]hfsplusRecoverySource)
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.scanning = false
		e.scanCancel = nil
		e.mu.Unlock()
	}()

	startTime := time.Now()

	e.mu.Lock()
	e.reader = reader
	e.mu.Unlock()

	// 创建可取消的 context
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.scanCancel = cancel
	e.mu.Unlock()
	defer cancel()

	// 安全的进度回调包装（防止 nil panic）
	safeProgress := func(p types.ScanProgress) {
		if callbacks.OnProgress != nil {
			callbacks.OnProgress(p)
		}
	}

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

	var allFiles []*types.RecoveredFile

	// 根据模式执行不同的扫描策略
	switch mode {
	case types.ScanQuick:
		// 快速模式：仅 NTFS MFT 扫描
		logger.Info("扫描模式", "mode", "quick")
		files, err := e.runNTFSScan(ctx, reader, 0, func(p types.ScanProgress) {
			// quick 模式下 NTFS 占 0-95%
			p.Percent = p.Percent * 0.95
			safeProgress(p)
		}, safeFound)
		if err != nil {
			return nil, fmt.Errorf("NTFS 扫描失败: %w", err)
		}
		allFiles = append(allFiles, files...)

	case types.ScanDeep:
		// 深度模式：仅深度扫描
		logger.Info("扫描模式", "mode", "deep")
		files, err := e.runCarverScan(ctx, reader, e.popResumeCarverOffset(), func(p types.ScanProgress) {
			// deep 模式下 carver 占 0-95%
			p.Percent = p.Percent * 0.95
			safeProgress(p)
		}, safeFound)
		if err != nil {
			return nil, fmt.Errorf("深度扫描失败: %w", err)
		}
		allFiles = append(allFiles, files...)

	case types.ScanFull:
		// 完整模式：NTFS + 深度扫描 + 验证
		logger.Info("扫描模式", "mode", "full")

		// 阶段1: NTFS 扫描 (0-12%)
		// 注意权重：NTFS 只读 MFT（磁盘很小一部分），对 U 盘通常几秒到十几秒就完成；
		// 深度扫描要读全盘，耗时占大头。把 NTFS 权重压到 12%，留 3% 给 exFAT
		ntfsFiles, err := e.runNTFSScan(ctx, reader, 0, func(p types.ScanProgress) {
			p.Percent = p.Percent * 0.12
			safeProgress(p)
		}, safeFound)
		if err != nil {
			// NTFS 扫描失败不中断（磁盘本身可能是 exFAT / 只有 exFAT 分区）
			logger.Warn("NTFS 扫描失败 (继续 exFAT + 深度扫描)", "err", err)
		} else {
			allFiles = append(allFiles, ntfsFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.5: exFAT 扫描 (12-14%)——对 U 盘 / SD 卡 / 移动硬盘关键
		exfatFiles, exfatErr := e.runEXFATScan(ctx, reader, func(p types.ScanProgress) {
			p.Percent = 12.0 + p.Percent*0.02
			safeProgress(p)
		}, safeFound)
		if exfatErr != nil {
			logger.Warn("exFAT 扫描失败或未发现 exFAT 分区", "err", exfatErr)
		} else {
			allFiles = append(allFiles, exfatFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.6: FAT12/16/32 扫描 (14-15%)——老 U 盘 / 老 SD 卡 / 老相机
		fatFiles, fatErr := e.runFATScan(ctx, reader, func(p types.ScanProgress) {
			p.Percent = 14.0 + p.Percent*0.005
			safeProgress(p)
		}, safeFound)
		if fatErr != nil {
			logger.Warn("FAT 扫描失败或未发现 FAT 分区", "err", fatErr)
		} else {
			allFiles = append(allFiles, fatFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.7: ext2/3/4 扫描 (14.5-14.7%)——Linux/Android 设备
		extFiles, extErr := e.runEXTScan(ctx, reader, func(p types.ScanProgress) {
			p.Percent = 14.5 + p.Percent*0.002
			safeProgress(p)
		}, safeFound)
		if extErr != nil {
			logger.Warn("ext 扫描失败或未发现 ext 分区", "err", extErr)
		} else {
			allFiles = append(allFiles, extFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.8: APFS 卷文件枚举（macOS / iOS 系统盘）
		apfsFiles, apfsErr := e.runAPFSScan(ctx, reader, func(p types.ScanProgress) {
			p.Percent = 14.7 + p.Percent*0.002
			safeProgress(p)
		}, safeFound)
		if apfsErr != nil {
			logger.Warn("APFS 扫描失败或未发现 APFS", "err", apfsErr)
		} else {
			allFiles = append(allFiles, apfsFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段1.9: HFS+ 卷文件枚举（老 macOS / Time Machine）
		hfsFiles, hfsErr := e.runHFSPlusScan(ctx, reader, func(p types.ScanProgress) {
			p.Percent = 14.9 + p.Percent*0.001
			safeProgress(p)
		}, safeFound)
		if hfsErr != nil {
			logger.Warn("HFS+ 扫描失败或未发现 HFS+", "err", hfsErr)
		} else {
			allFiles = append(allFiles, hfsFiles...)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段2: 深度扫描 (15-95%) — 占 80% 的总进度，与实际耗时比例更接近
		carverFiles, err := e.runCarverScan(ctx, reader, e.popResumeCarverOffset(), func(p types.ScanProgress) {
			p.Percent = 15.0 + p.Percent*0.80
			safeProgress(p)
		}, safeFound)
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
		e.validateAll(allFiles, reader, func(p types.ScanProgress) {
			p.Percent = 95.0 + p.Percent*0.05
			safeProgress(p)
		})

	default:
		return nil, fmt.Errorf("未知扫描模式: %s", mode)
	}

	// 对 quick/deep 模式也进行验证 (95-100%)
	if mode != types.ScanFull {
		e.validateAll(allFiles, reader, func(p types.ScanProgress) {
			p.Percent = 95.0 + p.Percent*0.05
			safeProgress(p)
		})
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

// runEXFATScan 执行 exFAT 扫描 —— 找分区 → 遍历目录（含已删除）→ 产出 RecoveredFile
//
// 对 U 盘 / SD 卡 / 移动硬盘这类外接存储设备关键：之前完全"看不见"，本轮新补。
// 扫描深度：
//   - 只遍历目录条目里的 in-use + deleted 文件，不走 FAT 链做块级数据重建
//   - 连续存储（NoFatChain=1）的文件可完整恢复
//   - 碎片文件被列出但标记为"需要 R-Studio"，FileSize 设为正确值供用户评估
func (e *Engine) runEXFATScan(
	ctx context.Context,
	reader disk.DiskReader,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 exFAT 扫描")

	scanner := exfat.NewScanner(reader)

	partitions, err := scanner.FindPartitions(ctx)
	if err != nil {
		return nil, err
	}

	var files []*types.RecoveredFile
	for pi, p := range partitions {
		if ctx.Err() != nil {
			return files, ctx.Err()
		}
		partitionLabel := fmt.Sprintf("exFAT 分区 %d/%d (@0x%X)", pi+1, len(partitions), p.Offset)
		if onProgress != nil {
			onProgress(types.ScanProgress{
				Phase:       "exfat",
				Percent:     float64(pi) / float64(len(partitions)) * 100,
				CurrentFile: partitionLabel + ": 扫描目录",
			})
		}

		perPartCount := 0
		err := scanner.ScanDirectory(ctx, p.BootSector, p.Offset, func(ff exfat.FoundFile) {
			file := exfatEntryToRecoveredFile(ff, p.BootSector)
			if file == nil {
				return
			}
			files = append(files, file)
			// 缓存恢复源（供 Recover 阶段按 ID 查回簇信息）
			e.cacheEXFATSource(file.ID, exfatRecoverySource{
				Entry:           ff.Entry,
				Boot:            p.BootSector,
				PartitionOffset: p.Offset,
			})
			if onFound != nil {
				onFound(file)
			}
			perPartCount++
		})
		if err != nil {
			logger.Warn("exFAT 目录遍历失败", "partition", partitionLabel, "err", err)
			continue
		}
		logger.Info("exFAT 分区扫描完成", "partition", partitionLabel, "files", perPartCount)
	}

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "exfat", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("exFAT 扫描完成", "files", len(files))
	return files, nil
}

// exfatEntryToRecoveredFile 把 exFAT 的一条目录发现翻译成统一的 RecoveredFile
func exfatEntryToRecoveredFile(ff exfat.FoundFile, boot *exfat.BootSector) *types.RecoveredFile {
	if ff.Entry.Name == "" || ff.Entry.IsDirectory {
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(ff.Entry.Name), "."))
	category := categorizeByExtension(ext)

	// 连续文件：Offset 指向 cluster heap 的字节；碎片文件：Offset 仍指向起始簇，
	// writer 侧根据 Source=="exfat" 决定怎么读
	var fileOffset int64 = -1
	if ff.Entry.FirstCluster >= 2 {
		fileOffset = boot.ClusterToByteOffset(ff.Entry.FirstCluster, ff.PartitionOff)
	}

	desc := ""
	if ff.Entry.IsDeleted {
		desc = "exFAT 已删除"
	}
	if !ff.Entry.NoFatChain {
		if desc != "" {
			desc += " + "
		}
		// 本轮新增 FAT 链遍历，碎片文件已支持恢复（但已删除文件的 FAT 链可能已回收，
		// 那种情况 FollowFATChain 会拿到 FREE 标记并报错，上层能识别 partial）
		desc += "碎片文件（走 FAT 链恢复）"
	}

	file := &types.RecoveredFile{
		ID:           fmt.Sprintf("exfat_%X_%d", ff.PartitionOff, ff.Entry.DirEntryOffset),
		Source:       "exfat",
		FileName:     ff.Entry.Name,
		Extension:    ext,
		Category:     category,
		Size:         ff.Entry.FileSize,
		SizeHuman:    types.FormatSize(ff.Entry.FileSize),
		Offset:       fileOffset,
		Confidence:   0.0, // 由 validator 赋值；连续文件通常给 0.8+
		IsDeleted:    ff.Entry.IsDeleted,
		OriginalPath: ff.FullPath,
		CreatedTime:  ff.Entry.CreatedTime,
		ModifiedTime: ff.Entry.ModifiedTime,
		Description:  desc,
	}
	return file
}

func (e *Engine) cacheEXFATSource(id string, src exfatRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exfatSources == nil {
		e.exfatSources = make(map[string]exfatRecoverySource)
	}
	e.exfatSources[id] = src
}

// runFATScan 执行 FAT12/16/32 扫描 —— U 盘 / SD 卡 / 老相机常用的文件系统。
// 已删除文件的 FAT 链大概率被清 0，FileClusterList 会退化成"连续 cluster"启发，
// 配合 signature validator（JPEG/PNG SOI 检测等）能救回大部分连续存储的用户照片。
func (e *Engine) runFATScan(
	ctx context.Context,
	reader disk.DiskReader,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 FAT 扫描")

	scanner := fat.NewScanner(reader)
	parts, err := scanner.FindPartitions(ctx)
	if err != nil {
		return nil, err
	}

	var files []*types.RecoveredFile
	for pi, p := range parts {
		if ctx.Err() != nil {
			return files, ctx.Err()
		}
		label := fmt.Sprintf("%s 分区 %d/%d (@0x%X)",
			p.BootSector.FSType.String(), pi+1, len(parts), p.Offset)
		if onProgress != nil {
			onProgress(types.ScanProgress{
				Phase:       "fat",
				Percent:     float64(pi) / float64(len(parts)) * 100,
				CurrentFile: label + ": 扫描目录",
			})
		}
		perPart := 0
		err := scanner.ScanDirectory(ctx, p.BootSector, p.Offset, func(ff fat.FoundFile) {
			file := fatEntryToRecoveredFile(ff, p.BootSector)
			if file == nil {
				return
			}
			files = append(files, file)
			e.cacheFATSource(file.ID, fatRecoverySource{
				Entry:           ff.Entry,
				Boot:            p.BootSector,
				PartitionOffset: p.Offset,
			})
			if onFound != nil {
				onFound(file)
			}
			perPart++
		})
		if err != nil {
			logger.Warn("FAT 目录遍历失败", "partition", label, "err", err)
			continue
		}
		logger.Info("FAT 分区扫描完成", "partition", label, "files", perPart)
	}
	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "fat", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("FAT 扫描完成", "files", len(files))
	return files, nil
}

func fatEntryToRecoveredFile(ff fat.FoundFile, boot *fat.BootSector) *types.RecoveredFile {
	if ff.Entry.Name == "" || ff.Entry.IsDirectory {
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(ff.Entry.Name), "."))
	category := categorizeByExtension(ext)

	fileOffset := int64(-1)
	if ff.Entry.FirstCluster >= 2 {
		fileOffset = boot.ClusterToByteOffset(ff.Entry.FirstCluster, ff.PartitionOff)
	}

	desc := boot.FSType.String()
	if ff.Entry.IsDeleted {
		desc += " 已删除"
	}

	return &types.RecoveredFile{
		ID:           fmt.Sprintf("fat_%X_%s_%d", ff.PartitionOff, ff.Entry.ShortName, ff.Entry.FirstCluster),
		Source:       "fat",
		FileName:     ff.Entry.Name,
		Extension:    ext,
		Category:     category,
		Size:         ff.Entry.FileSize,
		SizeHuman:    types.FormatSize(ff.Entry.FileSize),
		Offset:       fileOffset,
		Confidence:   0.0,
		IsDeleted:    ff.Entry.IsDeleted,
		OriginalPath: ff.FullPath,
		ModifiedTime: ff.Entry.ModifiedTime,
		CreatedTime:  ff.Entry.CreatedTime,
		Description:  desc,
	}
}

func (e *Engine) cacheFATSource(id string, src fatRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fatSources == nil {
		e.fatSources = make(map[string]fatRecoverySource)
	}
	e.fatSources[id] = src
}

// runEXTScan 执行 ext2/3/4 扫描 —— Linux/Android 设备的主流文件系统
func (e *Engine) runEXTScan(
	ctx context.Context,
	reader disk.DiskReader,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 ext2/3/4 扫描")

	scanner := ext4.NewScanner(reader)
	parts, err := scanner.FindPartitions(ctx)
	if err != nil {
		return nil, err
	}

	var files []*types.RecoveredFile
	for pi, p := range parts {
		if ctx.Err() != nil {
			return files, ctx.Err()
		}
		label := fmt.Sprintf("%s 分区 %d/%d (@0x%X)", p.SuperBlock.Variant, pi+1, len(parts), p.Offset)
		if onProgress != nil {
			onProgress(types.ScanProgress{
				Phase: "ext", Percent: float64(pi) / float64(len(parts)) * 100,
				CurrentFile: label + ": 遍历目录树",
			})
		}
		perPart := 0
		err := scanner.ScanFiles(ctx, p, func(ff ext4.FoundFile) {
			file := extEntryToRecoveredFile(ff)
			if file == nil {
				return
			}
			files = append(files, file)
			e.cacheEXTSource(file.ID, extRecoverySource{
				Inode:      ff.Inode,
				SuperBlock: ff.SuperBlock,
				GroupDescs: ff.GroupDescs,
			})
			if onFound != nil {
				onFound(file)
			}
			perPart++
		})
		if err != nil {
			logger.Warn("ext 扫描分区失败", "partition", label, "err", err)
			continue
		}
		logger.Info("ext 分区扫描完成", "partition", label, "files", perPart)
	}
	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "ext", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("ext 扫描完成", "files", len(files))
	return files, nil
}

func extEntryToRecoveredFile(ff ext4.FoundFile) *types.RecoveredFile {
	if ff.Inode == nil {
		return nil
	}
	name := filepath.Base(ff.FullPath)
	if name == "" || name == "/" {
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	category := categorizeByExtension(ext)

	desc := ff.SuperBlock.Variant.String()
	if ff.IsDeleted {
		desc += " 已删除"
	}

	id := fmt.Sprintf("ext_%X_%d", ff.PartitionOff, ff.Inode.Number)
	return &types.RecoveredFile{
		ID:           id,
		Source:       "ext",
		FileName:     name,
		Extension:    ext,
		Category:     category,
		Size:         ff.Inode.Size,
		SizeHuman:    types.FormatSize(ff.Inode.Size),
		Offset:       0, // ext 文件不是连续的，没有"起始字节偏移"概念
		Confidence:   0.0,
		IsDeleted:    ff.IsDeleted,
		OriginalPath: ff.FullPath,
		ModifiedTime: timePtrIfNonZero(ff.Inode.ModifyTime),
		CreatedTime:  timePtrIfNonZero(ff.Inode.ChangeTime),
		Description:  desc,
	}
}

func timePtrIfNonZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (e *Engine) cacheEXTSource(id string, src extRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.extSources == nil {
		e.extSources = make(map[string]extRecoverySource)
	}
	e.extSources[id] = src
}

// runNTFSScan 执行 NTFS MFT 扫描
//
// 使用 ntfs.Scanner 的回调式 API：
//   - ParseBootSector 解析引导扇区
//   - ScanMFT 通过 onEntry 回调收集所有条目
//   - FindDeletedFiles 筛选可恢复的已删除文件
//   - RebuildDirectoryTree 为每个条目构建完整路径
//   - 将 MFTEntry 转换为 RecoveredFile
func (e *Engine) runNTFSScan(
	ctx context.Context,
	reader disk.DiskReader,
	partitionOffset int64,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 NTFS MFT 扫描")

	scanner := ntfs.NewScanner(reader)
	e.mu.Lock()
	e.ntfsScn = scanner
	e.mu.Unlock()

	partitions, err := e.resolveNTFSPartitions(ctx, scanner, reader, partitionOffset)
	if err != nil {
		return nil, err
	}

	totalPartitionWeight := float64(0)
	for _, partition := range partitions {
		totalPartitionWeight += partitionWeight(partition)
	}
	if totalPartitionWeight <= 0 {
		totalPartitionWeight = float64(len(partitions))
	}

	var files []*types.RecoveredFile
	accumulatedWeight := float64(0)
	partitionScanned := 0
	var lastErr error

	for index, partition := range partitions {
		select {
		case <-ctx.Done():
			return files, ctx.Err()
		default:
		}

		weight := partitionWeight(partition)
		if weight <= 0 {
			weight = 1
		}
		normalizedWeight := weight / totalPartitionWeight
		partitionLabel := fmt.Sprintf("NTFS 分区 %d/%d", index+1, len(partitions))
		filesFoundBefore := len(files)

		partitionFiles, partitionErr := e.scanNTFSPartition(
			ctx,
			scanner,
			partition,
			partitionLabel,
			func(p types.ScanProgress) {
				p.Percent = accumulatedWeight*100 + p.Percent*normalizedWeight
				if p.FilesFound > 0 {
					p.FilesFound += filesFoundBefore
				} else {
					p.FilesFound = filesFoundBefore
				}
				onProgress(p)
			},
			onFound,
		)
		if partitionErr != nil {
			if ctx.Err() != nil {
				return files, ctx.Err()
			}
			lastErr = partitionErr
			logger.Warn("分区扫描失败", "partition", partitionLabel, "err", partitionErr)
			accumulatedWeight += normalizedWeight
			continue
		}

		partitionScanned++
		files = append(files, partitionFiles...)

		accumulatedWeight += normalizedWeight
	}

	if partitionScanned == 0 && lastErr != nil {
		return nil, lastErr
	}

	logger.Info("NTFS 扫描完成", "partitions", partitionScanned, "files", len(files))
	return files, nil
}

// mftEntryToRecoveredFile 将 MFT 条目转换为统一的 RecoveredFile 结构
//
// 使用 ntfs.MFTEntry 的实际字段名:
//   - EntryNumber (非 RecordNumber)
//   - IsUsed      (非 InUse)
//   - DataRun.ClusterOffset / ClusterCount (非 OffsetCluster / LengthClusters)
func mftEntryToRecoveredFile(entry *ntfs.MFTEntry, boot *ntfs.BootSector, partitionOffset int64) *types.RecoveredFile {
	if entry == nil {
		return nil
	}

	// 跳过目录和无名文件
	if entry.IsDirectory || entry.FileName == "" {
		return nil
	}

	// 提取扩展名
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(entry.FileName), "."))

	// 推断文件分类
	category := categorizeByExtension(ext)

	// 计算文件在磁盘上的绝对偏移。
	// 物理盘扫描时必须加上分区起始偏移，否则验证和通用回退读取会读错位置。
	var fileOffset int64
	if len(entry.DataRuns) > 0 && boot != nil {
		fileOffset = partitionOffset + entry.DataRuns[0].ClusterOffset*boot.ClusterSize
	}

	// 确定原始路径
	originalPath := entry.FullPath
	if originalPath == "" {
		originalPath = entry.FileName
	}

	file := &types.RecoveredFile{
		ID:           ntfsFileID(partitionOffset, entry.EntryNumber),
		Source:       "ntfs",
		FileName:     entry.FileName,
		Extension:    ext,
		Category:     category,
		Size:         entry.FileSize,
		SizeHuman:    types.FormatSize(entry.FileSize),
		Offset:       fileOffset,
		Confidence:   0.0, // 由后续验证阶段设置
		IsDeleted:    entry.IsDeleted,
		OriginalPath: originalPath,
		CreatedTime:  entry.CreatedTime,
		ModifiedTime: entry.ModifiedTime,
	}

	return file
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
			result = v.Validate(file)
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

		// 对深度扫描来源文件做即时验证，避免导出明显不可用的数据片段
		if file.Source == "carver" {
			verify := recoverValidator.Validate(file)
			file.IsValid = verify.IsValid
			file.Confidence = verify.Confidence
			file.ValidationMsg = verify.Message

			if !verify.IsValid {
				// validator 判 invalid = 文件打不开 → "skipped" 而非 "failed"
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
		default:
			// Carver 来源: 直接偏移读取
			writeErr = writer.WriteFile(file, outputPath)
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
			successCount++
			bytesWritten += file.Size
			// 输出路径含 _low_confidence 子目录 = validator 标低可靠（走 writer.GenerateOutputPath 规则）
			if strings.Contains(outputPath, "_low_confidence") {
				lowConfCount++
			}
			appendRecord(file, RecoveryStateSuccess, outputPath, "", started)
			logger.Info("恢复文件成功", "file", file.FileName, "output", outputPath)
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

	// 为预览单独开一个 reader（Windows FILE_SHARE_READ 允许并发），避免与扫描/恢复 reader 相互阻塞
	reader := disk.NewReader(devicePath)
	if err := reader.Open(); err != nil {
		return nil, fmt.Errorf("打开源盘失败: %w", err)
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
func (e *Engine) recoverNTFSFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	source, ok := e.ntfsSources[file.ID]
	writer := e.writer
	e.mu.RUnlock()

	if writer == nil {
		return fmt.Errorf("写入器未初始化")
	}

	if !ok || source.Entry == nil || source.Boot == nil {
		return fmt.Errorf("NTFS 恢复源已丢失 (ID=%s)，请重新扫描后再恢复", file.ID)
	}

	return writer.WriteNTFSFile(file, source.Entry, source.Boot, source.PartitionOffset, outputPath)
}

// recoverEXFATFile 恢复 exFAT 来源的文件。
//
// 两种路径：
//  1. 连续存储（NoFatChain=1）：cluster 号直接递增 → WriteEXFATFile
//  2. 碎片化（NoFatChain=0）：走 FAT 链拼 cluster 列表 → WriteEXFATFile
//
// 两条路径都走 cluster 级恢复（不走 byte offset 的 WriteFile），因为：
//   - 连续存储如果 FileSize 恰好 ≤ ClusterSize 的边界情况处理复杂
//   - 统一用 cluster 列表逻辑更简单，性能损失可忽略（磁盘 page cache 兜底）
func (e *Engine) recoverEXFATFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	source, ok := e.exfatSources[file.ID]
	writer := e.writer
	reader := e.reader
	e.mu.RUnlock()

	if writer == nil {
		return fmt.Errorf("写入器未初始化")
	}
	if !ok || source.Boot == nil {
		return fmt.Errorf("exFAT 恢复源已丢失 (ID=%s)，请重新扫描后再恢复", file.ID)
	}
	if reader == nil {
		return fmt.Errorf("磁盘 reader 未初始化")
	}

	clusters, err := exfat.FileClusterList(reader, source.Boot, source.PartitionOffset, &source.Entry)
	if err != nil {
		// 已删除文件的 FAT 链可能已被回收，典型错误：起始 cluster 标记为 free
		return fmt.Errorf("构造 cluster 列表失败: %w", err)
	}
	return writer.WriteEXFATFile(file, clusters, source.Boot, source.PartitionOffset, outputPath)
}

// recoverFATFile 恢复 FAT12/16/32 来源的文件。
// 与 exFAT 路径对称：构造 cluster 列表 → WriteFATFile。
// 对已删除 FAT 文件，FAT 链经常被清 0，FileClusterList 会退化成连续启发。
func (e *Engine) recoverFATFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	source, ok := e.fatSources[file.ID]
	writer := e.writer
	reader := e.reader
	e.mu.RUnlock()

	if writer == nil {
		return fmt.Errorf("写入器未初始化")
	}
	if !ok || source.Boot == nil {
		return fmt.Errorf("FAT 恢复源已丢失 (ID=%s)", file.ID)
	}
	if reader == nil {
		return fmt.Errorf("磁盘 reader 未初始化")
	}
	clusters, err := fat.FileClusterList(reader, source.Boot, source.PartitionOffset, &source.Entry)
	if err != nil {
		return fmt.Errorf("构造 FAT cluster 列表失败: %w", err)
	}
	return writer.WriteFATFile(file, clusters, source.Boot, source.PartitionOffset, outputPath)
}

// recoverEXTFile 恢复 ext2/3/4 来源文件 —— 走 inode → CollectFileBlocks → 写入
func (e *Engine) recoverEXTFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	source, ok := e.extSources[file.ID]
	writer := e.writer
	reader := e.reader
	e.mu.RUnlock()

	if writer == nil {
		return fmt.Errorf("写入器未初始化")
	}
	if !ok || source.Inode == nil || source.SuperBlock == nil {
		return fmt.Errorf("ext 恢复源已丢失 (ID=%s)", file.ID)
	}
	if reader == nil {
		return fmt.Errorf("磁盘 reader 未初始化")
	}
	ranges, err := ext4.CollectFileBlocks(reader, source.SuperBlock, source.Inode)
	if err != nil {
		return fmt.Errorf("收集 ext 文件块失败: %w", err)
	}
	return writer.WriteEXTFile(file, ranges, source.SuperBlock, outputPath)
}

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

// Stop 取消正在进行的扫描。
//
// 两步终止：
//  1. cancel context — 让所有循环里检查 ctx.Done() 的 goroutine 自然退出
//  2. 调 reader.Cancel() — 强制中断卡在内核 ReadAt syscall 上的 goroutine
//     （ctx.Cancel 无法穿透 syscall；不调 Cancel 则大块读会让 Stop 看似无反应）
func (e *Engine) Stop() {
	e.mu.RLock()
	cancel := e.scanCancel
	reader := e.reader
	e.mu.RUnlock()

	if cancel != nil {
		logger.Info("正在取消扫描")
		cancel()
	}
	if c, ok := reader.(disk.Canceller); ok {
		_ = c.Cancel()
	}
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
	e.ntfsSources = nil

	logger.Info("引擎已关闭")
}

func (e *Engine) resolveNTFSPartitions(
	ctx context.Context,
	scanner *ntfs.Scanner,
	reader disk.DiskReader,
	partitionOffset int64,
) ([]ntfs.Partition, error) {
	if partitionOffset > 0 {
		boot, err := scanner.ParseBootSector(partitionOffset)
		if err != nil {
			return nil, fmt.Errorf("解析 NTFS 引导扇区失败: %w", err)
		}

		return []ntfs.Partition{{
			Offset:     partitionOffset,
			Size:       boot.TotalSectors * int64(boot.BytesPerSector),
			Type:       "manual",
			BootSector: boot,
		}}, nil
	}

	if isPhysicalDrivePath(reader.DevicePath()) {
		partitions, err := scanner.FindPartitions(ctx)
		if err != nil {
			return nil, fmt.Errorf("在物理磁盘上未找到可扫描的 NTFS 分区: %w", err)
		}
		return partitions, nil
	}

	boot, err := scanner.ParseBootSector(0)
	if err != nil {
		return nil, fmt.Errorf("解析 NTFS 引导扇区失败: %w", err)
	}

	return []ntfs.Partition{{
		Offset:     0,
		Size:       boot.TotalSectors * int64(boot.BytesPerSector),
		Type:       "logical",
		BootSector: boot,
	}}, nil
}

func (e *Engine) scanNTFSPartition(
	ctx context.Context,
	scanner *ntfs.Scanner,
	partition ntfs.Partition,
	partitionLabel string,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	boot := partition.BootSector
	if boot == nil {
		var err error
		boot, err = scanner.ParseBootSector(partition.Offset)
		if err != nil {
			return nil, fmt.Errorf("解析 %s 引导扇区失败: %w", partitionLabel, err)
		}
	}

	var allEntries []*ntfs.MFTEntry
	var entriesMu sync.Mutex
	var liveFilesFound int64
	startTime := time.Now()

	onProgress(types.ScanProgress{
		Phase:       "ntfs",
		Percent:     0,
		CurrentFile: fmt.Sprintf("%s: 扫描 MFT 记录...", partitionLabel),
	})

	err := scanner.ScanMFT(ctx, boot, partition.Offset,
		func(current, total int64) {
			if total <= 0 {
				return
			}

			percent := float64(current) / float64(total) * 60.0
			bytesScanned := current * boot.MFTRecordSize
			elapsed := time.Since(startTime).Seconds()
			var speed int64
			if elapsed > 0.5 {
				speed = int64(float64(bytesScanned) / elapsed)
			}
			onProgress(types.ScanProgress{
				Phase:        "ntfs",
				Percent:      percent,
				BytesScanned: bytesScanned,
				TotalBytes:   total * boot.MFTRecordSize,
				FilesFound:   int(atomic.LoadInt64(&liveFilesFound)),
				Speed:        speed,
				Elapsed:      formatElapsed(elapsed),
				CurrentFile:  fmt.Sprintf("%s: 扫描 MFT 记录 %d/%d", partitionLabel, current, total),
			})
		},
		func(entry *ntfs.MFTEntry) {
			if entry == nil {
				return
			}
			entriesMu.Lock()
			allEntries = append(allEntries, entry)
			entriesMu.Unlock()

			// 实时推送：已删除且看起来可恢复 → 立即转 RecoveredFile 发给前端，
			// 不等整个 MFT 扫完（那需要好几分钟，用户以为卡死了）。
			// 最终的 scan:completed 会带完整 files 覆盖，这里是为了让用户在扫描
			// 进行中就能看到结果陆续冒出来。
			if onFound != nil && isLikelyRecoverable(entry) {
				f := mftEntryToRecoveredFile(entry, boot, partition.Offset)
				if f != nil {
					onFound(f)
					atomic.AddInt64(&liveFilesFound, 1)
				}
			}
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%s 扫描 MFT 失败: %w", partitionLabel, err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	onProgress(types.ScanProgress{
		Phase:       "ntfs",
		Percent:     65.0,
		CurrentFile: fmt.Sprintf("%s: 查找已删除文件...", partitionLabel),
		FilesFound:  len(allEntries),
	})
	deletedEntries := scanner.FindDeletedFiles(allEntries)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	onProgress(types.ScanProgress{
		Phase:       "ntfs",
		Percent:     75.0,
		CurrentFile: fmt.Sprintf("%s: 重建目录树...", partitionLabel),
		FilesFound:  len(deletedEntries),
	})
	scanner.RebuildDirectoryTree(allEntries)

	// 用 $UsnJrnl 找出"被删除文件的原文件名"清单 —— 即使 MFT entry 已被覆盖，
	// USN journal 里仍保留删除事件 + 原名 + 时间戳。给用户作为"参考线索"输出。
	usnDeletedNames := map[string]ntfs.DeletedFileEvent{} // FileName → event
	e.mu.RLock()
	rdr := e.reader
	e.mu.RUnlock()
	if events, _ := ntfs.ScanDeletedFileNames(rdr, boot, allEntries, 64*1024*1024); len(events) > 0 {
		logger.Info("USN journal 找回删除文件名", "count", len(events), "partition", partitionLabel)
		for _, ev := range events {
			usnDeletedNames[ev.FileName] = ev
		}
	}
	// 给已知 MFT entry 的恢复条目"补"上 USN 删除时间（如果 MFT 没有更准的时间）
	// + 把 USN 里有但 MFT 已不可恢复的文件作为"提示条目"加进结果

	files := make([]*types.RecoveredFile, 0, len(deletedEntries))
	for index, entry := range deletedEntries {
		select {
		case <-ctx.Done():
			return files, ctx.Err()
		default:
		}

		file := mftEntryToRecoveredFile(entry, boot, partition.Offset)
		if file == nil {
			continue
		}

		files = append(files, file)
		e.cacheNTFSSource(file.ID, ntfsRecoverySource{
			Entry:           entry,
			Boot:            boot,
			PartitionOffset: partition.Offset,
		})
		if onFound != nil {
			onFound(file)
		}

		if len(deletedEntries) > 0 {
			percent := 75.0 + float64(index+1)/float64(len(deletedEntries))*25.0
			onProgress(types.ScanProgress{
				Phase:       "ntfs",
				Percent:     percent,
				FilesFound:  len(files),
				CurrentFile: fmt.Sprintf("%s: %s", partitionLabel, file.FileName),
			})
		}
	}

	// 把"USN journal 里有但 MFT 已经枚举不到"的删除事件作为"线索条目"加入结果
	mftSeenNames := make(map[string]bool, len(files))
	for _, f := range files {
		mftSeenNames[f.FileName] = true
	}
	for _, ev := range usnDeletedNames {
		if mftSeenNames[ev.FileName] {
			continue
		}
		// 这种条目无法直接恢复（没数据 run），但用户可以在 carved 文件里按"原名"找
		// 配对（比如 carved 文件 file042.heic 大小匹配 IMG_3492.HEIC 的某次删除时间）
		hint := &types.RecoveredFile{
			ID:           fmt.Sprintf("usn_%d_%d", partition.Offset, ev.MFTEntry),
			Source:       "ntfs-usn-hint",
			FileName:     ev.FileName,
			Extension:    strings.ToLower(strings.TrimPrefix(filepath.Ext(ev.FileName), ".")),
			Category:     categorizeByExtension(strings.ToLower(strings.TrimPrefix(filepath.Ext(ev.FileName), "."))),
			Size:         0,
			SizeHuman:    "—",
			Offset:       0,
			Confidence:   0.0,
			IsDeleted:    true,
			OriginalPath: ev.FileName,
			ModifiedTime: timePtrIfNonZero(ev.DeletedAt),
			Description:  fmt.Sprintf("USN journal 提示：此文件曾于 %s 被删除（数据可能在 carved 列表里）", ev.DeletedAt.Format("2006-01-02 15:04:05")),
			IsValid:      false,
			ValidationMsg: "USN-only 提示：无 MFT 数据 run，无法直接恢复；只是告诉你曾经存在过这个文件名",
		}
		files = append(files, hint)
		if onFound != nil {
			onFound(hint)
		}
	}

	logger.Info("分区扫描完成",
		"partition", partitionLabel,
		"entries", len(allEntries),
		"deleted", len(deletedEntries),
		"usn_hints", len(usnDeletedNames),
		"recoverable", len(files))
	return files, nil
}

func isPhysicalDrivePath(path string) bool {
	return strings.Contains(strings.ToLower(path), "physicaldrive")
}

// isLikelyRecoverable 复用 ntfs.FindDeletedFiles 的判断条件，用在 MFT 扫描的 onEntry
// 实时回调里 —— 收到一个 entry 时立即判断能否恢复，能就转 RecoveredFile 推给前端。
// 保持与 FindDeletedFiles 逻辑同步，避免扫完筛选和实时筛选两套标准漂移。
func isLikelyRecoverable(e *ntfs.MFTEntry) bool {
	if e == nil || !e.IsDeleted || e.IsDirectory {
		return false
	}
	if e.FileSize <= 0 {
		return false
	}
	if e.FileName == "" || strings.HasPrefix(e.FileName, "$") {
		return false
	}
	hasDataRuns := len(e.DataRuns) > 0
	hasResidentData := e.IsResident && len(e.ResidentData) > 0
	return hasDataRuns || hasResidentData
}

// formatElapsed 把秒数格式化为 "12s" / "3m45s" / "1h02m" 便于前端展示
func formatElapsed(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", int(seconds))
	}
	if seconds < 3600 {
		m := int(seconds / 60)
		s := int(seconds) - m*60
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	h := int(seconds / 3600)
	m := int((seconds - float64(h)*3600) / 60)
	return fmt.Sprintf("%dh%02dm", h, m)
}

func partitionWeight(partition ntfs.Partition) float64 {
	if partition.Size > 0 {
		return float64(partition.Size)
	}

	if partition.BootSector != nil && partition.BootSector.TotalSectors > 0 {
		return float64(partition.BootSector.TotalSectors) * float64(partition.BootSector.BytesPerSector)
	}

	return 1
}

func ntfsFileID(partitionOffset int64, entryNumber int64) string {
	return fmt.Sprintf("ntfs_%X_%d", partitionOffset, entryNumber)
}

// ntfsFirstLess 让 NTFS 来源排在其它来源（carver 等）之前。
// 用于 sort.SliceStable 的 less 函数，确保跨源 SHA-256 去重时保留带元数据的 NTFS 版本。
//
// 注意：不能依赖字母序 —— "carver" < "ntfs" 会让 carver 跑在前面，与去重意图相反。
func ntfsFirstLess(a, b string) bool {
	if a == "ntfs" && b != "ntfs" {
		return true
	}
	if a != "ntfs" && b == "ntfs" {
		return false
	}
	return false
}

func (e *Engine) cacheNTFSSource(fileID string, source ntfsRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.ntfsSources == nil {
		e.ntfsSources = make(map[string]ntfsRecoverySource)
	}
	e.ntfsSources[fileID] = source
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
