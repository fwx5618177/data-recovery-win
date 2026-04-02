package recovery

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"data-recovery/internal/carver"
	"data-recovery/internal/disk"
	"data-recovery/internal/ntfs"
	"data-recovery/internal/signature"
	"data-recovery/internal/types"
	"data-recovery/internal/validator"
)

// ScanCallbacks 扫描回调函数集合
type ScanCallbacks struct {
	OnProgress  func(types.ScanProgress)
	OnFileFound func(*types.RecoveredFile)
}

// RecoverCallbacks 恢复回调函数集合
type RecoverCallbacks struct {
	OnProgress func(types.RecoveryProgress)
}

// RecoveryResult 恢复操作的结果
type RecoveryResult struct {
	Succeeded int `json:"success"`
	Partial   int `json:"partial"`
	Failed    int `json:"failed"`
	Total     int `json:"total"`
}

type ntfsRecoverySource struct {
	Entry           *ntfs.MFTEntry
	Boot            *ntfs.BootSector
	PartitionOffset int64
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

	results    []*types.RecoveredFile
	scanning   bool
	recovering bool

	scanCancel    context.CancelFunc
	recoverCancel context.CancelFunc
}

// NewEngine 创建新的恢复引擎实例
func NewEngine() *Engine {
	return &Engine{
		sigDB: signature.NewSignatureDB(),
	}
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
	// 加锁，设置扫描状态
	e.mu.Lock()
	if e.scanning {
		e.mu.Unlock()
		return nil, fmt.Errorf("已有扫描任务正在进行中")
	}
	e.scanning = true
	e.results = nil
	e.ntfsSources = make(map[string]ntfsRecoverySource)
	e.mu.Unlock()

	// 扫描结束时解锁状态
	defer func() {
		e.mu.Lock()
		e.scanning = false
		e.scanCancel = nil
		e.mu.Unlock()
	}()

	startTime := time.Now()

	// 创建 DiskReader 并打开
	reader := disk.NewReader(drivePath)
	if err := reader.Open(); err != nil {
		return nil, fmt.Errorf("打开磁盘设备失败: %w", err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Printf("[Engine] 关闭磁盘设备失败: %v", err)
		}
	}()

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
		log.Println("[Engine] 快速扫描模式: 仅 NTFS MFT")
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
		log.Println("[Engine] 深度扫描模式: 仅深度扫描")
		files, err := e.runCarverScan(ctx, reader, func(p types.ScanProgress) {
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
		log.Println("[Engine] 完整扫描模式: NTFS + 深度扫描 + 验证")

		// 阶段1: NTFS 扫描 (0-40%)
		ntfsFiles, err := e.runNTFSScan(ctx, reader, 0, func(p types.ScanProgress) {
			p.Percent = p.Percent * 0.40
			safeProgress(p)
		}, safeFound)
		if err != nil {
			// NTFS 扫描失败不中断，记录日志继续深度扫描
			log.Printf("[Engine] NTFS 扫描失败 (继续深度扫描): %v", err)
		} else {
			allFiles = append(allFiles, ntfsFiles...)
		}

		// 检查是否已取消
		if ctx.Err() != nil {
			return nil, fmt.Errorf("扫描已取消")
		}

		// 阶段2: 深度扫描 (40-95%)
		carverFiles, err := e.runCarverScan(ctx, reader, func(p types.ScanProgress) {
			p.Percent = 40.0 + p.Percent*0.55
			safeProgress(p)
		}, safeFound)
		if err != nil {
			log.Printf("[Engine] 深度扫描失败: %v", err)
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

	log.Printf("[Engine] 扫描完成: 耗时 %.1f 秒, 找到 %d 个文件", duration, len(allFiles))
	return result, nil
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
	log.Println("[Engine] 开始 NTFS MFT 扫描...")

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
			log.Printf("[Engine] %s 扫描失败: %v", partitionLabel, partitionErr)
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

	log.Printf("[Engine] NTFS 扫描完成: 共扫描 %d 个分区，找到 %d 个可恢复文件", partitionScanned, len(files))
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
func (e *Engine) runCarverScan(
	ctx context.Context,
	reader disk.DiskReader,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {

	log.Println("[Engine] 开始深度扫描...")

	// 获取磁盘总大小
	totalSize, err := reader.Size()
	if err != nil {
		return nil, fmt.Errorf("获取磁盘大小失败: %w", err)
	}

	// 创建 carver.Engine，传入默认配置
	cfg := carver.DefaultConfig()
	carverEngine := carver.NewEngine(reader, e.sigDB, cfg)
	e.mu.Lock()
	e.carverEng = carverEngine
	e.mu.Unlock()

	// 调用 carver.Scan —— onProgress 类型为 func(types.ScanProgress)
	var files []*types.RecoveredFile
	var filesMu sync.Mutex

	err = carverEngine.Scan(ctx, 0, totalSize,
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

	log.Printf("[Engine] 深度扫描完成: 找到 %d 个文件", len(files))
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

	log.Printf("[Engine] 开始验证 %d 个文件...", len(files))

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

	log.Printf("[Engine] 验证完成: %d/%d 有效", validCount, total)
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
		return nil, err
	}

	// Scan() 结束时会关闭扫描阶段使用的 reader，因此恢复阶段需要重新打开一个新的 reader。
	recoverReader := disk.NewReader(devicePath)
	if err := recoverReader.Open(); err != nil {
		return nil, fmt.Errorf("打开恢复源磁盘失败: %w", err)
	}
	defer func() {
		if err := recoverReader.Close(); err != nil {
			log.Printf("[Engine] 关闭恢复阶段 reader 失败: %v", err)
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

	// 创建 SafeWriter
	writer := NewSafeWriter(recoverReader, outputDir)
	e.mu.Lock()
	e.writer = writer
	e.mu.Unlock()

	// 恢复前即时验证：用于扫描过程中“立即恢复”场景，尽量拦截明显无效文件
	recoverValidator := validator.NewValidator(recoverReader)

	total := len(targetFiles)
	successCount := 0
	partialCount := 0
	failedCount := 0
	bytesWritten := int64(0)

	safeProgress := func(p types.RecoveryProgress) {
		if callbacks.OnProgress != nil {
			callbacks.OnProgress(p)
		}
	}

	safeProgress(types.RecoveryProgress{
		Current:      0,
		Total:        total,
		BytesWritten: 0,
		Success:      0,
		Partial:      0,
		Failed:       0,
	})

	for i, file := range targetFiles {
		// 检查是否已取消
		if ctx.Err() != nil {
			return nil, fmt.Errorf("恢复操作已取消")
		}

		// 对深度扫描来源文件做即时验证，避免导出明显不可用的数据片段
		if file.Source == "carver" {
			verify := recoverValidator.Validate(file)
			file.IsValid = verify.IsValid
			file.Confidence = verify.Confidence
			file.ValidationMsg = verify.Message

			if !verify.IsValid {
				failedCount++
				log.Printf("[Engine] 跳过低可靠文件 [%s]: %s", file.FileName, verify.Message)
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
		}

		// 生成输出路径
		outputPath := writer.GenerateOutputPath(file, outputDir)

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

		if file.Source == "ntfs" {
			writeErr = e.recoverNTFSFile(file, outputPath)
		} else {
			// Carver 来源: 直接偏移读取
			writeErr = writer.WriteFile(file, outputPath)
		}

		var partialErr *PartialWriteError
		switch {
		case writeErr == nil:
			successCount++
			bytesWritten += file.Size
			log.Printf("[Engine] 恢复文件成功: %s -> %s", file.FileName, outputPath)
		case errors.As(writeErr, &partialErr):
			// 严格模式：部分恢复视为失败，删除不完整输出，避免导出不可用文件
			if rmErr := os.Remove(partialErr.OutputPath); rmErr != nil {
				log.Printf("[Engine] 清理部分恢复文件失败 [%s]: %v", partialErr.OutputPath, rmErr)
			}
			failedCount++
			log.Printf("[Engine] 文件恢复失败（检测到不完整，已清理）[%s]: %v", file.FileName, partialErr)
		default:
			failedCount++
			log.Printf("[Engine] 恢复文件失败 [%s]: %v", file.FileName, writeErr)
		}

		safeProgress(types.RecoveryProgress{
			Current:      successCount + partialCount + failedCount,
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

	log.Printf("[Engine] 恢复完成: 成功 %d, 部分恢复 %d, 失败 %d", successCount, partialCount, failedCount)
	return &RecoveryResult{
		Succeeded: successCount,
		Partial:   partialCount,
		Failed:    failedCount,
		Total:     total,
	}, nil
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
// 在缓存的 NTFS 恢复源中按 ID 查找对应条目，
// 找到则使用 WriteNTFSFile 按 DataRuns 读取，
// 找不到则回退到通用 WriteFile。
func (e *Engine) recoverNTFSFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	source, ok := e.ntfsSources[file.ID]
	writer := e.writer
	e.mu.RUnlock()

	if writer == nil {
		return fmt.Errorf("写入器未初始化")
	}

	if !ok || source.Entry == nil || source.Boot == nil {
		// MFT 条目不可用，回退到通用写入
		log.Printf("[Engine] NTFS 条目未找到 (ID=%s)，回退通用写入", file.ID)
		return writer.WriteFile(file, outputPath)
	}

	return writer.WriteNTFSFile(file, source.Entry, source.Boot, source.PartitionOffset, outputPath)
}

// Stop 取消正在进行的扫描
func (e *Engine) Stop() {
	e.mu.RLock()
	cancel := e.scanCancel
	e.mu.RUnlock()

	if cancel != nil {
		log.Println("[Engine] 正在取消扫描...")
		cancel()
	}
}

// StopRecovery 取消正在进行的恢复操作
func (e *Engine) StopRecovery() {
	e.mu.RLock()
	cancel := e.recoverCancel
	e.mu.RUnlock()

	if cancel != nil {
		log.Println("[Engine] 正在取消恢复操作...")
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
	log.Println("[Engine] 正在关闭引擎...")

	// 取消所有正在进行的操作
	e.Stop()
	e.StopRecovery()

	e.mu.Lock()
	defer e.mu.Unlock()

	// 关闭磁盘读取器
	if e.reader != nil {
		if err := e.reader.Close(); err != nil {
			log.Printf("[Engine] 关闭磁盘读取器失败: %v", err)
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

	log.Println("[Engine] 引擎已关闭")
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
			onProgress(types.ScanProgress{
				Phase:        "ntfs",
				Percent:      percent,
				BytesScanned: current * boot.MFTRecordSize,
				TotalBytes:   total * boot.MFTRecordSize,
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

	log.Printf("[Engine] %s 扫描完成: 共 %d 条目, %d 个已删除, %d 个可恢复文件",
		partitionLabel, len(allEntries), len(deletedEntries), len(files))
	return files, nil
}

func isPhysicalDrivePath(path string) bool {
	return strings.Contains(strings.ToLower(path), "physicaldrive")
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
	case "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "webp", "svg", "ico", "raw", "cr2", "nef", "psd", "heic", "heif":
		return types.CategoryImage
	case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "odt", "ods", "odp", "csv", "md", "html", "htm", "xml", "json", "epub":
		return types.CategoryDocument
	case "mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg", "3gp", "ts", "vob":
		return types.CategoryVideo
	case "mp3", "wav", "flac", "aac", "ogg", "wma", "m4a", "opus", "aiff", "ape", "mid", "midi":
		return types.CategoryAudio
	case "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "iso", "dmg", "cab", "zst":
		return types.CategoryArchive
	case "db", "sqlite", "sqlite3", "mdb", "accdb", "sql", "dbf":
		return types.CategoryDatabase
	default:
		return types.CategoryOther
	}
}
