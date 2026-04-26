package recovery

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/ntfs"
	"data-recovery/internal/types"
)

// ================================================================
// NTFS 扫描与恢复
//
// 历史上这块代码和 engine.go 混在一起（单文件 2200 行）。本文件把 NTFS 相关的
// 所有逻辑（分区解析、MFT 扫描、USN journal 线索、DataRun 恢复）集中放在一起，
// engine.go 只保留协调器职责。
//
// 保留的方法签名和旧版完全一致 —— adapter (scanner.go 里的 ntfsScannerAdapter)
// 会把这些方法转成 FilesystemScanner 接口调用。
// ================================================================

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

// resolveNTFSPartitions 决定本次 NTFS 扫描覆盖哪些分区：
//   - 调用方显式传了 partitionOffset > 0：只扫这一个分区（manual 模式）
//   - 物理盘（\\.\PhysicalDriveN / /dev/diskN）：走 FindPartitions 自动枚举
//   - 逻辑盘（\\.\C: / /dev/disk0s2）：只扫盘首的那一个 NTFS 卷
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

// scanNTFSPartition 扫描一个 NTFS 分区：
//  1. 解析 boot sector（若未提供）
//  2. 全量扫 MFT，实时回调已删除文件到前端
//  3. FindDeletedFiles 收束可恢复集合
//  4. RebuildDirectoryTree 拼原路径
//  5. 尝试解析 $UsnJrnl 给出"曾经存在过的文件名"提示
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
			ID:            fmt.Sprintf("usn_%d_%d", partition.Offset, ev.MFTEntry),
			Source:        "ntfs-usn-hint",
			FileName:      ev.FileName,
			Extension:     strings.ToLower(strings.TrimPrefix(filepath.Ext(ev.FileName), ".")),
			Category:      categorizeByExtension(strings.ToLower(strings.TrimPrefix(filepath.Ext(ev.FileName), "."))),
			Size:          0,
			SizeHuman:     "—",
			Offset:        0,
			Confidence:    0.0,
			IsDeleted:     true,
			OriginalPath:  ev.FileName,
			ModifiedTime:  timePtrIfNonZero(ev.DeletedAt),
			Description:   fmt.Sprintf("USN journal 提示：此文件曾于 %s 被删除（数据可能在 carved 列表里）", ev.DeletedAt.Format("2006-01-02 15:04:05")),
			IsValid:       false,
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

// isPhysicalDrivePath 判断路径是否指向物理盘（需要分区表扫描）。
// Windows 物理盘路径形如 `\\.\PhysicalDrive0`；macOS/Linux 的原始整盘是 `/dev/disk0`、`/dev/sda`。
// 注：当前只按"physicaldrive"关键字判断，保留旧行为。
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

// partitionWeight 返回一个分区在"进度权重"中的占比基数，
// 单位是字节（理想）；boot sector 可得则用 boot 推算；都不可用时回退 1。
func partitionWeight(partition ntfs.Partition) float64 {
	if partition.Size > 0 {
		return float64(partition.Size)
	}

	if partition.BootSector != nil && partition.BootSector.TotalSectors > 0 {
		return float64(partition.BootSector.TotalSectors) * float64(partition.BootSector.BytesPerSector)
	}

	return 1
}

// ntfsFileID 为一个 MFT 条目生成稳定 ID：`ntfs_<part-offset-hex>_<entry-num>`。
// 分区偏移是为了多分区磁盘下同一 entry 号不冲突。
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

// cacheNTFSSource 把 MFT entry / boot sector / 分区偏移 缓存到 engine，供 Recover 阶段
// 按 file.ID 查出 DataRuns 直接读盘。必须加锁（多 goroutine 并发扫多分区）。
func (e *Engine) cacheNTFSSource(fileID string, source ntfsRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.ntfsSources == nil {
		e.ntfsSources = make(map[string]ntfsRecoverySource)
	}
	e.ntfsSources[fileID] = source
}

// formatElapsed 把秒数格式化为 "12s" / "3m45s" / "1h02m" 便于前端展示。
// 放这里是因为目前唯一调用点是 NTFS 分区扫描的进度回调；如果未来别的扫描器
// 也需要，再提到独立的 util.go。
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

// openPreviewReader 为 ReadFilePreview 开一个短生命周期的 reader。
//
// 必须包 TimeoutReader：否则 preview 去读一个 bad sector 时，Windows 驱动层的
// ReadFile 会在内核 queue 里无限 hang（见 internal/disk/timeout.go 的说明），
// preview goroutine 永远不返回，前端用户体验就是"卡死"。扫描 reader 在
// engine.runScan 里用了 Resilient+Timeout，preview 路径历史上漏掉了这层包装。
//
// 这里刻意不用 ResilientReader —— preview 是 UX 路径，bad sector 应该 fail-fast
// 让用户看到"预览超时/失败"，而不是静默返回一张 zero-fill 的花屏图。
// 3s/read + 5s Open 的组合对绝大多数健康盘都够，对坏盘也不会让用户等太久。
func openPreviewReader(devicePath string) (disk.DiskReader, error) {
	base := disk.NewReader(devicePath)
	reader := disk.NewTimeoutReader(base, 3*time.Second)
	if err := disk.OpenWithTimeout(reader, 5*time.Second); err != nil {
		return nil, err
	}
	return reader, nil
}
