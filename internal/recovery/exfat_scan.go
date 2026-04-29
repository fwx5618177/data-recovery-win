package recovery

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"data-recovery/internal/disk"
	"data-recovery/internal/exfat"
	"data-recovery/internal/types"
)

// ================================================================
// exFAT 扫描与恢复
//
// exFAT 常见于 U 盘 / SD 卡 / 移动硬盘这类外接存储。旧版把它和 NTFS/FAT/ext
// 一起堆在 engine.go 里；按 FilesystemScanner 模式抽到本文件。
// ================================================================

// runEXFATScan 执行 exFAT 扫描 —— 找分区 → 遍历目录（含已删除）→ 产出 RecoveredFile
//
// 扫描深度：
//   - 遍历目录条目里的 in-use + deleted 文件
//   - 连续存储（NoFatChain=1）的文件可完整恢复
//   - 碎片文件走 FAT 链拼 cluster 列表（本批次已内置），已删除碎片文件的 FAT
//     链可能已被回收，那种情况 FollowFATChain 会报错，上层归入 partial
//
// includeDeletedPartitions = true 启用 brute-force 找已删除/丢失的 exFAT 分区残骸（取证模式）；
// false 只跑 fast path（默认；健康盘上微秒级返回）。
func (e *Engine) runEXFATScan(
	ctx context.Context,
	reader disk.DiskReader,
	includeDeletedPartitions bool,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 exFAT 扫描", "brute_force", includeDeletedPartitions)

	// 立刻 emit 一个 0% 占位，让前端跳出 ready/init 状态进入 "正在查找 exFAT 分区..."
	if onProgress != nil {
		onProgress(types.ScanProgress{
			Phase:       "exfat",
			Percent:     0.5,
			CurrentFile: "正在查找 exFAT 分区...",
		})
	}

	scanner := exfat.NewScanner(reader)

	// 暴力扫分区时把字节级进度映射到 0-50% phase 进度（找到分区后再喂另一半）。
	// 默认模式下 BruteForce=false → onProgress 这个 callback 不会触发（fast path 微秒返回）。
	partitions, err := scanner.FindPartitions(ctx, exfat.FindOptions{
		BruteForce: includeDeletedPartitions,
		OnProgress: func(scanned, total int64) {
			if onProgress == nil || total <= 0 {
				return
			}
			percent := float64(scanned) / float64(total) * 50.0
			if percent < 0.5 {
				percent = 0.5
			}
			onProgress(types.ScanProgress{
				Phase:        "exfat",
				Percent:      percent,
				BytesScanned: scanned,
				TotalBytes:   total,
				CurrentFile:  fmt.Sprintf("正在查找已删除 exFAT 分区… %s / %s", types.FormatSize(scanned), types.FormatSize(total)),
			})
		},
	})
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
			// 50-100% 留给目录遍历阶段（前 50% 已被 FindPartitions 用掉）
			onProgress(types.ScanProgress{
				Phase:       "exfat",
				Percent:     50.0 + float64(pi)/float64(len(partitions))*50.0,
				FilesFound:  len(files),
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
		Confidence:   0.0,
		IsDeleted:    ff.Entry.IsDeleted,
		OriginalPath: ff.FullPath,
		CreatedTime:  ff.Entry.CreatedTime,
		ModifiedTime: ff.Entry.ModifiedTime,
		Description:  desc,
	}
	return file
}

// cacheEXFATSource 把 exFAT entry / boot / 分区偏移 缓存到 engine。
func (e *Engine) cacheEXFATSource(id string, src exfatRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exfatSources == nil {
		e.exfatSources = make(map[string]exfatRecoverySource)
	}
	e.exfatSources[id] = src
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
		return fmt.Errorf("构造 cluster 列表失败: %w", err)
	}
	return writer.WriteEXFATFile(file, clusters, source.Boot, source.PartitionOffset, outputPath)
}
