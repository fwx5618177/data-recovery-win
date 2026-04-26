package recovery

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"data-recovery/internal/disk"
	"data-recovery/internal/fat"
	"data-recovery/internal/types"
)

// ================================================================
// FAT12 / FAT16 / FAT32 扫描与恢复
//
// FAT 族在 U 盘 / SD 卡 / 老相机 / 嵌入式设备里仍然大量存在。已删除文件的 FAT
// 链大概率被清 0，FileClusterList 会退化成"连续 cluster"启发，配合 signature
// validator 能救回大部分连续存储的用户照片。
// ================================================================

// runFATScan 执行 FAT12/16/32 扫描。
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
	if len(parts) == 0 {
		return nil, nil
	}

	concurrency := runtime.NumCPU()
	if concurrency > len(parts) {
		concurrency = len(parts)
	}
	if concurrency > 4 {
		concurrency = 4
	}

	var (
		mu        sync.Mutex
		files     []*types.RecoveredFile
		completed int
	)
	emit := func(f *types.RecoveredFile, src fatRecoverySource) {
		mu.Lock()
		files = append(files, f)
		mu.Unlock()
		e.cacheFATSource(f.ID, src)
		if onFound != nil {
			onFound(f)
		}
	}

	jobs := make(chan int, len(parts))
	for i := range parts {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pi := range jobs {
				if ctx.Err() != nil {
					return
				}
				p := parts[pi]
				label := fmt.Sprintf("%s 分区 %d/%d (@0x%X)",
					p.BootSector.FSType.String(), pi+1, len(parts), p.Offset)
				if onProgress != nil {
					mu.Lock()
					done := completed
					mu.Unlock()
					onProgress(types.ScanProgress{
						Phase:       "fat",
						Percent:     float64(done) / float64(len(parts)) * 100,
						CurrentFile: label + ": 扫描目录",
					})
				}
				perPart := 0
				err := scanner.ScanDirectory(ctx, p.BootSector, p.Offset, func(ff fat.FoundFile) {
					file := fatEntryToRecoveredFile(ff, p.BootSector)
					if file == nil {
						return
					}
					emit(file, fatRecoverySource{
						Entry:           ff.Entry,
						Boot:            p.BootSector,
						PartitionOffset: p.Offset,
					})
					perPart++
				})
				if err != nil {
					logger.Warn("FAT 目录遍历失败", "partition", label, "err", err)
				} else {
					logger.Info("FAT 分区扫描完成", "partition", label, "files", perPart)
				}
				mu.Lock()
				completed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "fat", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("FAT 扫描完成", "files", len(files), "concurrency", concurrency)
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
