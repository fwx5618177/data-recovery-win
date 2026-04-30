package recovery

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/ext4"
	"data-recovery/internal/types"
)

// ================================================================
// ext2 / ext3 / ext4 扫描与恢复
//
// 面向 Linux / Android 设备。已删除文件在 ext3/4 上恢复率一般（inode 的 block
// pointer/extent 大多被清空），但通过 journal 回放和目录 entry 残留能捞回相当
// 一部分最近操作的文件。
// ================================================================

func (e *Engine) runEXTScan(
	ctx context.Context,
	reader disk.DiskReader,
	includeDeletedPartitions bool,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 ext2/3/4 扫描", "brute_force", includeDeletedPartitions)

	if onProgress != nil {
		onProgress(types.ScanProgress{
			Phase:       "ext",
			Percent:     0.5,
			CurrentFile: "正在查找 ext 分区...",
		})
	}

	scanner := ext4.NewScanner(reader)
	parts, err := scanner.FindPartitions(ctx, ext4.FindOptions{
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
				Phase:        "ext",
				Percent:      percent,
				BytesScanned: scanned,
				TotalBytes:   total,
				CurrentFile:  fmt.Sprintf("正在查找已删除 ext 分区… %s / %s", types.FormatSize(scanned), types.FormatSize(total)),
			})
		},
	})
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, nil
	}

	// 多分区并发扫描：worker 数 = min(NumCPU, len(parts), 4)。
	// 4 是 HDD 友好上限：> 4 并发对单 HDD 有寻道竞争劣化；SSD/NVMe/image file 无害。
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

	// emit 在 onFound / files / source cache 之间做线程安全合并
	emit := func(f *types.RecoveredFile, src extRecoverySource) {
		mu.Lock()
		files = append(files, f)
		mu.Unlock()
		e.cacheEXTSource(f.ID, src)
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
				label := fmt.Sprintf("%s 分区 %d/%d (@0x%X)", p.SuperBlock.Variant, pi+1, len(parts), p.Offset)
				if onProgress != nil {
					mu.Lock()
					done := completed
					mu.Unlock()
					onProgress(types.ScanProgress{
						Phase: "ext", Percent: float64(done) / float64(len(parts)) * 100,
						CurrentFile: label + ": 遍历目录树",
					})
				}

				perPart := 0
				err := scanner.ScanFiles(ctx, p, func(ff ext4.FoundFile) {
					file := extEntryToRecoveredFile(ff)
					if file == nil {
						return
					}
					emit(file, extRecoverySource{
						Inode:      ff.Inode,
						SuperBlock: ff.SuperBlock,
						GroupDescs: ff.GroupDescs,
					})
					perPart++
				})
				if err != nil {
					logger.Warn("ext 扫描分区失败", "partition", label, "err", err)
				} else {
					logger.Info("ext 分区扫描完成", "partition", label, "files", perPart)
				}
				mu.Lock()
				completed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "ext", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("ext 扫描完成", "files", len(files), "concurrency", concurrency)
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

// timePtrIfNonZero 把零值 time.Time 归一化成 nil，避免前端显示 1970-01-01。
// 放在 ext_scan.go 是因为这里调用最频繁（每个 inode 都会用到）；其他 scanner
// 也可以复用。
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
