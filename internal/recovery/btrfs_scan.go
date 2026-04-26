package recovery

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"data-recovery/internal/btrfs"
	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// ================================================================
// Btrfs 文件枚举与恢复（Linux 较新发行版默认 / Synology / Facebook）
//
// 链路：
//   FindVolumes → 对每个卷 ParseExtendedSuperblock → EnumerateFSTreeFiles
//   → 每个 FSTreeFile 转 RecoveredFile + 缓存 source 给 recover 阶段用
//
// 当前实现的边界：
//   ✅ FS tree 全量枚举（含 subvolume / snapshot）
//   ✅ INODE_ITEM + INODE_REF / DIR_INDEX 关联文件名 + 父目录
//   ✅ EXTENT_DATA 三种 type：inline / regular / prealloc
//   ✅ 多 extent 拼接（chunk catalog 翻译 logical → physical）
//   ❌ 压缩 extent：识别 compression type 字段但不解压（zlib / LZO / ZSTD）
//   ❌ RAID 5/6 parity 重建（单盘 RAID 0 / 1 / 10 走 stripes[0] OK）
// ================================================================

// btrfsRecoverySource 缓存恢复一个 btrfs 文件需要的全部上下文。
type btrfsRecoverySource struct {
	File     *btrfs.FSTreeFile
	SB       *btrfs.ExtendedSuperblock
	Catalog  *btrfs.ChunkCatalog
	VolStart int64
}

func (e *Engine) runBtrfsScan(
	ctx context.Context,
	reader disk.DiskReader,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 Btrfs 扫描")

	scanner := btrfs.NewScanner(reader)
	vols, err := scanner.FindVolumes()
	if err != nil {
		return nil, err
	}
	if len(vols) == 0 {
		logger.Info("未发现 Btrfs 卷")
		return nil, nil
	}

	concurrency := runtime.NumCPU()
	if concurrency > len(vols) {
		concurrency = len(vols)
	}
	if concurrency > 4 {
		concurrency = 4
	}

	var (
		mu        sync.Mutex
		files     []*types.RecoveredFile
		completed int
	)
	emit := func(rf *types.RecoveredFile, src btrfsRecoverySource) {
		mu.Lock()
		files = append(files, rf)
		mu.Unlock()
		e.cacheBtrfsSource(rf.ID, src)
		if onFound != nil {
			onFound(rf)
		}
	}

	jobs := make(chan int, len(vols))
	for i := range vols {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for vi := range jobs {
				if ctx.Err() != nil {
					return
				}
				sb := vols[vi]
				volStart := sb.Offset - btrfs.SuperblockOffset
				ext, err := btrfs.ParseExtendedSuperblock(reader, volStart)
				if err != nil {
					logger.Warn("Btrfs ParseExtendedSuperblock 失败", "vol", vi, "err", err)
					continue
				}

				label := fmt.Sprintf("Btrfs 卷 %d/%d (label=%q)", vi+1, len(vols), sb.Label)
				if onProgress != nil {
					mu.Lock()
					done := completed
					mu.Unlock()
					onProgress(types.ScanProgress{
						Phase: "btrfs", Percent: float64(done) / float64(len(vols)) * 100,
						CurrentFile: label + ": 遍历 FS tree",
					})
				}

				fsFiles, err := btrfs.EnumerateFSTreeFiles(reader, volStart, ext)
				if err != nil {
					logger.Warn("Btrfs EnumerateFSTreeFiles 失败", "vol", vi, "err", err)
					mu.Lock()
					completed++
					mu.Unlock()
					continue
				}

				// 共享 chunk catalog 给所有文件的 recover 阶段
				catalog, err := btrfs.NewChunkCatalog(reader, volStart, ext)
				if err != nil {
					logger.Warn("Btrfs NewChunkCatalog 失败", "vol", vi, "err", err)
					mu.Lock()
					completed++
					mu.Unlock()
					continue
				}

				perVol := 0
				for _, f := range fsFiles {
					if ctx.Err() != nil {
						return
					}
					rf := btrfsFileToRecoveredFile(f, sb.Label, vi)
					if rf == nil {
						continue
					}
					emit(rf, btrfsRecoverySource{
						File:     f,
						SB:       ext,
						Catalog:  catalog,
						VolStart: volStart,
					})
					perVol++
				}
				logger.Info("Btrfs 卷扫描完成", "vol", vi, "files", perVol)
				mu.Lock()
				completed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "btrfs", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("Btrfs 扫描完成", "files", len(files), "concurrency", concurrency)
	return files, nil
}

// btrfsFileToRecoveredFile 把 btrfs.FSTreeFile 转成统一 RecoveredFile。
// 跳过目录、空名、零大小的非文件项。
func btrfsFileToRecoveredFile(f *btrfs.FSTreeFile, volLabel string, volIdx int) *types.RecoveredFile {
	if f == nil || f.IsDir {
		return nil
	}
	name := f.Name
	if name == "" {
		// 没文件名 → 用 inode id 兜底（恢复时仍能写入）
		name = fmt.Sprintf("INODE_%d", f.InoID)
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	category := categorizeByExtension(ext)

	desc := fmt.Sprintf("Btrfs (label=%q)", volLabel)
	if f.Compression != 0 {
		desc += fmt.Sprintf(" 压缩=%d", f.Compression) // 1=zlib 2=lzo 3=zstd
	}
	if f.IsSymlink {
		desc += " symlink"
	}

	// 完整路径优先于 basename：FSTreeFile.FullPath 在 EnumerateFSTreeFiles 末尾
	// 通过 parents/names 回溯填充；若回溯失败（断链 / 系统文件等）退回 basename。
	originalPath := f.FullPath
	if originalPath == "" {
		originalPath = "/" + name
	}

	id := fmt.Sprintf("btrfs_%d_%d", volIdx, f.InoID)
	return &types.RecoveredFile{
		ID:           id,
		Source:       "btrfs",
		FileName:     name,
		Extension:    ext,
		Category:     category,
		Size:         int64(f.Size),
		SizeHuman:    types.FormatSize(int64(f.Size)),
		OriginalPath: originalPath,
		Description:  desc,
		ModifiedTime: btrfsTimePtr(f.ModTime),
	}
}

func btrfsTimePtr(epoch int64) *time.Time {
	if epoch <= 0 {
		return nil
	}
	t := time.Unix(epoch, 0)
	return &t
}

func (e *Engine) cacheBtrfsSource(id string, src btrfsRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.btrfsSources == nil {
		e.btrfsSources = make(map[string]btrfsRecoverySource)
	}
	e.btrfsSources[id] = src
}

// recoverBtrfsFile 从缓存的 source 把 btrfs 文件按 extents 拼出来写盘。
//
// 当前限制：
//   - 压缩 extent 直接拷贝原始（压缩后）字节，不解压；用户拿到的 .gz 风格垃圾
//     提示（产品上应在 UI 上 warn 用户"压缩文件需用 btrfs-progs 打开"）
//   - prealloc extent 写零（preallocated 但未写入实际数据）
func (e *Engine) recoverBtrfsFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	source, ok := e.btrfsSources[file.ID]
	writer := e.writer
	reader := e.reader
	e.mu.RUnlock()

	if writer == nil {
		return fmt.Errorf("写入器未初始化")
	}
	if !ok || source.File == nil {
		return fmt.Errorf("btrfs 恢复源已丢失 (ID=%s)", file.ID)
	}
	if reader == nil {
		return fmt.Errorf("磁盘 reader 未初始化")
	}

	return writer.WriteBtrfsFile(file, source.File, source.SB, source.Catalog, source.VolStart, outputPath)
}
