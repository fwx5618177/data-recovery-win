package recovery

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"data-recovery/internal/apfs"
	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// apfsRecoverySource 保存 APFS 文件恢复所需信息：extent 列表 + 容器偏移 + block size
type apfsRecoverySource struct {
	ContainerOffset int64
	BlockSize       uint32
	Extents         []apfs.FileExtentRecord
	LogicalSize     uint64
}

// runAPFSScan 执行 APFS 卷的文件枚举：
//
//	1. 全盘找 APFS 容器
//	2. 每个容器 LoadOmap → 拿到 (vOID → pAddr) 映射
//	3. 对每个未加密卷：用 omap 解出 root tree 物理位置 → FSTreeCrawler.Crawl
//	4. EnumerateFiles 拍平成 (path, inode, extents) 列表 → RecoveredFile
//
// 加密卷（FileVault）跳过：需要 keybag 解出 VEK 才能读 fs tree（fs tree 节点本身也加密）。
//
// includeDeletedPartitions=true 启用 brute-force 找已删除/孤立的 APFS 容器残骸。
func (e *Engine) runAPFSScan(
	ctx context.Context,
	reader disk.DiskReader,
	includeDeletedPartitions bool,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 APFS 扫描", "brute_force", includeDeletedPartitions)

	if onProgress != nil {
		onProgress(types.ScanProgress{
			Phase:       "apfs",
			Percent:     0.5,
			CurrentFile: "正在查找 APFS 容器...",
		})
	}

	containers, err := apfs.NewScanner(reader).FindContainers(ctx, apfs.FindOptions{
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
				Phase:        "apfs",
				Percent:      percent,
				BytesScanned: scanned,
				TotalBytes:   total,
				CurrentFile:  fmt.Sprintf("正在查找已删除 APFS 容器… %s / %s", types.FormatSize(scanned), types.FormatSize(total)),
			})
		},
	})
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		return nil, nil
	}

	var (
		mu    sync.Mutex
		files []*types.RecoveredFile
	)
	emit := func(rf *types.RecoveredFile, src apfsRecoverySource) {
		mu.Lock()
		files = append(files, rf)
		mu.Unlock()
		e.cacheAPFSSource(rf.ID, src)
		if onFound != nil {
			onFound(rf)
		}
	}

	for ci, c := range containers {
		if ctx.Err() != nil {
			return files, ctx.Err()
		}
		if onProgress != nil {
			onProgress(types.ScanProgress{
				Phase:       "apfs",
				Percent:     float64(ci) / float64(len(containers)) * 100,
				CurrentFile: fmt.Sprintf("APFS 容器 %d/%d @0x%X 加载 omap", ci+1, len(containers), c.Offset),
			})
		}

		omap, err := apfs.LoadOmap(reader, c.Offset, c.BlockSize, c.OmapOID)
		if err != nil || len(omap) == 0 {
			logger.Warn("APFS omap 加载失败（跳过本容器）", "container", c.Offset, "err", err)
			continue
		}

		c := c // pin loop var
		// 单容器内多卷并发：典型 Mac 系统盘有 system / data / preboot / recovery / vm
		// 等 4-8 个卷；并发能 2-4× 加速。Worker 数 ∩ 4 是 HDD 友好上限。
		concurrency := runtime.NumCPU()
		if concurrency > len(c.Volumes) {
			concurrency = len(c.Volumes)
		}
		if concurrency > 4 {
			concurrency = 4
		}
		if concurrency < 1 {
			concurrency = 1
		}

		jobs := make(chan int, len(c.Volumes))
		for vi := range c.Volumes {
			jobs <- vi
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
					v := c.Volumes[vi]
					scanAPFSVolume(e, reader, c, v, omap, emit)
				}
			}()
		}
		wg.Wait()
	}
	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "apfs", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("APFS 扫描完成", "files", len(files))
	return files, nil
}

// scanAPFSVolume 扫描单个 APFS 卷（FileVault 走 EncryptedReader；普通卷直读）。
// 把 emit 抽出来后这里逻辑纯净 — 给 worker pool 调用。
func scanAPFSVolume(
	e *Engine,
	reader disk.DiskReader,
	c *apfs.Container,
	v apfs.Volume,
	omap map[uint64]apfs.OmapEntry,
	emit func(*types.RecoveredFile, apfsRecoverySource),
) {
	if v.IsEncrypted {
		vek := e.getAPFSVEK(v.UUID)
		if vek == nil {
			logger.Info("APFS 卷加密（FileVault）— 未提供 VEK，fs tree 不可读，跳过",
				"name", v.Name, "uuid", fmt.Sprintf("%X", v.UUID))
			return
		}
		encReader, err := apfs.NewEncryptedReader(reader, vek, c.BlockSize, c.Offset)
		if err != nil {
			logger.Warn("FileVault EncryptedReader 构造失败", "vol", v.Name, "err", err)
			return
		}
		if v.RootTreeOID == 0 {
			return
		}
		crawler := apfs.NewFSTreeCrawler(encReader, c.Offset, c.BlockSize, omap)
		if err := crawler.Crawl(v.RootTreeOID); err != nil {
			logger.Warn("FileVault fs tree 遍历失败", "vol", v.Name, "err", err)
			return
		}
		for _, ent := range crawler.EnumerateFiles() {
			if ent.IsDir {
				continue
			}
			rf := apfsEntryToRecoveredFile(ent, c, &v)
			if rf == nil {
				continue
			}
			rf.Description += " (FileVault 解密后)"
			emit(rf, apfsRecoverySource{
				ContainerOffset: c.Offset,
				BlockSize:       c.BlockSize,
				Extents:         ent.Extents,
			})
		}
		return
	}

	if v.RootTreeOID == 0 {
		return
	}
	crawler := apfs.NewFSTreeCrawler(reader, c.Offset, c.BlockSize, omap)
	if err := crawler.Crawl(v.RootTreeOID); err != nil {
		logger.Warn("APFS 卷 fs tree 遍历失败", "vol", v.Name, "err", err)
		return
	}
	perVol := 0
	for _, ent := range crawler.EnumerateFiles() {
		if ent.IsDir {
			continue
		}
		rf := apfsEntryToRecoveredFile(ent, c, &v)
		if rf == nil {
			continue
		}
		emit(rf, apfsRecoverySource{
			ContainerOffset: c.Offset,
			BlockSize:       c.BlockSize,
			Extents:         ent.Extents,
			LogicalSize:     0,
		})
		perVol++
	}
	logger.Info("APFS 卷扫描完成", "vol", v.Name, "files", perVol)
}

func apfsEntryToRecoveredFile(ent apfs.FileEntry, c *apfs.Container, v *apfs.Volume) *types.RecoveredFile {
	if ent.Inode == nil {
		return nil
	}
	name := filepath.Base(ent.Path)
	if name == "" || name == "/" {
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	category := categorizeByExtension(ext)

	id := fmt.Sprintf("apfs_%X_%d", c.Offset, ent.Inode.ObjID)
	desc := fmt.Sprintf("APFS / 卷 %q", v.Name)

	// 用 extent 累计算文件总大小（inode 里 size 可能是未必同步的字段）
	var size int64
	for _, ex := range ent.Extents {
		size += int64(ex.Length)
	}

	return &types.RecoveredFile{
		ID:           id,
		Source:       "apfs",
		FileName:     name,
		Extension:    ext,
		Category:     category,
		Size:         size,
		SizeHuman:    types.FormatSize(size),
		Offset:       0,
		Confidence:   0.0,
		IsDeleted:    false,
		OriginalPath: ent.Path,
		Description:  desc,
	}
}

func (e *Engine) cacheAPFSSource(id string, src apfsRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.apfsSources == nil {
		e.apfsSources = make(map[string]apfsRecoverySource)
	}
	e.apfsSources[id] = src
}

// recoverAPFSFile 把 APFS 文件按 extent 拼出来写到 outputPath。
//
// 每个 extent: (LogicalOffset, Length, PhysicalBlock)
//   PhysicalBlock = 0 表示稀疏洞（写 0）
//   否则从容器内物理位置 (containerOffset + PhysicalBlock * blockSize + extent_internal_off) 读
func (e *Engine) recoverAPFSFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	src, ok := e.apfsSources[file.ID]
	reader := e.reader
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("找不到 APFS 文件源信息: %s", file.ID)
	}
	if reader == nil {
		return fmt.Errorf("engine reader 为 nil")
	}

	if e.writer == nil {
		e.writer = NewSafeWriter(reader, filepath.Dir(outputPath))
	}

	// 顺序拷贝每个 extent 到目标文件
	out, err := openOutputForWrite(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	const ioChunk = int64(1 << 20) // 1MB
	for _, ex := range src.Extents {
		if ex.Length == 0 {
			continue
		}
		// sparse hole：直接写 0
		if ex.PhysicalBlock == 0 {
			zero := make([]byte, 64*1024)
			remain := int64(ex.Length)
			for remain > 0 {
				w := int64(len(zero))
				if w > remain {
					w = remain
				}
				if _, err := out.Write(zero[:w]); err != nil {
					return err
				}
				remain -= w
			}
			continue
		}
		// 非稀疏：按 ioChunk 段读 + 写
		extPhysOff := src.ContainerOffset + int64(ex.PhysicalBlock)*int64(src.BlockSize)
		remain := int64(ex.Length)
		readOff := extPhysOff
		for remain > 0 {
			w := ioChunk
			if w > remain {
				w = remain
			}
			buf := make([]byte, w)
			n, err := reader.ReadAt(buf, readOff)
			if n > 0 {
				if _, werr := out.Write(buf[:n]); werr != nil {
					return werr
				}
			}
			if err != nil && n == 0 {
				return fmt.Errorf("APFS extent 读失败 @%d: %w", readOff, err)
			}
			remain -= int64(n)
			readOff += int64(n)
		}
	}
	return nil
}
