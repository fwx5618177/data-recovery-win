package recovery

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

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
func (e *Engine) runAPFSScan(
	ctx context.Context,
	reader disk.DiskReader,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 APFS 扫描")

	containers, err := apfs.NewScanner(reader).FindContainers()
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		return nil, nil
	}

	var files []*types.RecoveredFile
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

		c := c // pin loop var; FindContainers 返回 []*Container
		for _, v := range c.Volumes {
			if v.IsEncrypted {
				logger.Info("APFS 卷加密（FileVault），fs tree 不可读，跳过",
					"name", v.Name, "uuid", fmt.Sprintf("%X", v.UUID))
				continue
			}
			if v.RootTreeOID == 0 {
				continue
			}
			crawler := apfs.NewFSTreeCrawler(reader, c.Offset, c.BlockSize, omap)
			if err := crawler.Crawl(v.RootTreeOID); err != nil {
				logger.Warn("APFS 卷 fs tree 遍历失败", "vol", v.Name, "err", err)
				continue
			}
			entries := crawler.EnumerateFiles()
			perVol := 0
			vCopy := v
			for _, ent := range entries {
				if ent.IsDir {
					continue
				}
				rf := apfsEntryToRecoveredFile(ent, c, &vCopy)
				if rf == nil {
					continue
				}
				files = append(files, rf)
				e.cacheAPFSSource(rf.ID, apfsRecoverySource{
					ContainerOffset: c.Offset,
					BlockSize:       c.BlockSize,
					Extents:         ent.Extents,
					LogicalSize:     0,
				})
				if onFound != nil {
					onFound(rf)
				}
				perVol++
			}
			logger.Info("APFS 卷扫描完成", "vol", v.Name, "files", perVol)
		}
	}
	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "apfs", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("APFS 扫描完成", "files", len(files))
	return files, nil
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
