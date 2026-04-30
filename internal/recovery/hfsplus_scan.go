package recovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"

	"data-recovery/internal/disk"
	"data-recovery/internal/hfsplus"
	"data-recovery/internal/types"
)

// hfsplusRecoverySource 保存 HFS+ 文件恢复所需信息：
type hfsplusRecoverySource struct {
	VolumeOffset int64               // 卷在底层 reader 上的字节偏移
	BlockSize    uint32              // HFS+ block size
	LogicalSize  uint64              // 文件 data fork 字节数
	Extents      [8]hfsplus.ForkExtent
}

// runHFSPlusScan 执行 HFS+ / HFSX 卷扫描：
//
//	1. 全盘找 HFS+ 卷
//	2. 对每个卷读 catalog header → 拿到 catalog file 的 extents
//	3. 顺着 extents 读 catalog B-tree 的 leaf nodes，把 folder/file records 摊出来
//	4. 拍平成 (full path, file) 列表 → RecoveredFile
//
// 由于 HFS+ catalog file 可能跨多个 extent + extents overflow tree（极少见），
// 本实现处理 vol header 给出的 catalog extents（前 8 个）即可覆盖几乎所有真实卷。
//
// includeDeletedPartitions=true 启用 brute-force 找已删除/孤立的 HFS+ 卷。
func (e *Engine) runHFSPlusScan(
	ctx context.Context,
	reader disk.DiskReader,
	includeDeletedPartitions bool,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	logger.Info("开始 HFS+ 扫描", "brute_force", includeDeletedPartitions)

	if onProgress != nil {
		onProgress(types.ScanProgress{
			Phase:       "hfsplus",
			Percent:     0.5,
			CurrentFile: "正在查找 HFS+ 卷...",
		})
	}

	vols, err := hfsplus.NewScanner(reader).FindVolumes(ctx, hfsplus.FindOptions{
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
				Phase:        "hfsplus",
				Percent:      percent,
				BytesScanned: scanned,
				TotalBytes:   total,
				CurrentFile:  fmt.Sprintf("正在查找已删除 HFS+ 卷… %s / %s", types.FormatSize(scanned), types.FormatSize(total)),
			})
		},
	})
	if err != nil {
		return nil, err
	}
	if len(vols) == 0 {
		return nil, nil
	}

	var files []*types.RecoveredFile
	for vi, v := range vols {
		if ctx.Err() != nil {
			return files, ctx.Err()
		}
		if onProgress != nil {
			onProgress(types.ScanProgress{
				Phase:       "hfsplus",
				Percent:     float64(vi) / float64(len(vols)) * 100,
				CurrentFile: fmt.Sprintf("HFS+ 卷 %d/%d @0x%X", vi+1, len(vols), v.Offset),
			})
		}

		// 从 volume header 拿 catalog file 的 extents
		// volume header @ +1024，catalog file fork @ +0x18 起 80 字节（HFSPlusForkData）
		hdr := make([]byte, 512)
		if _, err := reader.ReadAt(hdr, v.Offset+hfsplus.VolumeHeaderOffset); err != nil {
			continue
		}
		// HFSPlusForkData 字节布局：8 logicalSize + 4 clumpSize + 4 totalBlocks + 8*ForkExtent(64)
		// catalogFile fork 在 volume header offset 0xE8 (= 232) — TN1150
		// 解析 8 个 catalog extent
		catalogExtents := parseHFSPlusForkExtents(hdr[0xE8 : 0xE8+80])

		entries, err := walkHFSPlusCatalog(reader, v, catalogExtents)
		if err != nil {
			logger.Warn("HFS+ catalog 遍历失败", "vol", v.Offset, "err", err)
			continue
		}
		// 从 catalog entries 构造 path 字典
		paths := buildHFSPlusPaths(entries)
		perVol := 0
		for _, ent := range entries {
			if ent.File == nil {
				continue
			}
			full := paths[ent.File.FileID]
			rf := hfsplusFileToRecoveredFile(ent.File, full, v)
			if rf == nil {
				continue
			}
			files = append(files, rf)
			e.cacheHFSPlusSource(rf.ID, hfsplusRecoverySource{
				VolumeOffset: v.Offset,
				BlockSize:    v.BlockSize,
				LogicalSize:  ent.File.LogicalSize,
				Extents:      ent.File.Extents,
			})
			if onFound != nil {
				onFound(rf)
			}
			perVol++
		}
		logger.Info("HFS+ 卷扫描完成", "vol", v.Offset, "files", perVol)
	}
	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "hfsplus", Percent: 100, FilesFound: len(files)})
	}
	return files, nil
}

// parseHFSPlusForkExtents 解析 HFSPlusForkData 里的 8 个 ForkExtent
func parseHFSPlusForkExtents(buf []byte) [8]hfsplus.ForkExtent {
	var ex [8]hfsplus.ForkExtent
	if len(buf) < 16+8*8 {
		return ex
	}
	for i := 0; i < 8; i++ {
		off := 16 + i*8
		ex[i] = hfsplus.ForkExtent{
			StartBlock: binary.BigEndian.Uint32(buf[off : off+4]),
			BlockCount: binary.BigEndian.Uint32(buf[off+4 : off+8]),
		}
	}
	return ex
}

// walkHFSPlusCatalog 顺着 catalog 文件的 extents 把所有 leaf B-tree 节点读出来 + 平铺成
// CatalogRecord 列表。简化策略：把每个 extent 视作连续的 4KB node，逐一 ParseCatalogNode。
// 真实 HFS+ B-tree node size 在 catalog header 里 (4096 / 8192)，本实现按 4096 兜底。
func walkHFSPlusCatalog(reader disk.DiskReader, v *hfsplus.VolumeHeader, extents [8]hfsplus.ForkExtent) ([]hfsplus.CatalogRecord, error) {
	const nodeSize = 4096
	var out []hfsplus.CatalogRecord
	buf := make([]byte, nodeSize)
	for _, ex := range extents {
		if ex.BlockCount == 0 {
			continue
		}
		extentByteLen := int64(ex.BlockCount) * int64(v.BlockSize)
		extentStart := v.Offset + int64(ex.StartBlock)*int64(v.BlockSize)
		for off := int64(0); off+nodeSize <= extentByteLen; off += nodeSize {
			n, err := reader.ReadAt(buf, extentStart+off)
			if err != nil && n == 0 {
				continue
			}
			node, err := hfsplus.ParseCatalogNode(buf[:n])
			if err != nil {
				continue
			}
			if node.Kind != hfsplus.BTNodeKindLeaf {
				continue
			}
			out = append(out, node.Records...)
		}
	}
	return out, nil
}

// buildHFSPlusPaths 用 folder records 构造 CNID → 完整路径 字典（递归到 root）。
// HFS+ root folder CNID = 2 (kHFSRootFolderID)
func buildHFSPlusPaths(records []hfsplus.CatalogRecord) map[uint32]string {
	const rootCNID uint32 = 2

	folders := make(map[uint32]string) // CNID → name（不含路径）
	parents := make(map[uint32]uint32) // CNID → parent CNID
	folders[rootCNID] = ""

	for _, r := range records {
		if r.Folder != nil {
			folders[r.Folder.FolderID] = r.Folder.Name
			parents[r.Folder.FolderID] = r.Folder.ParentID
		}
	}

	// 用记忆化展开 folder 路径
	folderPath := func(cnid uint32) string {
		var parts []string
		for c := cnid; c != rootCNID && c != 0; {
			if name, ok := folders[c]; ok {
				parts = append([]string{name}, parts...)
			} else {
				break
			}
			next, ok := parents[c]
			if !ok || next == c {
				break
			}
			c = next
		}
		return "/" + strings.Join(parts, "/")
	}

	out := make(map[uint32]string)
	for _, r := range records {
		if r.File != nil {
			full := filepath.Join(folderPath(r.File.ParentID), r.File.Name)
			out[r.File.FileID] = full
		}
	}
	return out
}

func hfsplusFileToRecoveredFile(f *hfsplus.CatalogFile, fullPath string, v *hfsplus.VolumeHeader) *types.RecoveredFile {
	if f == nil {
		return nil
	}
	name := f.Name
	if fullPath == "" {
		fullPath = name
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	category := categorizeByExtension(ext)
	id := fmt.Sprintf("hfsplus_%X_%d", v.Offset, f.FileID)
	desc := "HFS+"
	if v.IsHFSX {
		desc = "HFSX"
	}
	return &types.RecoveredFile{
		ID:           id,
		Source:       "hfsplus",
		FileName:     name,
		Extension:    ext,
		Category:     category,
		Size:         int64(f.LogicalSize),
		SizeHuman:    types.FormatSize(int64(f.LogicalSize)),
		Offset:       0,
		Confidence:   0.0,
		IsDeleted:    false,
		OriginalPath: fullPath,
		Description:  desc,
	}
}

func (e *Engine) cacheHFSPlusSource(id string, src hfsplusRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hfsplusSources == nil {
		e.hfsplusSources = make(map[string]hfsplusRecoverySource)
	}
	e.hfsplusSources[id] = src
}

// recoverHFSPlusFile 按 ForkExtent 顺序读 + 拼到 outputPath。
// 注意：HFS+ 文件超过 8 个 extent 的部分在 extents overflow tree 里，本实现不处理
// （>8 extent 的文件极少；视频/超大文件可能命中）。
func (e *Engine) recoverHFSPlusFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	src, ok := e.hfsplusSources[file.ID]
	reader := e.reader
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("找不到 HFS+ 文件源信息: %s", file.ID)
	}
	if reader == nil {
		return fmt.Errorf("engine reader 为 nil")
	}

	out, err := openOutputForWrite(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	remain := int64(src.LogicalSize)
	for _, ex := range src.Extents {
		if ex.BlockCount == 0 || remain <= 0 {
			break
		}
		extentLen := int64(ex.BlockCount) * int64(src.BlockSize)
		if extentLen > remain {
			extentLen = remain
		}
		extentStart := src.VolumeOffset + int64(ex.StartBlock)*int64(src.BlockSize)
		const ioChunk = int64(1 << 20)
		left := extentLen
		readOff := extentStart
		for left > 0 {
			w := ioChunk
			if w > left {
				w = left
			}
			buf := make([]byte, w)
			n, err := reader.ReadAt(buf, readOff)
			if n > 0 {
				if _, werr := out.Write(buf[:n]); werr != nil {
					return werr
				}
			}
			if err != nil && n == 0 {
				return fmt.Errorf("HFS+ extent 读失败 @%d: %w", readOff, err)
			}
			left -= int64(n)
			readOff += int64(n)
			remain -= int64(n)
		}
	}
	return nil
}
