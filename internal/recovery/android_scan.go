package recovery

// ============================================================================
// Android `.ab` 备份扫描接入 Engine
// ============================================================================

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"data-recovery/internal/android"
	"data-recovery/internal/types"
)

// 类型别名给 engine.go 的 struct 字段（保持主文件 import 瘦身）
type androidBackupAlias = android.Backup

// androidRecoverySource 把 Backup 句柄 + 单条 entry 关联起来。
// Recover 阶段按 file.ID 找对应的 (backup, entry name)，调 backup.RecoverFile。
type androidRecoverySource struct {
	backup    *android.Backup
	entryName string
}

// AndroidBackupInfo UI 友好的备份元数据
type AndroidBackupInfo struct {
	Path         string `json:"path"`
	Version      int    `json:"version"`
	IsCompressed bool   `json:"isCompressed"`
	IsEncrypted  bool   `json:"isEncrypted"`
}

// InspectAndroidBackup 仅读 .ab 头部判断是否加密 / 版本（不解密）。
// UI 上传文件后立即调一次，决定要不要弹密码框。
func (e *Engine) InspectAndroidBackup(path string) (*AndroidBackupInfo, error) {
	// 用 DialBackup("") 触发 ErrEncrypted 即可知道加密状态
	b, err := android.DialBackup(context.Background(), path, "")
	if err == android.ErrEncrypted {
		// 加密但只想看头部 —— 重新只 parse header（DialBackup 已经走了一次但没暴露 header）
		// 我们改用直接 ParseHeader 的简化路径
		// 但 DialBackup 用 path 参数我们没保留 header；为了简化，直接 reopen 并 parse。
		return inspectByPath(path)
	}
	if err != nil {
		return nil, err
	}
	defer b.Close()
	return &AndroidBackupInfo{
		Path:         path,
		Version:      b.Header.Version,
		IsCompressed: b.Header.IsCompressed,
		IsEncrypted:  b.Header.IsEncrypted(),
	}, nil
}

func inspectByPath(path string) (*AndroidBackupInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hdr, err := android.ParseHeader(f)
	if err != nil {
		return nil, err
	}
	return &AndroidBackupInfo{
		Path:         path,
		Version:      hdr.Version,
		IsCompressed: hdr.IsCompressed,
		IsEncrypted:  hdr.IsEncrypted(),
	}, nil
}

// ScanAndroidBackup 扫描一份 .ab，把每个文件转成 RecoveredFile。
//
// password == "" 时：未加密直接扫；加密则返回 android.ErrEncrypted。
//
// 注意：和 iOS 不同，.ab 是流式 tar，扫描必须把整个文件读一遍才能列出条目；
// 大 backup（几 GB）会扫几秒到几十秒。前端进度条按 entry 数量更新。
func (e *Engine) ScanAndroidBackup(
	ctx context.Context,
	backupPath, password string,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	b, err := android.DialBackup(ctx, backupPath, password)
	if err != nil {
		return nil, err
	}

	// 挂到 Engine 让 Recover 阶段能复用同一份 Backup（密钥已解到内存里）
	e.mu.Lock()
	e.androidBackups = append(e.androidBackups, b)
	e.mu.Unlock()

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "android", Percent: 0, CurrentFile: filepath.Base(backupPath)})
	}

	var files []*types.RecoveredFile
	count := 0
	err = b.EnumerateFiles(ctx, func(ent android.ABEntry) {
		count++
		if !shouldIncludeAndroidEntry(ent) {
			return
		}
		rf := abEntryToRecoveredFile(ent, backupPath, b.IsEncrypted())
		if rf == nil {
			return
		}
		files = append(files, rf)
		e.cacheAndroidSource(rf.ID, androidRecoverySource{backup: b, entryName: ent.Name})
		if onFound != nil {
			onFound(rf)
		}
		if count%200 == 0 && onProgress != nil {
			// 流式格式不知道总数；进度条按"已扫文件数"展示，不强求百分比
			onProgress(types.ScanProgress{
				Phase:       "android",
				FilesFound:  len(files),
				CurrentFile: ent.Name,
			})
		}
	})
	if err != nil {
		return files, err
	}

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "android", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("Android backup 扫描完成",
		"path", backupPath,
		"encrypted", b.IsEncrypted(),
		"version", b.Header.Version,
		"files", len(files))
	return files, nil
}

// shouldIncludeAndroidEntry 过滤"不是用户想恢复的"条目
//   - 目录：跳过（前端展示为文件列表）
//   - 符号链接：保留（RecoverFile 会落成 .symlink.txt）
//   - "_meta" 等 backup 内部元数据文件：跳过（用户拿了也没用）
func shouldIncludeAndroidEntry(e android.ABEntry) bool {
	if e.IsDir {
		return false
	}
	if e.Name == "" {
		return false
	}
	if strings.HasPrefix(e.Name, "apps/") && strings.HasSuffix(e.Name, "/_manifest") {
		return false
	}
	return true
}

func abEntryToRecoveredFile(e android.ABEntry, backupPath string, encrypted bool) *types.RecoveredFile {
	name := filepath.Base(e.Name)
	if name == "" || name == "/" || name == "." {
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	desc := "Android 备份"
	if encrypted {
		desc += "（加密已解锁）"
	}
	app := android.AppDomainFromPath(e.Name)
	displayPath := app + "/" + e.Name

	var modPtr *time.Time
	if !e.ModTime.IsZero() {
		t := e.ModTime
		modPtr = &t
	}

	return &types.RecoveredFile{
		ID:           fmt.Sprintf("android_%s_%s", filepath.Base(backupPath), e.Name),
		Source:       "android",
		FileName:     name,
		Extension:    ext,
		Category:     categorizeByExtension(ext),
		Size:         e.Size,
		SizeHuman:    types.FormatSize(e.Size),
		Offset:       0,
		Confidence:   1.0,
		IsValid:      true,
		OriginalPath: displayPath,
		ModifiedTime: modPtr,
		Description:  desc,
	}
}

func (e *Engine) cacheAndroidSource(id string, src androidRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.androidSources == nil {
		e.androidSources = make(map[string]androidRecoverySource)
	}
	e.androidSources[id] = src
}

// recoverAndroidFile 从对应 Backup 流式提取这个 file。
//
// 性能注意：每个文件都要重扫一遍 tar 流（流式格式无随机访问）。
// 大批量恢复时会被 batch 化（见 batchRecoverAndroidFiles）。
func (e *Engine) recoverAndroidFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	src, ok := e.androidSources[file.ID]
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("android 恢复源已丢失 (ID=%s)", file.ID)
	}
	return src.backup.RecoverFile(context.Background(), src.entryName, outputPath)
}

// closeAndroidBackups 在 Engine.Shutdown 时清掉所有 backup 句柄（清密钥）
func (e *Engine) closeAndroidBackups() {
	for _, b := range e.androidBackups {
		if b != nil {
			_ = b.Close()
		}
	}
	e.androidBackups = nil
}
