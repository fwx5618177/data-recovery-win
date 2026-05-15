package recovery

// ============================================================================
// iOS 备份扫描：走 internal/ios 的 Session，产出 RecoveredFile（source="ios"）。
//
// 两种启动方式：
//   ScanIOSBackup(ctx, path, password, ...)   UI 已经选定某个备份
//   DiscoverIOSBackups()                      UI 列表查看本机所有可用备份
// ============================================================================

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"data-recovery/internal/ios"
	"data-recovery/internal/types"
)

// 类型别名：让 engine.go 的 struct 字段不用直接 import ios（保持瘦）
type iosSessionAlias = ios.Session

// iosRecoverySource 为 recoverIOSFile 保留的信息：一个会话 + 一条记录
type iosRecoverySource struct {
	session *ios.Session
	record  ios.FileRecord
}

// IOSBackupInfo 前端 UI 展示用（json 友好）
type IOSBackupInfo struct {
	UDID           string `json:"udid"`
	Root           string `json:"root"`
	DeviceName     string `json:"deviceName"`
	ProductType    string `json:"productType"`
	ProductVersion string `json:"productVersion"`
	IsEncrypted    bool   `json:"isEncrypted"`
	LastBackup     int64  `json:"lastBackup"` // unix 秒
}

// DiscoverIOSBackups 列出本机所有 iOS 备份（给 UI 选择列表）。
func (e *Engine) DiscoverIOSBackups() ([]IOSBackupInfo, error) {
	backups, err := ios.DiscoverBackups()
	if err != nil {
		return nil, err
	}
	out := make([]IOSBackupInfo, 0, len(backups))
	for _, b := range backups {
		out = append(out, IOSBackupInfo{
			UDID:           b.UDID,
			Root:           b.Root,
			DeviceName:     b.DeviceName,
			ProductType:    b.ProductType,
			ProductVersion: b.ProductVersion,
			IsEncrypted:    b.IsEncrypted,
			LastBackup:     b.LastBackup.Unix(),
		})
	}
	return out, nil
}

// ScanIOSBackup 扫描指定备份目录，产出每个文件为 RecoveredFile（源头="ios"）。
//
// password = "" 时：
//
//	非加密备份正常扫描；加密备份返回 ios.ErrEncrypted，UI 应提示用户输密码。
//
// 会话由 Engine 持有直到 Shutdown —— Recover 阶段要复用 session 拷贝 / 解密文件。
func (e *Engine) ScanIOSBackup(
	ctx context.Context,
	backupPath, password string,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	backup, err := ios.OpenBackup(backupPath)
	if err != nil {
		return nil, err
	}

	sess, err := ios.DialBackup(ctx, backup, password)
	if err != nil {
		return nil, err
	}

	// 挂到 Engine 以便后续 Recover 使用；Shutdown 会统一 Close
	e.mu.Lock()
	e.iosSessions = append(e.iosSessions, sess)
	e.mu.Unlock()

	label := fmt.Sprintf("iOS 备份 %s", backup.DeviceName)
	if label == "iOS 备份 " {
		label = "iOS 备份"
	}
	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "ios", Percent: 0, CurrentFile: label})
	}

	var files []*types.RecoveredFile
	err = sess.EnumerateFiles(ctx, func(rec ios.FileRecord) {
		if !rec.IsFile() {
			return
		}
		rf := iosRecordToRecoveredFile(rec, backup, sess.IsEncrypted())
		if rf == nil {
			return
		}
		files = append(files, rf)
		e.cacheIOSSource(rf.ID, iosRecoverySource{session: sess, record: rec})
		if onFound != nil {
			onFound(rf)
		}
	})
	if err != nil {
		return files, err
	}

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "ios", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("iOS 备份扫描完成",
		"udid", backup.UDID,
		"device", backup.DeviceName,
		"encrypted", backup.IsEncrypted,
		"files", len(files))
	return files, nil
}

func iosRecordToRecoveredFile(rec ios.FileRecord, backup *ios.Backup, encrypted bool) *types.RecoveredFile {
	if rec.FileID == "" {
		return nil
	}
	name := filepath.Base(rec.RelativePath)
	if name == "" || name == "." || name == "/" {
		// domain-only 记录（如 CameraRollDomain 根目录），跳过
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))

	desc := "iOS 备份"
	if encrypted {
		desc += " (加密已解锁)"
	}

	var modTime *time.Time
	if rec.MTime > 0 {
		t := time.Unix(rec.MTime, 0)
		modTime = &t
	}
	var createTime *time.Time
	if rec.BTime > 0 {
		t := time.Unix(rec.BTime, 0)
		createTime = &t
	}

	return &types.RecoveredFile{
		ID:           fmt.Sprintf("ios_%s_%s", backup.UDID, rec.FileID),
		Source:       "ios",
		FileName:     name,
		Extension:    ext,
		Category:     categorizeByExtension(ext),
		Size:         rec.Size,
		SizeHuman:    types.FormatSize(rec.Size),
		Offset:       0,
		Confidence:   1.0, // 备份里的文件都是活跃数据，权威
		IsValid:      true,
		OriginalPath: ios.DomainDisplayPath(rec.Domain, rec.RelativePath),
		ModifiedTime: modTime,
		CreatedTime:  createTime,
		Description:  desc,
	}
}

func (e *Engine) cacheIOSSource(id string, src iosRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.iosSources == nil {
		e.iosSources = make(map[string]iosRecoverySource)
	}
	e.iosSources[id] = src
}

// recoverIOSFile 把一个 iOS 备份文件写到本地（未加密 = 直接拷；加密 = AES-CBC 解密）。
func (e *Engine) recoverIOSFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	src, ok := e.iosSources[file.ID]
	e.mu.RUnlock()
	if !ok {
		return fmt.Errorf("iOS 恢复源已丢失 (ID=%s)", file.ID)
	}
	return src.session.RecoverFile(src.record, outputPath)
}

// closeIOSSessions 在 Engine.Shutdown 时被调用
func (e *Engine) closeIOSSessions() {
	for _, s := range e.iosSessions {
		if s != nil {
			_ = s.Close()
		}
	}
	e.iosSessions = nil
}
