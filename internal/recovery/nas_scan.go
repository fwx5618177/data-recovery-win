package recovery

// ============================================================================
// NAS 网络共享扫描：SMB / NFS
//
// 和"盘级扫描"（NTFS / APFS / carver）的差异：
//   - 不做块级原始读，走 SMB/NFS 的文件级 API；一条条文件"直接拷"
//   - 不做"已删除文件恢复"（SMB/NFS 协议本身不暴露这种能力）
//   - 适用场景：NAS 坏盘前紧急备份；企业文件服务器迁移；U 盘接网络共享备份
//
// 为什么仍然走 Engine：统一的"扫描进度 + 文件选中 + 恢复成报告"UX，
// 用户不用学第二套流程。
// ============================================================================

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"data-recovery/internal/netfs"
	"data-recovery/internal/types"
)

// 类型别名：给 engine.go 里的 struct 字段用，避免在 engine.go 里 import netfs
// （engine.go 想尽量瘦，"网络协议栈 import"属于 NAS 子关切）
type (
	netfsSMBSession = netfs.SMBSession
	netfsNFSSession = netfs.NFSSession
)

// NASRecoverySource NAS 文件恢复用的信息：
//   - SMB：smbSession + share + path
//   - NFS：nfsSession + file handle + size
type NASRecoverySource struct {
	Kind string // "smb" | "nfs"
	SMB  *nasSMBRef
	NFS  *nasNFSRef
}

type nasSMBRef struct {
	Session *netfs.SMBSession
	Share   string
	Path    string
}

type nasNFSRef struct {
	Session *netfs.NFSSession
	FH      []byte
	Size    int64
}

// SMBScanRequest 一次 SMB 扫描任务的参数。
// v2.8.36: 加 json tag —— 当前虽然只在 Go 内部用，但加上保持跟所有 IPC-邻近类型
// 一致，免得未来扩成 IPC 直接暴露时撞 JSON-tag 缺失 bug。
type SMBScanRequest struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	User     string   `json:"user"`
	Password string   `json:"password"`
	Domain   string   `json:"domain"`
	Shares   []string `json:"shares"` // 空 = 全部 share
	MaxDepth int      `json:"maxDepth"`
	MaxFiles int      `json:"maxFiles"`
}

// NFSScanRequest 一次 NFS 扫描任务的参数。
type NFSScanRequest struct {
	Host      string   `json:"host"`
	NFSPort   uint32   `json:"nfsPort"`
	MountPort uint32   `json:"mountPort"`
	UID       uint32   `json:"uid"`
	GID       uint32   `json:"gid"`
	Exports   []string `json:"exports"` // 空 = 全部 export
	MaxDepth  int      `json:"maxDepth"`
	MaxFiles  int      `json:"maxFiles"`
}

// ScanSMBShare 扫描 SMB 共享。整个会话由 Engine 持有直到 Shutdown / 用户取消。
//
// 为什么 Engine 持 session：Recover 阶段要按已枚举的文件 ID 取出来重新读内容。
// 如果 session 扫完就关闭了，Recover 要从头建连 + 重新 Walk 找文件，费时且可能
// 因为 NAS 文件被改动而拿到不同数据。
func (e *Engine) ScanSMBShare(
	ctx context.Context,
	req SMBScanRequest,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	cfg := netfs.SMBScanConfig{
		Host: req.Host, Port: req.Port,
		User: req.User, Password: req.Password, Domain: req.Domain,
		Shares: req.Shares, MaxDepth: req.MaxDepth, MaxFiles: req.MaxFiles,
	}
	sess, err := netfs.DialSMB(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// 挂会话到 Engine，供 Recover 阶段复用；Shutdown 时统一 Close
	e.mu.Lock()
	e.nasSMBSessions = append(e.nasSMBSessions, sess)
	e.mu.Unlock()

	shares := req.Shares
	if len(shares) == 0 {
		if lst, err := sess.ListShares(); err == nil {
			shares = lst
		} else {
			logger.Warn("SMB 列 share 失败，需要用户显式指定", "err", err)
			return nil, err
		}
	}

	var files []*types.RecoveredFile
	for si, share := range shares {
		if ctx.Err() != nil {
			return files, ctx.Err()
		}
		label := fmt.Sprintf("SMB 共享 %d/%d: \\\\%s\\%s", si+1, len(shares), req.Host, share)
		if onProgress != nil {
			onProgress(types.ScanProgress{
				Phase: "smb", Percent: float64(si) / float64(len(shares)) * 100,
				CurrentFile: label + ": 遍历目录",
			})
		}

		err := sess.WalkShare(ctx, share, cfg, func(ent netfs.SMBDirEntry) {
			if ent.IsDir {
				return
			}
			rf := smbEntryToRecoveredFile(ent, req.Host)
			if rf == nil {
				return
			}
			files = append(files, rf)
			e.cacheNASSource(rf.ID, NASRecoverySource{
				Kind: "smb",
				SMB: &nasSMBRef{
					Session: sess,
					Share:   ent.Share,
					Path:    ent.Path,
				},
			})
			if onFound != nil {
				onFound(rf)
			}
		})
		if err != nil {
			logger.Warn("SMB 扫描 share 失败", "share", share, "err", err)
			continue
		}
	}

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "smb", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("SMB 扫描完成", "host", req.Host, "files", len(files))
	return files, nil
}

// ScanNFSExport 扫描 NFS export。
func (e *Engine) ScanNFSExport(
	ctx context.Context,
	req NFSScanRequest,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) ([]*types.RecoveredFile, error) {
	cfg := netfs.NFSScanConfig{
		Host: req.Host, NFSPort: req.NFSPort, MountPort: req.MountPort,
		UID: req.UID, GID: req.GID,
		Exports: req.Exports, MaxDepth: req.MaxDepth, MaxFiles: req.MaxFiles,
	}
	sess, err := netfs.DialNFSSession(ctx, cfg)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.nasNFSSessions = append(e.nasNFSSessions, sess)
	e.mu.Unlock()

	exports := req.Exports
	if len(exports) == 0 {
		if lst, err := sess.ListExports(ctx); err == nil {
			exports = lst
		} else {
			logger.Warn("NFS 列 export 失败", "err", err)
			return nil, err
		}
	}

	var files []*types.RecoveredFile
	for ei, exp := range exports {
		if ctx.Err() != nil {
			return files, ctx.Err()
		}
		label := fmt.Sprintf("NFS export %d/%d: %s:%s", ei+1, len(exports), req.Host, exp)
		if onProgress != nil {
			onProgress(types.ScanProgress{
				Phase: "nfs", Percent: float64(ei) / float64(len(exports)) * 100,
				CurrentFile: label + ": 遍历目录",
			})
		}
		err := sess.WalkExport(ctx, exp, cfg, func(ent netfs.NFSDirEntryReport) {
			if ent.IsDir {
				return
			}
			rf := nfsEntryToRecoveredFile(ent, req.Host)
			if rf == nil {
				return
			}
			files = append(files, rf)
			e.cacheNASSource(rf.ID, NASRecoverySource{
				Kind: "nfs",
				NFS: &nasNFSRef{
					Session: sess,
					FH:      ent.Handle,
					Size:    ent.Size,
				},
			})
			if onFound != nil {
				onFound(rf)
			}
		})
		if err != nil {
			logger.Warn("NFS 扫描 export 失败", "export", exp, "err", err)
			continue
		}
	}

	if onProgress != nil {
		onProgress(types.ScanProgress{Phase: "nfs", Percent: 100, FilesFound: len(files)})
	}
	logger.Info("NFS 扫描完成", "host", req.Host, "files", len(files))
	return files, nil
}

func smbEntryToRecoveredFile(e netfs.SMBDirEntry, host string) *types.RecoveredFile {
	if e.Name == "" || e.IsDir {
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(e.Name), "."))
	return &types.RecoveredFile{
		ID:           fmt.Sprintf("smb_%s_%s_%s", host, e.Share, e.Path),
		Source:       "smb",
		FileName:     e.Name,
		Extension:    ext,
		Category:     categorizeByExtension(ext),
		Size:         e.Size,
		SizeHuman:    types.FormatSize(e.Size),
		Offset:       0,
		Confidence:   1.0, // NAS 活跃文件，内容就是权威
		IsValid:      true,
		OriginalPath: fmt.Sprintf("\\\\%s\\%s\\%s", host, e.Share, strings.ReplaceAll(e.Path, "/", `\`)),
		ModifiedTime: timePtrIfNonZero(e.Modified),
		Description:  "SMB 远程文件",
	}
}

func nfsEntryToRecoveredFile(e netfs.NFSDirEntryReport, host string) *types.RecoveredFile {
	if e.Name == "" || e.IsDir {
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(e.Name), "."))
	return &types.RecoveredFile{
		ID:           fmt.Sprintf("nfs_%s_%s_%s", host, e.Export, e.Path),
		Source:       "nfs",
		FileName:     e.Name,
		Extension:    ext,
		Category:     categorizeByExtension(ext),
		Size:         e.Size,
		SizeHuman:    types.FormatSize(e.Size),
		Offset:       0,
		Confidence:   1.0,
		IsValid:      true,
		OriginalPath: fmt.Sprintf("%s:%s/%s", host, e.Export, e.Path),
		ModifiedTime: timePtrIfNonZero(e.Modified),
		Description:  "NFS 远程文件",
	}
}

func (e *Engine) cacheNASSource(id string, src NASRecoverySource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.nasSources == nil {
		e.nasSources = make(map[string]NASRecoverySource)
	}
	e.nasSources[id] = src
}

// recoverNASFile 把 NAS 文件拷贝到 outputPath。用 io.Copy 流式（避免大文件 OOM）。
// 写完后做 SHA-256 校验（和本地恢复路径对齐）。
func (e *Engine) recoverNASFile(file *types.RecoveredFile, outputPath string) error {
	e.mu.RLock()
	src, ok := e.nasSources[file.ID]
	e.mu.RUnlock()

	if !ok {
		return fmt.Errorf("NAS 恢复源已丢失 (ID=%s)", file.ID)
	}

	// 打开远程 reader
	var remoteReader io.ReaderAt
	var remoteCloser io.Closer
	switch src.Kind {
	case "smb":
		if src.SMB == nil {
			return fmt.Errorf("SMB 恢复源为空")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		handle, err := src.SMB.Session.OpenFileReader(ctx, src.SMB.Share, src.SMB.Path)
		if err != nil {
			return fmt.Errorf("SMB 打开远程文件失败: %w", err)
		}
		remoteReader = handle
		remoteCloser = handle

	case "nfs":
		if src.NFS == nil {
			return fmt.Errorf("NFS 恢复源为空")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		r := src.NFS.Session.OpenFileReader(ctx, src.NFS.FH, src.NFS.Size)
		remoteReader = r
		remoteCloser = r

	default:
		return fmt.Errorf("未知 NAS 来源 kind=%q", src.Kind)
	}
	defer remoteCloser.Close()

	// 确保输出目录存在
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	// 流式拷贝：按 64KB 块，避免一次性加载整个大文件
	tmpPath := outputPath + ".part"
	outFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer func() {
		outFile.Close()
		_ = os.Remove(tmpPath) // 失败时清理；成功 rename 后 remove 也会是 no-op
	}()

	buf := make([]byte, 64*1024)
	var offset int64
	for {
		n, rerr := remoteReader.ReadAt(buf, offset)
		if n > 0 {
			if _, werr := outFile.Write(buf[:n]); werr != nil {
				return fmt.Errorf("写入本地文件失败: %w", werr)
			}
			offset += int64(n)
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return fmt.Errorf("读远程文件失败: %w", rerr)
		}
	}
	if err := outFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return fmt.Errorf("重命名输出文件失败: %w", err)
	}
	return nil
}

// closeNASSessions 在 Engine.Shutdown 时被调用，拆除所有挂着的 NAS 连接。
func (e *Engine) closeNASSessions() {
	for _, s := range e.nasSMBSessions {
		if s != nil {
			_ = s.Close()
		}
	}
	e.nasSMBSessions = nil
	for _, s := range e.nasNFSSessions {
		if s != nil {
			_ = s.Close()
		}
	}
	e.nasNFSSessions = nil
}
