package netfs

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// ============================================================================
// SMB 递归扫描 + 单文件恢复
//
// 原来 smb.go 只能"按已知路径打开一个文件作为 DiskReader"——等同于"用户已经
// 知道镜像文件叫什么、在哪"。真实 NAS 备份场景是：
//
//   用户说"我的群晖 NAS 坏盘了"、"办公室 Windows Server 共享要换硬件"——
//   他要做的是进去**遍历所有能看到的文件 + 挑选 + 逐个拷出来**。
//
// 这要求：
//   1. ListShares：列出 host 上所有 share（不需要提前知道共享名）
//   2. WalkShare：递归遍历指定 share 的所有文件 → 产出文件清单
//   3. OpenFile：按路径打开单个文件读取（用于 Recover 阶段逐个拷）
//
// 实现策略：直接用 go-smb2 已有的 Share.DirFS() 拿到 fs.FS，用 fs.WalkDir 遍历。
// 这是业界标准做法（和 smbclient 的 recurse 命令等价）。
// ============================================================================

// SMBDirEntry 一条 SMB 共享下的文件/目录发现记录
type SMBDirEntry struct {
	Host     string    // NAS 主机
	Share    string    // 共享名
	Path     string    // share 内相对路径（用 "/" 分隔，即使 SMB wire 用 "\"）
	Name     string    // 基名
	Size     int64     // 文件字节数；目录为 0
	IsDir    bool      // 是否目录
	Modified time.Time // 最后修改时间（SMB 协议给到的就是 UTC）
}

// SMBScanConfig SMB 扫描配置。Host/User/Password 来自 UI 表单。
type SMBScanConfig struct {
	Host     string
	Port     int    // 默认 445
	User     string
	Password string
	Domain   string // 可选
	// Shares 过滤：为空扫全部；否则只扫指定的。避免"扫了 20 个 share，用户只关心 public"的浪费。
	Shares []string
	// MaxDepth 防御性限制目录深度，默认 50。SMB 允许循环符号链接，深度墙兜底。
	MaxDepth int
	// MaxFiles 单次扫描最多返回这么多文件（兜底大共享扫到用户取消前就给出部分结果）。默认 1M。
	MaxFiles int
}

// SMBSession 封装一次 SMB 会话，复用同一个 TCP + auth 做多 share 操作。
type SMBSession struct {
	conn    net.Conn
	session *smb2.Session
	host    string
}

// DialSMB 建立 TCP + SMB2 会话。不 Mount 任何 share —— 后续按需 Mount / Umount。
func DialSMB(ctx context.Context, cfg SMBScanConfig) (*SMBSession, error) {
	port := cfg.Port
	if port == 0 {
		port = 445
	}
	dialer := net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", cfg.Host, port))
	if err != nil {
		return nil, fmt.Errorf("tcp 连接 %s:%d 失败: %w", cfg.Host, port, err)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cfg.User,
			Password: cfg.Password,
			Domain:   cfg.Domain,
		},
	}
	sess, err := d.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMB 认证失败: %w", err)
	}
	return &SMBSession{conn: conn, session: sess, host: cfg.Host}, nil
}

// Close 拆除会话（Logoff + TCP close）。多次调用幂等。
func (s *SMBSession) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.session != nil {
		if err := s.session.Logoff(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.session = nil
	}
	if s.conn != nil {
		if err := s.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.conn = nil
	}
	return firstErr
}

// ListShares 列出当前会话能看到的所有 share（包含管理类 IPC$、ADMIN$ 等，
// 本函数会过滤掉以 $ 结尾的管理 share —— 它们对普通用户恢复无价值且常常权限受限）。
//
// 对应协议：DCE-RPC over SMB、srvsvc NetShareEnum。go-smb2 封好了。
func (s *SMBSession) ListShares() ([]string, error) {
	all, err := s.session.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("列出 share 失败: %w", err)
	}
	out := make([]string, 0, len(all))
	for _, name := range all {
		if strings.HasSuffix(name, "$") {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// WalkShare 递归遍历指定 share 的所有文件/目录，通过 onEntry 回调推送。
//
// 行为：
//   - 深度限制：cfg.MaxDepth（默认 50），防止符号链接循环
//   - 数量限制：cfg.MaxFiles（默认 1_000_000），防止"几亿文件的企业文件服务器"爆内存
//   - ctx 取消：fs.WalkDir 本身不接 ctx，我们在 onEntry 里 double-check
//   - 错误容忍：遇到某个子目录读权限不足时记录 log 继续扫其余，不整体失败
func (s *SMBSession) WalkShare(
	ctx context.Context,
	shareName string,
	cfg SMBScanConfig,
	onEntry func(SMBDirEntry),
) error {
	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 50
	}
	maxFiles := cfg.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 1_000_000
	}

	share, err := s.session.Mount(shareName)
	if err != nil {
		return fmt.Errorf("挂载 share %q 失败: %w", shareName, err)
	}
	defer share.Umount()
	share = share.WithContext(ctx) // 让 ctx 能打断读

	root := share.DirFS(".")
	var (
		fileCount int
		lastErr   error
	)

	walkErr := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, werr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if werr != nil {
			// 目录读失败：记一下但继续（典型原因：ACL 拒绝）
			lastErr = werr
			return nil
		}
		// 深度墙
		if strings.Count(p, "/") > maxDepth {
			return fs.SkipDir
		}
		if p == "." {
			return nil
		}

		info, ierr := d.Info()
		if ierr != nil {
			return nil // skip entry
		}
		entry := SMBDirEntry{
			Host:     s.host,
			Share:    shareName,
			Path:     p,
			Name:     path.Base(p),
			IsDir:    d.IsDir(),
			Size:     info.Size(),
			Modified: info.ModTime(),
		}
		if !entry.IsDir {
			fileCount++
			if fileCount > maxFiles {
				return fmt.Errorf("SMB 扫描文件数超限 (%d)，已停止", maxFiles)
			}
		}
		if onEntry != nil {
			onEntry(entry)
		}
		return nil
	})

	if walkErr != nil && ctx.Err() == nil {
		return walkErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_ = lastErr // 有权限失败也不算整体失败；上层能从 files 数量判断
	return nil
}

// OpenFileReader 打开 share 里指定文件作为 io.ReaderAt + io.Closer，供 Recover
// 阶段拷贝到本地。返回的 reader 已经绑定好 share，Close 会同时拆 share。
func (s *SMBSession) OpenFileReader(
	ctx context.Context,
	shareName, filePath string,
) (*smbFileHandle, error) {
	share, err := s.session.Mount(shareName)
	if err != nil {
		return nil, fmt.Errorf("挂载 share %q 失败: %w", shareName, err)
	}
	share = share.WithContext(ctx)
	smbPath := strings.ReplaceAll(filePath, "/", `\`)
	f, err := share.OpenFile(smbPath, 0, 0)
	if err != nil {
		share.Umount()
		return nil, fmt.Errorf("打开 %q 失败: %w", smbPath, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		share.Umount()
		return nil, err
	}
	return &smbFileHandle{file: f, share: share, size: fi.Size()}, nil
}

// smbFileHandle 一个单文件句柄，包含用完必须释放的 share。
type smbFileHandle struct {
	file  *smb2.File
	share *smb2.Share
	size  int64
}

func (h *smbFileHandle) ReadAt(p []byte, off int64) (int, error) {
	n, err := h.file.ReadAt(p, off)
	if err == io.EOF && n > 0 {
		return n, nil
	}
	return n, err
}
func (h *smbFileHandle) Size() int64 { return h.size }
func (h *smbFileHandle) Close() error {
	var first error
	if h.file != nil {
		if err := h.file.Close(); err != nil && first == nil {
			first = err
		}
	}
	if h.share != nil {
		if err := h.share.Umount(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
