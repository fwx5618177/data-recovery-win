package netfs

// ============================================================================
// NFS v3 高层 API：对齐 SMB，提供 ListExports / WalkExport / OpenFileReader。
// 内部用 nfs_v3.go 里的原始协议实现。
// ============================================================================

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

// NFSDirEntryReport 一条 NFS 扫描结果（和 SMBDirEntry 对齐）
type NFSDirEntryReport struct {
	Host     string
	Export   string    // 比如 "/volume1/photos"
	Path     string    // export 内的相对路径（"/" 分隔）
	Name     string
	Size     int64
	IsDir    bool
	Modified time.Time
	// Handle NFSv3 file handle。Recover 阶段按它直接 READ，不用再 LOOKUP 一次
	Handle []byte
}

// NFSScanConfig NFS 扫描配置
type NFSScanConfig struct {
	Host     string
	NFSPort  uint32 // 默认 2049；为 0 时尝试 portmap 查
	MountPort uint32 // 默认 0 = portmap 查动态端口
	UID      uint32 // AUTH_UNIX 的 UID；0 = root（许多 NAS 会 squash 成 nobody）
	GID      uint32
	Exports  []string // 过滤：只扫这些 export 路径；为空扫全部
	MaxDepth int      // 默认 50
	MaxFiles int      // 默认 1_000_000
}

// NFSSession 持有 mountd 和 nfsd 两个连接 + 每个已挂载 export 的 root fh。
type NFSSession struct {
	cfg NFSScanConfig

	mnt *MountClient
	nfs *NFSClient

	// key = export path；value = root filehandle
	rootFHs map[string][]byte
}

// DialNFSSession 建立 mount + nfs 两个会话，不挂载任何 export。
func DialNFSSession(ctx context.Context, cfg NFSScanConfig) (*NFSSession, error) {
	mnt, err := DialMount(ctx, cfg.Host, cfg.MountPort, cfg.UID, cfg.GID)
	if err != nil {
		return nil, fmt.Errorf("mount 连接失败: %w", err)
	}
	nfs, err := DialNFS(ctx, cfg.Host, cfg.NFSPort, cfg.UID, cfg.GID)
	if err != nil {
		mnt.Close()
		return nil, fmt.Errorf("nfs 连接失败: %w", err)
	}
	return &NFSSession{
		cfg:     cfg,
		mnt:     mnt,
		nfs:     nfs,
		rootFHs: make(map[string][]byte),
	}, nil
}

// Close 拆除所有已挂载的 export + 关两个 RPC 连接。
func (s *NFSSession) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	// Umnt 每个已挂载的 export
	if s.mnt != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for p := range s.rootFHs {
			if err := s.mnt.Umnt(ctx, p); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := s.mnt.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.mnt = nil
	}
	if s.nfs != nil {
		if err := s.nfs.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.nfs = nil
	}
	return firstErr
}

// ListExports 返回所有可挂载的 export 路径（不挂载，只列出）。
// 注意有些 NAS 配置 EXPORT 拒绝（或 require authenticated），会返回错误；
// 这种情况调用方可以跳过 ListExports，直接 MountExport("/known/path")。
func (s *NFSSession) ListExports(ctx context.Context) ([]string, error) {
	exp, err := s.mnt.Export(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(exp))
	for _, e := range exp {
		out = append(out, e.Path)
	}
	return out, nil
}

// MountExport 挂载一个 export，拿到 root fh 并缓存。多次调用幂等。
func (s *NFSSession) MountExport(ctx context.Context, exportPath string) ([]byte, error) {
	if fh, ok := s.rootFHs[exportPath]; ok {
		return fh, nil
	}
	fh, err := s.mnt.Mnt(ctx, exportPath)
	if err != nil {
		return nil, err
	}
	s.rootFHs[exportPath] = fh
	return fh, nil
}

// WalkExport 递归遍历一个已挂载的 export，推送每个文件/目录到 onEntry。
// 内部用 READDIRPLUS 批量取目录（最大可能的性能，每批一次 RTT + 附带 attr + handle）。
func (s *NFSSession) WalkExport(
	ctx context.Context,
	exportPath string,
	cfg NFSScanConfig,
	onEntry func(NFSDirEntryReport),
) error {
	rootFH, err := s.MountExport(ctx, exportPath)
	if err != nil {
		return err
	}

	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 50
	}
	maxFiles := cfg.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 1_000_000
	}

	// DFS 栈：每个 item = (fh, path_in_export, depth)
	type item struct {
		fh    []byte
		path  string
		depth int
	}
	stack := []item{{fh: rootFH, path: "", depth: 0}}
	fileCount := 0

	for len(stack) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// READDIRPLUS 可能要多轮（每轮返回一批 + eof=false + 新 cookie）
		cookie := uint64(0)
		var cookieverf []byte
		for {
			entries, eof, newCV, err := s.nfs.Readdirplus(ctx, top.fh, cookie, cookieverf,
				8192,   // dircount（仅索引大小的启发）
				65535,  // maxcount（整个应答上限；32-64KB 是业界 sweet spot）
			)
			if err != nil {
				// 权限拒绝 / stale handle：跳过这个子目录而不是整体失败
				break
			}
			cookieverf = newCV
			for _, e := range entries {
				if e.Name == "." || e.Name == ".." {
					if len(entries) > 0 {
						cookie = entries[len(entries)-1].Cookie
					}
					continue
				}
				relPath := e.Name
				if top.path != "" {
					relPath = top.path + "/" + e.Name
				}
				isDir := e.Attr != nil && e.Attr.IsDir()
				report := NFSDirEntryReport{
					Host:   s.cfg.Host,
					Export: exportPath,
					Path:   relPath,
					Name:   e.Name,
					IsDir:  isDir,
					Handle: e.Handle,
				}
				if e.Attr != nil {
					report.Size = int64(e.Attr.Size)
					report.Modified = e.Attr.Mtime
				}
				if !isDir {
					fileCount++
					if fileCount > maxFiles {
						if onEntry != nil {
							onEntry(report)
						}
						return fmt.Errorf("NFS 扫描文件数超限 (%d)，已停止", maxFiles)
					}
				}
				if onEntry != nil {
					onEntry(report)
				}
				if isDir && top.depth+1 <= maxDepth && len(e.Handle) > 0 {
					stack = append(stack, item{
						fh:    e.Handle,
						path:  relPath,
						depth: top.depth + 1,
					})
				}
				cookie = e.Cookie
			}
			if eof {
				break
			}
			if len(entries) == 0 {
				// 防御：server 返回空 batch 但 eof=false 的 bug，避免死循环
				break
			}
		}
	}
	return nil
}

// OpenFileReader 打开一个 NFS 文件作为 ReaderAt。
// 对大文件会循环发 READ（一般 NFS 服务端单次 READ 上限 32KB-1MB）。
func (s *NFSSession) OpenFileReader(ctx context.Context, fh []byte, size int64) *NFSFileReader {
	return &NFSFileReader{
		nfs:  s.nfs,
		fh:   append([]byte(nil), fh...),
		size: size,
		ctx:  ctx,
	}
}

// NFSFileReader 实现 io.ReaderAt + io.Closer 的 NFS 文件视图
type NFSFileReader struct {
	nfs  *NFSClient
	fh   []byte
	size int64
	ctx  context.Context
}

func (r *NFSFileReader) Size() int64  { return r.size }
func (r *NFSFileReader) Close() error { return nil } // fh 没有显式 close 概念

// ReadAt 按 NFS READ 协议拆块读。max rsize 按 64KB（业界 sweet spot）。
func (r *NFSFileReader) ReadAt(p []byte, off int64) (int, error) {
	const chunk = 64 * 1024
	total := 0
	for total < len(p) {
		if r.ctx.Err() != nil {
			return total, r.ctx.Err()
		}
		want := len(p) - total
		if want > chunk {
			want = chunk
		}
		data, eof, err := r.nfs.Read(r.ctx, r.fh, uint64(off)+uint64(total), uint32(want))
		if err != nil {
			return total, err
		}
		n := copy(p[total:], data)
		total += n
		if n == 0 {
			return total, io.ErrUnexpectedEOF
		}
		if eof && total < len(p) {
			return total, io.EOF
		}
	}
	return total, nil
}

// ResolvePath 按路径依次 LOOKUP，拿到某个绝对路径在 export 内的 fh。
// 主要用于 UI "用户给了完整路径，直接开文件" 的路径。
func (s *NFSSession) ResolvePath(ctx context.Context, exportPath, relPath string) ([]byte, *NFSAttr, error) {
	fh, err := s.MountExport(ctx, exportPath)
	if err != nil {
		return nil, nil, err
	}
	if relPath == "" || relPath == "." || relPath == "/" {
		attr, err := s.nfs.Getattr(ctx, fh)
		return fh, attr, err
	}
	parts := strings.Split(strings.Trim(relPath, "/"), "/")
	var attr *NFSAttr
	for _, p := range parts {
		if p == "" {
			continue
		}
		next, a, err := s.nfs.Lookup(ctx, fh, p)
		if err != nil {
			return nil, nil, err
		}
		fh = next
		attr = a
	}
	return fh, attr, nil
}

// 保留 path 引用让未来重构时 IDE 索引不丢
var _ = path.Base
