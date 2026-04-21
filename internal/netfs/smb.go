package netfs

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// SMBConfig SMB 连接参数
type SMBConfig struct {
	Host     string // "server.local" 或 "192.168.1.100"
	Port     int    // 默认 445
	User     string
	Password string
	Domain   string // 可选，默认 WORKGROUP
	Share    string // 例 "data"
}

// SMBFileReader 打开远程 SMB 共享里的镜像文件，实现 disk.DiskReader 接口。
//
// 调用：
//
//	r, err := OpenSMB(ctx, SMBConfig{...}, "path/to/image.img")
//	defer r.Close()
//
// 之后可直接喂给 engine.ScanWithReader。
type SMBFileReader struct {
	conn    net.Conn
	session *smb2.Session
	share   *smb2.Share
	file    *smb2.File
	path    string
	size    int64
}

// OpenSMB 打开 SMB 共享里的一个文件做 reader。
// 内部建立 TCP + SMB2 认证 + 挂载 share + 打开文件；Close 时全部拆除。
func OpenSMB(ctx context.Context, cfg SMBConfig, filePath string) (*SMBFileReader, error) {
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
	session, err := d.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMB 认证失败: %w", err)
	}
	share, err := session.Mount(cfg.Share)
	if err != nil {
		session.Logoff()
		conn.Close()
		return nil, fmt.Errorf("挂载 share %q 失败: %w", cfg.Share, err)
	}
	// SMB 路径用 "\" 分隔
	smbPath := strings.ReplaceAll(filePath, "/", `\`)
	f, err := share.OpenFile(smbPath, 0, 0) // read-only
	if err != nil {
		share.Umount()
		session.Logoff()
		conn.Close()
		return nil, fmt.Errorf("打开远程文件 %q 失败: %w", smbPath, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		share.Umount()
		session.Logoff()
		conn.Close()
		return nil, err
	}
	return &SMBFileReader{
		conn:    conn,
		session: session,
		share:   share,
		file:    f,
		path:    fmt.Sprintf("smb://%s/%s/%s", cfg.Host, cfg.Share, smbPath),
		size:    fi.Size(),
	}, nil
}

func (r *SMBFileReader) Open() error  { return nil }
func (r *SMBFileReader) Close() error {
	if r.file != nil {
		r.file.Close()
	}
	if r.share != nil {
		r.share.Umount()
	}
	if r.session != nil {
		r.session.Logoff()
	}
	if r.conn != nil {
		r.conn.Close()
	}
	return nil
}
func (r *SMBFileReader) Size() (int64, error) { return r.size, nil }
func (r *SMBFileReader) SectorSize() int      { return 512 }
func (r *SMBFileReader) DevicePath() string   { return r.path }

// ReadAt smb2.File 支持 io.ReaderAt
func (r *SMBFileReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.file.ReadAt(p, off)
	if err == io.EOF && n > 0 {
		return n, nil
	}
	return n, err
}
