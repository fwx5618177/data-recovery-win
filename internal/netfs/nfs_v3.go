package netfs

// ============================================================================
// NFS v3 客户端（RFC 1813 + Mount v3 + Portmap v2）
//
// 作用域（只读路径，够覆盖"NAS 备份"和"坏盘前抢数据"场景）：
//   - Portmap GETPORT     定位 mountd 动态端口（nfsd 固定 2049）
//   - Mount v3 MNT/UMNT   获得 root filehandle
//   - Mount v3 EXPORT     列出所有可挂载路径
//   - NFS v3 LOOKUP       目录+名字 → 子 fh
//   - NFS v3 GETATTR      文件属性
//   - NFS v3 READDIRPLUS  批量列目录（带 fh + attr，减少 RTT）
//   - NFS v3 READ         按 offset 读文件内容
//
// 故意不实现的（等用户明确需要再加，避免 "写了没人用又要维护" 的死代码）：
//   - 写操作（CREATE/WRITE/REMOVE/RENAME）- 本工具永远只读
//   - RPCSEC_GSS（Kerberos）- 家用/办公 NAS 99% 走 AUTH_UNIX
//   - NLM 锁协议 - 读不需要锁
//   - NFS v4 - v3 是 NAS 厂商最通用的版本；v4 的 compound RPC 架构要整体重写
//
// 错误码：NFS3ERR_* 常量直接传递给调用方，由调用方决定映射成"文件不存在"还是
// "权限不足"还是"NAS 下线"。不做语义翻译，因为每个错误对 UI 的展示都可能不同。
// ============================================================================

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// Portmap v2 常量
const (
	portmapVers        = 2
	portmapProcGetPort = 3

	ipprotoTCP = 6
	ipprotoUDP = 17
)

// Mount v3 procedures
const (
	mountVers3      = 3
	mountProcNull   = 0
	mountProcMnt    = 1
	mountProcUmnt   = 3
	mountProcExport = 5
)

// NFS v3 procedures
const (
	nfsVers3           = 3
	nfsProcNull        = 0
	nfsProcGetattr     = 1
	nfsProcAccess      = 4
	nfsProcReadlink    = 5
	nfsProcLookup      = 3
	nfsProcRead        = 6
	nfsProcReaddirplus = 17
	nfsProcFsstat      = 18
	nfsProcFsinfo      = 19
)

// NFS3 ACCESS bit mask（RFC 1813 §3.3.4）
const (
	ACCESS3_READ    uint32 = 0x0001
	ACCESS3_LOOKUP  uint32 = 0x0002
	ACCESS3_MODIFY  uint32 = 0x0004
	ACCESS3_EXTEND  uint32 = 0x0008
	ACCESS3_DELETE  uint32 = 0x0010
	ACCESS3_EXECUTE uint32 = 0x0020
)

// NFS3 错误码（RFC 1813）
const (
	NFS3_OK             uint32 = 0
	NFS3ERR_PERM        uint32 = 1
	NFS3ERR_NOENT       uint32 = 2
	NFS3ERR_IO          uint32 = 5
	NFS3ERR_ACCES       uint32 = 13
	NFS3ERR_EXIST       uint32 = 17
	NFS3ERR_NOTDIR      uint32 = 20
	NFS3ERR_ISDIR       uint32 = 21
	NFS3ERR_INVAL       uint32 = 22
	NFS3ERR_NAMETOOLONG uint32 = 63
	NFS3ERR_STALE       uint32 = 70
	NFS3ERR_SERVERFAULT uint32 = 10006
)

// ============================================================================
// Portmap: 查动态端口
// ============================================================================

// portmapGetPort 询问 portmapper（总是在 :111）某程序/版本使用的端口号。
// 返回 0 表示该程序未注册。
func portmapGetPort(ctx context.Context, host string, prog, vers uint32) (uint32, error) {
	c, err := newRPCClient(ctx, host, 111, 0, 0)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	var args xdrWriter
	args.writeUint32(prog)
	args.writeUint32(vers)
	args.writeUint32(ipprotoTCP)
	args.writeUint32(0) // port 字段，请求时无意义

	result, err := c.call(progPortmap, portmapVers, portmapProcGetPort, args.Bytes(), false)
	if err != nil {
		return 0, err
	}
	port, err := newXDRReader(result).readUint32()
	if err != nil {
		return 0, err
	}
	return port, nil
}

// ============================================================================
// Mount v3: 获取 root filehandle
// ============================================================================

// MountExport 一条 export list 条目：路径 + 允许挂载的 client 列表
type MountExport struct {
	Path   string   // 服务端暴露的 export 点，如 "/volume1/photos"
	Groups []string // 允许挂载的 netgroup / IP / 域，空=全允许
}

// MountClient 封装一次 mountd 会话。
type MountClient struct {
	rpc  *rpcClient
	host string
	port uint32
}

// DialMount 连上 mountd。port 为 0 时先查 portmap 动态解析。
func DialMount(ctx context.Context, host string, port uint32, uid, gid uint32) (*MountClient, error) {
	if port == 0 {
		p, err := portmapGetPort(ctx, host, progMount, mountVers3)
		if err != nil {
			return nil, fmt.Errorf("查 mountd 端口失败: %w", err)
		}
		if p == 0 {
			return nil, fmt.Errorf("服务端未注册 mountd v3")
		}
		port = p
	}
	rpc, err := newRPCClient(ctx, host, int(port), uid, gid)
	if err != nil {
		return nil, err
	}
	return &MountClient{rpc: rpc, host: host, port: port}, nil
}

func (m *MountClient) Close() error {
	if m == nil || m.rpc == nil {
		return nil
	}
	return m.rpc.Close()
}

// Export 返回服务端所有 export 点。部分 NAS（如群晖 DSM < 7）会拒绝，非致命。
func (m *MountClient) Export(ctx context.Context) ([]MountExport, error) {
	result, err := m.rpc.call(progMount, mountVers3, mountProcExport, nil, true)
	if err != nil {
		return nil, err
	}
	r := newXDRReader(result)
	var out []MountExport
	for {
		hasMore, err := r.readBool()
		if err != nil {
			return nil, err
		}
		if !hasMore {
			break
		}
		dir, err := r.readString(4096)
		if err != nil {
			return nil, err
		}
		var groups []string
		for {
			grpMore, err := r.readBool()
			if err != nil {
				return nil, err
			}
			if !grpMore {
				break
			}
			g, err := r.readString(4096)
			if err != nil {
				return nil, err
			}
			groups = append(groups, g)
		}
		out = append(out, MountExport{Path: dir, Groups: groups})
	}
	return out, nil
}

// Mnt 挂载一个 export 路径，拿到 root filehandle。
// 成功必须配对调用 Umnt 释放（大多数 NAS 会泄漏 mount 状态到日志）。
func (m *MountClient) Mnt(ctx context.Context, path string) ([]byte, error) {
	var args xdrWriter
	args.writeString(path)
	result, err := m.rpc.call(progMount, mountVers3, mountProcMnt, args.Bytes(), true)
	if err != nil {
		return nil, err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, fmt.Errorf("MNT 失败，status=%d", status)
	}
	fh, err := r.readOpaque(64) // NFS v3 fhandle ≤ 64 字节
	if err != nil {
		return nil, err
	}
	// 跳过 auth_flavors 列表（不关心）
	return fh, nil
}

// Umnt 卸载之前 Mnt 过的 export。参数必须和 Mnt 一致。
func (m *MountClient) Umnt(ctx context.Context, path string) error {
	var args xdrWriter
	args.writeString(path)
	_, err := m.rpc.call(progMount, mountVers3, mountProcUmnt, args.Bytes(), true)
	return err
}

// ============================================================================
// NFS v3 核心操作
// ============================================================================

// NFSClient 一个和 nfsd 的长连接。
type NFSClient struct {
	rpc  *rpcClient
	host string
}

// DialNFS 连上 nfsd（端口默认 2049；某些 NAS 要先 portmap 查）。
func DialNFS(ctx context.Context, host string, port uint32, uid, gid uint32) (*NFSClient, error) {
	if port == 0 {
		port = 2049 // 标准端口，先直接尝试
	}
	rpc, err := newRPCClient(ctx, host, int(port), uid, gid)
	if err != nil && port == 2049 {
		// fallback：portmap 查
		p, perr := portmapGetPort(ctx, host, progNFS, nfsVers3)
		if perr == nil && p != 0 && p != 2049 {
			rpc, err = newRPCClient(ctx, host, int(p), uid, gid)
		}
	}
	if err != nil {
		return nil, err
	}
	return &NFSClient{rpc: rpc, host: host}, nil
}

func (c *NFSClient) Close() error {
	if c == nil || c.rpc == nil {
		return nil
	}
	return c.rpc.Close()
}

// NFSAttr 文件属性（fattr3 的子集，只保留恢复工具用得上的）
type NFSAttr struct {
	Type   uint32 // 1=REG, 2=DIR, 3=BLK, 4=CHR, 5=LNK, 6=SOCK, 7=FIFO
	Mode   uint32
	Nlink  uint32
	UID    uint32
	GID    uint32
	Size   uint64
	Used   uint64
	FSID   uint64
	FileID uint64
	Atime  time.Time
	Mtime  time.Time
	Ctime  time.Time
}

func (a NFSAttr) IsDir() bool     { return a.Type == 2 }
func (a NFSAttr) IsRegular() bool { return a.Type == 1 }

// NFSDirEntry 一条 READDIRPLUS 返回的条目
type NFSDirEntry struct {
	FileID uint64
	Name   string
	Cookie uint64
	Handle []byte   // 可能为 nil（POST_OP_FH3 可缺省）
	Attr   *NFSAttr // 可能为 nil
}

// Getattr 查文件属性
func (c *NFSClient) Getattr(ctx context.Context, fh []byte) (*NFSAttr, error) {
	var args xdrWriter
	args.writeOpaque(fh)
	result, err := c.rpc.call(progNFS, nfsVers3, nfsProcGetattr, args.Bytes(), true)
	if err != nil {
		return nil, err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if status != NFS3_OK {
		return nil, fmt.Errorf("GETATTR 失败, status=%d", status)
	}
	return readFattr3(r)
}

// Lookup 查目录下的子项，返回子 fh（失败时 status 为非 0）。
func (c *NFSClient) Lookup(ctx context.Context, dirFH []byte, name string) ([]byte, *NFSAttr, error) {
	var args xdrWriter
	args.writeOpaque(dirFH)
	args.writeString(name)
	result, err := c.rpc.call(progNFS, nfsVers3, nfsProcLookup, args.Bytes(), true)
	if err != nil {
		return nil, nil, err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return nil, nil, err
	}
	if status != NFS3_OK {
		return nil, nil, fmt.Errorf("LOOKUP %q 失败, status=%d", name, status)
	}
	fh, err := r.readOpaque(64)
	if err != nil {
		return nil, nil, err
	}
	// post_op_attr (子)
	attr, err := readPostOpAttr(r)
	if err != nil {
		return fh, nil, err
	}
	// post_op_attr (父) 丢弃
	_, _ = readPostOpAttr(r)
	return fh, attr, nil
}

// Read 读文件的一个范围。返回实际读到字节（可能小于 count）+ eof 标志。
//
// count 上限建议 32KB（多数 NFS 实现的 max rsize）；调用方要循环读大文件。
func (c *NFSClient) Read(ctx context.Context, fh []byte, offset uint64, count uint32) ([]byte, bool, error) {
	if count > 1024*1024 {
		return nil, false, fmt.Errorf("单次 READ 上限 1MB (got %d)", count)
	}
	var args xdrWriter
	args.writeOpaque(fh)
	args.writeUint64(offset)
	args.writeUint32(count)
	result, err := c.rpc.call(progNFS, nfsVers3, nfsProcRead, args.Bytes(), true)
	if err != nil {
		return nil, false, err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return nil, false, err
	}
	// post_op_attr 无论成功失败都有
	_, _ = readPostOpAttr(r)
	if status != NFS3_OK {
		return nil, false, fmt.Errorf("READ 失败, status=%d", status)
	}
	_, err = r.readUint32() // count_returned (冗余，data 的长度前缀更权威)
	if err != nil {
		return nil, false, err
	}
	eof, err := r.readBool()
	if err != nil {
		return nil, false, err
	}
	data, err := r.readOpaque(int(count))
	if err != nil {
		return nil, false, err
	}
	return data, eof, nil
}

// Readdirplus 批量列目录。cookie=0 表示从头开始；后续调用用上次返回的最后 cookie。
// 返回 entries + 是否 eof + 新 cookieverf（后续调用必须传回去）。
func (c *NFSClient) Readdirplus(
	ctx context.Context,
	dirFH []byte,
	cookie uint64,
	cookieverf []byte,
	dircount, maxcount uint32,
) ([]NFSDirEntry, bool, []byte, error) {
	var args xdrWriter
	args.writeOpaque(dirFH)
	args.writeUint64(cookie)
	if len(cookieverf) != 8 {
		cookieverf = make([]byte, 8)
	}
	args.buf = append(args.buf, cookieverf...)
	args.writeUint32(dircount)
	args.writeUint32(maxcount)

	result, err := c.rpc.call(progNFS, nfsVers3, nfsProcReaddirplus, args.Bytes(), true)
	if err != nil {
		return nil, false, nil, err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return nil, false, nil, err
	}
	// dir_attributes
	_, _ = readPostOpAttr(r)
	if status != NFS3_OK {
		return nil, false, nil, fmt.Errorf("READDIRPLUS 失败, status=%d", status)
	}
	// cookieverf (8 字节固定)
	if r.remaining() < 8 {
		return nil, false, nil, fmt.Errorf("cookieverf 不足")
	}
	cv := make([]byte, 8)
	copy(cv, r.buf[r.pos:r.pos+8])
	r.pos += 8

	var entries []NFSDirEntry
	for {
		has, err := r.readBool()
		if err != nil {
			return nil, false, nil, err
		}
		if !has {
			break
		}
		fileID, err := r.readUint64()
		if err != nil {
			return nil, false, nil, err
		}
		name, err := r.readString(256)
		if err != nil {
			return nil, false, nil, err
		}
		cook, err := r.readUint64()
		if err != nil {
			return nil, false, nil, err
		}
		attr, err := readPostOpAttr(r)
		if err != nil {
			return nil, false, nil, err
		}
		handle, err := readPostOpFH3(r)
		if err != nil {
			return nil, false, nil, err
		}
		entries = append(entries, NFSDirEntry{
			FileID: fileID,
			Name:   name,
			Cookie: cook,
			Handle: handle,
			Attr:   attr,
		})
	}
	eof, err := r.readBool()
	if err != nil {
		return nil, false, nil, err
	}
	return entries, eof, cv, nil
}

// Access 询问 server 对给定 fh 我们有哪些权限（合并到 access mask 里返回）。
//
// 用法：在 walk 一个子目录前先 ACCESS 查 ACCESS3_LOOKUP，避免 LOOKUP 失败浪费 RTT。
// 返回值是 server 实际允许的位（granted），可能是 want 的子集。
func (c *NFSClient) Access(ctx context.Context, fh []byte, want uint32) (uint32, error) {
	var args xdrWriter
	args.writeOpaque(fh)
	args.writeUint32(want)
	result, err := c.rpc.call(progNFS, nfsVers3, nfsProcAccess, args.Bytes(), true)
	if err != nil {
		return 0, err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return 0, err
	}
	_, _ = readPostOpAttr(r) // 可选 obj_attributes
	if status != NFS3_OK {
		return 0, fmt.Errorf("ACCESS 失败, status=%d", status)
	}
	granted, err := r.readUint32()
	if err != nil {
		return 0, err
	}
	return granted, nil
}

// Readlink 读符号链接的目标路径
//
// 用法：scanner 遇到 NFSAttr.Type==5（symlink）时调，决定要不要跟踪到目标
// （多数情况扫描器不跟符号链接以避免 cycle）。
func (c *NFSClient) Readlink(ctx context.Context, fh []byte) (string, error) {
	var args xdrWriter
	args.writeOpaque(fh)
	result, err := c.rpc.call(progNFS, nfsVers3, nfsProcReadlink, args.Bytes(), true)
	if err != nil {
		return "", err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return "", err
	}
	_, _ = readPostOpAttr(r) // symlink_attributes
	if status != NFS3_OK {
		return "", fmt.Errorf("READLINK 失败, status=%d", status)
	}
	return r.readString(4096)
}

// FSInfo 静态文件系统能力信息（block size 上限、最大文件大小、time 精度等）
//
// 用法：拿来调整 READ 的 chunk size 上限，让大文件传输更高效。
type NFSFSInfo struct {
	RTMax      uint32 // 最大 read 字节数（server 侧 cap）
	RTPref     uint32 // 推荐 read 字节数
	RTMult     uint32 // read 字节数的倍数对齐
	WTMax      uint32 // 最大 write
	WTPref     uint32 //
	WTMult     uint32 //
	DTPref     uint32 // readdir 最大返回字节数
	MaxFileSz  uint64 // 文件最大字节数
	TimeDelta  time.Duration
	Properties uint32
}

// FSInfo 调 NFS3_FSINFO 获取 server 文件系统能力
func (c *NFSClient) FSInfo(ctx context.Context, fh []byte) (*NFSFSInfo, error) {
	var args xdrWriter
	args.writeOpaque(fh)
	result, err := c.rpc.call(progNFS, nfsVers3, nfsProcFsinfo, args.Bytes(), true)
	if err != nil {
		return nil, err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_, _ = readPostOpAttr(r)
	if status != NFS3_OK {
		return nil, fmt.Errorf("FSINFO 失败, status=%d", status)
	}
	info := &NFSFSInfo{}
	if info.RTMax, err = r.readUint32(); err != nil {
		return nil, err
	}
	if info.RTPref, err = r.readUint32(); err != nil {
		return nil, err
	}
	if info.RTMult, err = r.readUint32(); err != nil {
		return nil, err
	}
	if info.WTMax, err = r.readUint32(); err != nil {
		return nil, err
	}
	if info.WTPref, err = r.readUint32(); err != nil {
		return nil, err
	}
	if info.WTMult, err = r.readUint32(); err != nil {
		return nil, err
	}
	if info.DTPref, err = r.readUint32(); err != nil {
		return nil, err
	}
	if info.MaxFileSz, err = r.readUint64(); err != nil {
		return nil, err
	}
	// time_delta = (sec u32, nsec u32)
	tsec, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	tnsec, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	info.TimeDelta = time.Duration(tsec)*time.Second + time.Duration(tnsec)*time.Nanosecond
	if info.Properties, err = r.readUint32(); err != nil {
		return nil, err
	}
	return info, nil
}

// FSStat 动态文件系统状态（free space、files count）
//
// 用法：用户问"NAS 上还剩多少空间"时调；recovery 任务前可用来估算"扫了一半再
// 看 cache 还能写多少"。
type NFSFSStat struct {
	Tbytes   uint64 // 总字节
	Fbytes   uint64 // 空闲字节
	Abytes   uint64 // 普通用户可用
	Tfiles   uint64
	Ffiles   uint64
	Afiles   uint64
	Invarsec uint32
}

// FSStat 调 NFS3_FSSTAT
func (c *NFSClient) FSStat(ctx context.Context, fh []byte) (*NFSFSStat, error) {
	var args xdrWriter
	args.writeOpaque(fh)
	result, err := c.rpc.call(progNFS, nfsVers3, nfsProcFsstat, args.Bytes(), true)
	if err != nil {
		return nil, err
	}
	r := newXDRReader(result)
	status, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	_, _ = readPostOpAttr(r)
	if status != NFS3_OK {
		return nil, fmt.Errorf("FSSTAT 失败, status=%d", status)
	}
	stat := &NFSFSStat{}
	for _, p := range []*uint64{&stat.Tbytes, &stat.Fbytes, &stat.Abytes, &stat.Tfiles, &stat.Ffiles, &stat.Afiles} {
		v, err := r.readUint64()
		if err != nil {
			return nil, err
		}
		*p = v
	}
	if stat.Invarsec, err = r.readUint32(); err != nil {
		return nil, err
	}
	return stat, nil
}

// ============================================================================
// XDR 辅助：RFC 1813 里的共用结构
// ============================================================================

// readFattr3 读一个 fattr3 结构（RFC 1813 §2.5）
func readFattr3(r *xdrReader) (*NFSAttr, error) {
	a := &NFSAttr{}
	var err error
	if a.Type, err = r.readUint32(); err != nil {
		return nil, err
	}
	if a.Mode, err = r.readUint32(); err != nil {
		return nil, err
	}
	if a.Nlink, err = r.readUint32(); err != nil {
		return nil, err
	}
	if a.UID, err = r.readUint32(); err != nil {
		return nil, err
	}
	if a.GID, err = r.readUint32(); err != nil {
		return nil, err
	}
	if a.Size, err = r.readUint64(); err != nil {
		return nil, err
	}
	if a.Used, err = r.readUint64(); err != nil {
		return nil, err
	}
	// specdata1 / specdata2（设备文件用，普通文件忽略）
	if err = r.skip(8); err != nil {
		return nil, err
	}
	if a.FSID, err = r.readUint64(); err != nil {
		return nil, err
	}
	if a.FileID, err = r.readUint64(); err != nil {
		return nil, err
	}
	if a.Atime, err = readNFSTime(r); err != nil {
		return nil, err
	}
	if a.Mtime, err = readNFSTime(r); err != nil {
		return nil, err
	}
	if a.Ctime, err = readNFSTime(r); err != nil {
		return nil, err
	}
	return a, nil
}

// readNFSTime 读 nfstime3 = (uint32 seconds, uint32 nseconds)
func readNFSTime(r *xdrReader) (time.Time, error) {
	sec, err := r.readUint32()
	if err != nil {
		return time.Time{}, err
	}
	nsec, err := r.readUint32()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(sec), int64(nsec)).UTC(), nil
}

// readPostOpAttr 读 "可选的 fattr3"（bool + [fattr3 if true]）
func readPostOpAttr(r *xdrReader) (*NFSAttr, error) {
	has, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return readFattr3(r)
}

// readPostOpFH3 读 "可选的 fhandle"（bool + [opaque if true]）
func readPostOpFH3(r *xdrReader) ([]byte, error) {
	has, err := r.readBool()
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return r.readOpaque(64)
}

// 占位以压制 "imported and not used" 警告；binary 在其它辅助文件可能会用到。
var _ = binary.BigEndian
