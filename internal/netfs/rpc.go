package netfs

// ============================================================================
// ONC RPC over TCP (RFC 5531) 最小客户端
//
// NFS / Portmap / Mount 都是 ONC RPC 程序，wire protocol 都一样：
//
//   Request:
//     fragment_header(4)     高位 = last-fragment bit，低 31 位 = record length
//     XID(4)                 transaction id
//     msg_type(4)            0 = CALL
//     rpc_vers(4)            2
//     program(4)             100000=portmap / 100003=nfs / 100005=mount
//     version(4)
//     procedure(4)
//     auth_cred:             flavor(4) + opaque_body
//     auth_verf:             flavor(4) + opaque_body
//     args...
//
//   Reply:
//     fragment_header(4)
//     XID(4)
//     msg_type(4)            1 = REPLY
//     reply_stat(4)          0 = MSG_ACCEPTED
//     auth_verf              (AUTH_NULL 时 = 0 0)
//     accept_stat(4)         0 = SUCCESS
//     results...
//
// 只实现 AUTH_NULL / AUTH_UNIX。不支持 RPCSEC_GSS（Kerberos 5）——后者需要
// 9 千行 GSS-API + SPNEGO，对家用/办公 NAS 场景不实用（99% NAS 出厂走 NTLM
// 或 AUTH_UNIX）。
// ============================================================================

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RPC 常量
const (
	rpcMsgCall    = 0
	rpcMsgReply   = 1
	rpcVersion    = 2
	authNull      = 0
	authUnix      = 1
	replyAccepted = 0
	acceptSuccess = 0

	// RFC 5531 §9 accept_stat 错误码
	progUnavail  = 1
	progMismatch = 2
	procUnavail  = 3
	garbageArgs  = 4
	systemErr    = 5
)

// 程序号（NFS 相关的）
const (
	progPortmap = 100000
	progMount   = 100005
	progNFS     = 100003
)

// rpcClient 一个 TCP 长连接上的 RPC 客户端，可并发（锁住 wire 一次发一个请求）。
// 用在小并发场景：一次恢复任务里通常就几条 session。
type rpcClient struct {
	conn net.Conn

	// 单写锁：一次只能有一个请求在 fly。做并发优化要求实现 XID 路由 +
	// 响应分发 goroutine，现在用不着——单请求 round-trip 典型 < 10ms。
	mu sync.Mutex

	nextXID uint32 // atomic counter 起点；实际调用时 atomic.Add 拿
	authUID uint32
	authGID uint32
	authGIDs []uint32 // AUX groups
	hostname string   // AUTH_UNIX 里的 "machinename" 字段
}

// newRPCClient 建立 TCP 连接（带超时）并返回客户端。
//
// authUID/authGID：走 AUTH_UNIX 时用的 UID/GID。对于只读恢复场景，一般用
//   0/0（root）或用户端的 geteuid/getegid。public NFS 服务器（no_root_squash
//   off 的情况）会把 root 映射成 nobody——那就以 nobody 权限读。
func newRPCClient(ctx context.Context, host string, port int, authUID, authGID uint32) (*rpcClient, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, fmt.Errorf("RPC dial %s:%d 失败: %w", host, port, err)
	}
	// 设个 deadline 防止 NAS 挂死
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	hn, err := getHostname()
	if err != nil {
		hn = "data-recovery"
	}

	// XID 是 RPC transaction id —— 仅用作匹配 request/response 的对偶号，
	// 没有任何安全意义（可被中间人观察、可被预测）。math/rand 足够；
	// 改用 crypto/rand 反而引入依赖加重启动 IO。
	return &rpcClient{
		conn: conn,
		// #nosec G404 -- RPC XID 是非安全 transaction counter，math/rand 是合适选择
		nextXID:  rand.Uint32(),
		authUID:  authUID,
		authGID:  authGID,
		authGIDs: nil,
		hostname: hn,
	}, nil
}

// Close 关连接。多次调用幂等。
func (c *rpcClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// SetDeadline 刷新整个连接的 read/write 死线。
// 长时间空闲或大文件 read 开始前调一下。
func (c *rpcClient) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return fmt.Errorf("connection closed")
	}
	return c.conn.SetDeadline(t)
}

// call 发一次 RPC 请求，返回应答里的 result 字节（已剥掉 RPC header 和 auth_verf）。
//
// 调用方负责把 result 用 xdrReader 解成结构体。
//
// 错误分层：
//   net error / EOF       → 网络层故障，返回 err
//   reply_stat != accepted → auth 或协议版本错误
//   accept_stat != success → 程序没找到 / 版本不匹配 / 参数畸形
//   以上三类都是 err；只有 accept_stat == SUCCESS 才返回 (result, nil)
func (c *rpcClient) call(program, version, procedure uint32, args []byte, useAuthUnix bool) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	xid := atomic.AddUint32(&c.nextXID, 1)

	// 构造 RPC request body（不含 fragment header）
	var w xdrWriter
	w.writeUint32(xid)
	w.writeUint32(rpcMsgCall)
	w.writeUint32(rpcVersion)
	w.writeUint32(program)
	w.writeUint32(version)
	w.writeUint32(procedure)

	// auth_cred
	if useAuthUnix {
		var cred xdrWriter
		cred.writeUint32(uint32(time.Now().Unix())) // stamp
		cred.writeString(c.hostname)
		cred.writeUint32(c.authUID)
		cred.writeUint32(c.authGID)
		cred.writeUint32(uint32(len(c.authGIDs)))
		for _, g := range c.authGIDs {
			cred.writeUint32(g)
		}
		w.writeUint32(authUnix)
		w.writeOpaque(cred.Bytes())
	} else {
		w.writeUint32(authNull)
		w.writeUint32(0) // opaque len = 0
	}

	// auth_verf = AUTH_NULL（即使 cred 用 AUTH_UNIX，verf 通常也是 NULL）
	w.writeUint32(authNull)
	w.writeUint32(0)

	// 用户 args
	w.buf = append(w.buf, args...)

	body := w.Bytes()

	// 写 record：fragment header + body，last-fragment bit = 1
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body))|0x80000000)
	if _, err := c.conn.Write(hdr[:]); err != nil {
		return nil, fmt.Errorf("RPC 写 fragment header: %w", err)
	}
	if _, err := c.conn.Write(body); err != nil {
		return nil, fmt.Errorf("RPC 写 body: %w", err)
	}

	// 读 reply：可能多个 fragment（大 READ 响应常见）
	reply, err := readFullRecord(c.conn)
	if err != nil {
		return nil, fmt.Errorf("RPC 读应答: %w", err)
	}

	r := newXDRReader(reply)
	rxid, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if rxid != xid {
		return nil, fmt.Errorf("RPC XID 不匹配: 发 %d 收 %d", xid, rxid)
	}
	msgType, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if msgType != rpcMsgReply {
		return nil, fmt.Errorf("RPC msg_type 非 reply: %d", msgType)
	}
	replyStat, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if replyStat != replyAccepted {
		// msg_denied 分支：auth 失败或 rpc vers 不符
		rejectStat, _ := r.readUint32()
		return nil, fmt.Errorf("RPC msg_denied，reject_stat=%d", rejectStat)
	}
	// auth_verf in accepted reply
	if _, err := r.readUint32(); err != nil { // flavor
		return nil, err
	}
	vb, err := r.readOpaque(512)
	if err != nil {
		return nil, err
	}
	_ = vb

	acceptStat, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	switch acceptStat {
	case acceptSuccess:
		// 剩余字节就是 result
		return reply[r.pos:], nil
	case progMismatch:
		low, _ := r.readUint32()
		high, _ := r.readUint32()
		return nil, fmt.Errorf("RPC prog_mismatch: 服务端支持版本 [%d..%d]", low, high)
	case progUnavail:
		return nil, fmt.Errorf("RPC prog_unavail (program %d 不可用)", program)
	case procUnavail:
		return nil, fmt.Errorf("RPC proc_unavail (program=%d vers=%d proc=%d)", program, version, procedure)
	case garbageArgs:
		return nil, fmt.Errorf("RPC garbage_args（客户端发了畸形参数）")
	case systemErr:
		return nil, fmt.Errorf("RPC system_err（服务端内部错误）")
	default:
		return nil, fmt.Errorf("RPC 未知 accept_stat=%d", acceptStat)
	}
}

// readFullRecord 读完一个 ONC RPC record（可能多 fragment）。
// 每个 fragment 前 4 字节是 header，高位 = last-fragment bit。
func readFullRecord(conn io.Reader) ([]byte, error) {
	var all []byte
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, fmt.Errorf("读 fragment header: %w", err)
		}
		h := binary.BigEndian.Uint32(hdr[:])
		last := (h & 0x80000000) != 0
		size := int(h & 0x7FFFFFFF)
		// 防御：单个 fragment 限制 8MB
		if size > 8*1024*1024 {
			return nil, fmt.Errorf("fragment 超过 8MB 上限: %d", size)
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(conn, chunk); err != nil {
			return nil, fmt.Errorf("读 fragment body: %w", err)
		}
		all = append(all, chunk...)
		if last {
			return all, nil
		}
		// 防御：防 server 无限发 fragment
		if len(all) > 64*1024*1024 {
			return nil, fmt.Errorf("RPC record 超过 64MB 上限")
		}
	}
}

// getHostname 返回本机主机名用于 AUTH_UNIX 的 "machinename" 字段。
// 不要求精确；失败就 fallback 到 "data-recovery"。
func getHostname() (string, error) {
	hn, err := osHostname()
	if err != nil || hn == "" {
		return "data-recovery", nil
	}
	return hn, nil
}
