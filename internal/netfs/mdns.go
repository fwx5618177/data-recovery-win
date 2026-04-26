package netfs

// ============================================================================
// mDNS / DNS-SD (RFC 6762 + RFC 6763) NAS 自动发现
//
// 工作方式：
//   1. 往 UDP 多播地址 224.0.0.251:5353（IPv4）/ [ff02::fb]:5353 (IPv6)
//      发一个 DNS query (PTR type) 查 "_smb._tcp.local."（SMB）或
//      "_nfs._tcp.local."（NFS）或 "_afpovertcp._tcp.local."（AFP）
//   2. 监听 listen socket 收到的 DNS reply，每条 reply 是一个服务实例
//   3. 每个服务实例 SRV 记录 → (host, port)，A/AAAA → IP 地址
//
// 为什么自己写而不用第三方库（grandcat/zeroconf / hashicorp/mdns）：
//   - 两者都很大（几千行带 watcher/cache）
//   - 我们的需求非常简单：一次性查 3 种服务 → 解析 reply → 30s 后关闭
//   - 依赖面最小化：一个会处理法律证据的工具，每个外部依赖都是 supply chain 风险
//   - 本文件约 250 行，语义范围透明
//
// 设计限制：
//   - 不实现"持续 watcher"（NAS 上下线实时通知）——UI 里按钮"扫一次"够用
//   - 不做 IPv6（办公室网络绝大多数 NAS 注册的还是 A 记录；加 IPv6 翻倍代码量）
// ============================================================================

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// DiscoveredService 一个被发现的网络服务
type DiscoveredService struct {
	Kind     ServiceKind // 哪类服务
	Host     string      // 主机名（没有 IP 时用）
	IP       net.IP      // 解析到的 IPv4
	Port     uint16
	Instance string      // 服务实例名，如 "Synology File Station"
	TTL      uint32      // 服务公告的 TTL（秒）
}

// ServiceKind 支持发现的服务类型
type ServiceKind string

const (
	ServiceSMB  ServiceKind = "smb"
	ServiceNFS  ServiceKind = "nfs"
	ServiceAFP  ServiceKind = "afp"
)

var serviceToDNSName = map[ServiceKind]string{
	ServiceSMB: "_smb._tcp.local.",
	ServiceNFS: "_nfs._tcp.local.",
	ServiceAFP: "_afpovertcp._tcp.local.",
}

// DiscoverNAS 往本地网络广播 mDNS 查询，收集 SMB / NFS / AFP 服务。
// timeout 是总超时（包含发送 + 等待 reply）；建议 2-5 秒。
//
// 并发：内部同时监听 3 种服务，公平收集。返回数组包含全部 3 种。
func DiscoverNAS(ctx context.Context, timeout time.Duration) ([]DiscoveredService, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 一个 UDP socket 同时处理请求和回复
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("绑定本地 UDP 失败: %w", err)
	}
	defer conn.Close()

	mdnsAddr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

	// 对每种服务发一个 PTR 查询
	for _, name := range serviceToDNSName {
		q := buildMDNSQuery(name)
		if _, err := conn.WriteToUDP(q, mdnsAddr); err != nil {
			// 单种失败不放弃，接着下一种（常见：没权限发多播到非默认接口）
			continue
		}
	}

	// 收集
	discovered := make(map[string]*DiscoveredService) // key = kind|host|port 去重
	buf := make([]byte, 65535)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	for {
		if ctx.Err() != nil {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超过 listen deadline，检查总 ctx
				if ctx.Err() != nil {
					break
				}
				continue
			}
			break
		}
		services := parseMDNSReply(buf[:n], src.IP)
		for _, s := range services {
			key := fmt.Sprintf("%s|%s|%d", s.Kind, s.Host, s.Port)
			if _, ok := discovered[key]; !ok {
				discovered[key] = s
			}
		}
	}

	out := make([]DiscoveredService, 0, len(discovered))
	for _, s := range discovered {
		out = append(out, *s)
	}
	return out, nil
}

// ============================================================================
// mDNS / DNS wire 编解码（RFC 1035 + RFC 6762）
// ============================================================================

// buildMDNSQuery 构造一个 PTR 查询
// DNS header (12 bytes): ID=0, flags=0, QD=1, AN=0, NS=0, AR=0
// QNAME: wire 编码（每段 length-prefixed） + 0x00 terminator
// QTYPE: 12 (PTR) QCLASS: 1 (IN)
func buildMDNSQuery(name string) []byte {
	var buf []byte

	// Header: 12 bytes
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:], 0)       // ID
	binary.BigEndian.PutUint16(hdr[2:], 0x0000)  // flags: standard query
	binary.BigEndian.PutUint16(hdr[4:], 1)       // QDCOUNT
	buf = append(buf, hdr[:]...)

	// QNAME
	for _, part := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if part == "" {
			continue
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // terminator

	// QTYPE + QCLASS
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:], 12) // PTR
	binary.BigEndian.PutUint16(tail[2:], 1)  // IN
	buf = append(buf, tail[:]...)

	return buf
}

// parseMDNSReply 解析 mDNS 响应包，抽取 SRV + A + PTR 记录
// 返回多条 DiscoveredService（一个 packet 可能含多个服务）
func parseMDNSReply(data []byte, srcIP net.IP) []*DiscoveredService {
	if len(data) < 12 {
		return nil
	}
	// header
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])
	nsCount := binary.BigEndian.Uint16(data[8:10])
	arCount := binary.BigEndian.Uint16(data[10:12])

	pos := 12
	// 跳过 question 段
	for i := uint16(0); i < qdCount; i++ {
		_, next, err := decodeName(data, pos)
		if err != nil {
			return nil
		}
		pos = next + 4 // QTYPE + QCLASS
		if pos > len(data) {
			return nil
		}
	}

	// 收集所有 RR —— AN / NS / AR 合并处理（mDNS replies 常把 SRV/A 都放 AR）
	var records []parsedRR
	total := int(anCount) + int(nsCount) + int(arCount)
	for i := 0; i < total; i++ {
		rr, next, err := decodeRR(data, pos)
		if err != nil {
			break
		}
		records = append(records, rr)
		pos = next
	}

	// 组装：PTR 给出服务实例名 → 查 SRV → 查 A
	// 简单处理：对每个 SRV 找对应的 A（按 Name/Target 匹配）
	srvs := map[string]*parsedSRV{}
	addrs := map[string]net.IP{}
	ptrs := map[string]string{} // 服务类型 → instance 名

	for _, rr := range records {
		switch rr.Type {
		case 33: // SRV
			if len(rr.Data) < 6 {
				continue
			}
			port := binary.BigEndian.Uint16(rr.Data[4:6])
			target, _, err := decodeName(rr.Data, 6)
			if err != nil {
				continue
			}
			srvs[rr.Name] = &parsedSRV{Port: port, Target: target, TTL: rr.TTL}
		case 1: // A
			if len(rr.Data) == 4 {
				addrs[rr.Name] = net.IPv4(rr.Data[0], rr.Data[1], rr.Data[2], rr.Data[3])
			}
		case 12: // PTR
			target, _, err := decodeName(rr.Data, 0)
			if err == nil {
				ptrs[rr.Name] = target
			}
		}
	}

	var out []*DiscoveredService
	for ptrName, instanceName := range ptrs {
		kind := ptrKindOf(ptrName)
		if kind == "" {
			continue
		}
		srv := srvs[instanceName]
		if srv == nil {
			// 有些 reply 不带 SRV；只拿到 instance 名，端口按协议默认
			out = append(out, &DiscoveredService{
				Kind:     kind,
				Host:     instanceName,
				Port:     defaultPort(kind),
				Instance: instanceName,
				IP:       srcIP,
			})
			continue
		}
		ip := addrs[srv.Target]
		if ip == nil {
			ip = srcIP
		}
		out = append(out, &DiscoveredService{
			Kind:     kind,
			Host:     srv.Target,
			IP:       ip,
			Port:     srv.Port,
			Instance: instanceName,
			TTL:      srv.TTL,
		})
	}
	return out
}

type parsedRR struct {
	Name string
	Type uint16
	TTL  uint32
	Data []byte
}

type parsedSRV struct {
	Port   uint16
	Target string
	TTL    uint32
}

func ptrKindOf(name string) ServiceKind {
	for k, dns := range serviceToDNSName {
		if strings.Contains(name, strings.TrimSuffix(dns, ".")) {
			return k
		}
	}
	return ""
}

func defaultPort(k ServiceKind) uint16 {
	switch k {
	case ServiceSMB:
		return 445
	case ServiceNFS:
		return 2049
	case ServiceAFP:
		return 548
	}
	return 0
}

// decodeName 按 RFC 1035 §4.1.4 解压缩域名（支持 pointer 压缩）
func decodeName(data []byte, pos int) (string, int, error) {
	var parts []string
	originalPos := pos
	jumped := false
	// 防御：每次最多跳 20 次避免循环压缩
	for jumps := 0; jumps < 20; jumps++ {
		if pos >= len(data) {
			return "", 0, fmt.Errorf("name 截断")
		}
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}
		if length&0xC0 == 0xC0 {
			// pointer（高 2 位 11）
			if pos+1 >= len(data) {
				return "", 0, fmt.Errorf("pointer 截断")
			}
			target := int(binary.BigEndian.Uint16(data[pos:pos+2]) & 0x3FFF)
			if !jumped {
				originalPos = pos + 2
			}
			pos = target
			jumped = true
			continue
		}
		if pos+1+length > len(data) {
			return "", 0, fmt.Errorf("label 截断")
		}
		parts = append(parts, string(data[pos+1:pos+1+length]))
		pos += 1 + length
	}
	if !jumped {
		originalPos = pos
	}
	return strings.Join(parts, "."), originalPos, nil
}

// decodeRR 解析一条 DNS Resource Record
func decodeRR(data []byte, pos int) (parsedRR, int, error) {
	name, next, err := decodeName(data, pos)
	if err != nil {
		return parsedRR{}, 0, err
	}
	if next+10 > len(data) {
		return parsedRR{}, 0, fmt.Errorf("RR header 截断")
	}
	rrType := binary.BigEndian.Uint16(data[next:])
	ttl := binary.BigEndian.Uint32(data[next+4:])
	rdlen := int(binary.BigEndian.Uint16(data[next+8:]))
	rdStart := next + 10
	if rdStart+rdlen > len(data) {
		return parsedRR{}, 0, fmt.Errorf("RDATA 截断")
	}
	return parsedRR{
		Name: name,
		Type: rrType,
		TTL:  ttl,
		Data: data[rdStart : rdStart+rdlen],
	}, rdStart + rdlen, nil
}
