package netfs

import (
	"encoding/binary"
	"testing"
)

// mDNS 走 UDP 多播很难在 unit test 里真 echo，我们聚焦测 wire 编解码。

func TestBuildMDNSQuery_HeaderAndQName(t *testing.T) {
	q := buildMDNSQuery("_smb._tcp.local.")
	// 最短：12 (header) + 1+4 "_smb" + 1+4 "_tcp" + 1+5 "local" + 1 (terminator) + 4 (QTYPE+QCLASS) = 33
	if len(q) < 33 {
		t.Errorf("query 太短: %d bytes", len(q))
	}
	// 头部 QDCOUNT = 1
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Errorf("QDCOUNT 应为 1")
	}
	// QTYPE = 12 (PTR)
	qtype := binary.BigEndian.Uint16(q[len(q)-4 : len(q)-2])
	if qtype != 12 {
		t.Errorf("QTYPE 应为 12 (PTR)，实际 %d", qtype)
	}
}

func TestDecodeName_Simple(t *testing.T) {
	// "ns.example.com" in wire format
	data := []byte{2, 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, pos, err := decodeName(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if name != "ns.example.com" {
		t.Errorf("got %q", name)
	}
	if pos != len(data) {
		t.Errorf("pos 应在 name 末尾")
	}
}

func TestDecodeName_Pointer(t *testing.T) {
	// 前置一个完整名 "a.b"，之后用指针复用
	data := make([]byte, 0, 32)
	// "a.b" starting at offset 0
	data = append(data, 1, 'a', 1, 'b', 0)
	// 然后在 offset 5 开始：一个指针 0xC0 0x00（指向 offset 0）
	data = append(data, 0xC0, 0x00)

	name, _, err := decodeName(data, 5)
	if err != nil {
		t.Fatal(err)
	}
	if name != "a.b" {
		t.Errorf("指针解码 got %q", name)
	}
}

func TestDecodeName_PointerLoopProtection(t *testing.T) {
	// 构造一个指向自己的指针
	data := []byte{0xC0, 0x00, 0, 0}
	_, _, err := decodeName(data, 0)
	// 循环保护最多 20 跳后报错或返回空
	_ = err // 任何结果都行，主要是不 infinite loop
}

func TestPtrKindOf(t *testing.T) {
	// 真实 mDNS reply 里 PTR target 总是完整形式 "_<svc>._tcp.local"
	cases := map[string]ServiceKind{
		"_smb._tcp.local":        ServiceSMB,
		"_nfs._tcp.local":        ServiceNFS,
		"_afpovertcp._tcp.local": ServiceAFP,
		"_random._tcp.local":     "",
		"instance-name._smb._tcp.local": ServiceSMB, // SRV 实例名包含服务类型
	}
	for in, want := range cases {
		got := ptrKindOf(in)
		if got != want {
			t.Errorf("ptrKindOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultPort(t *testing.T) {
	if defaultPort(ServiceSMB) != 445 {
		t.Errorf("SMB default port")
	}
	if defaultPort(ServiceNFS) != 2049 {
		t.Errorf("NFS default port")
	}
	if defaultPort(ServiceAFP) != 548 {
		t.Errorf("AFP default port")
	}
}
