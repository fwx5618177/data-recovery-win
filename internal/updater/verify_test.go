package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"
)

// Round-trip: 用 Go 标准库签 → 我们验
func TestVerifySHA256SUMSSignature_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	content := []byte("abc123 DataRecovery-windows-amd64.exe\ndef456 DataRecovery-linux-amd64.tar.gz\n")
	sig := ed25519.Sign(priv, content)

	// 两种公钥格式都验过
	if err := VerifySHA256SUMSSignature(content, sig, pub); err != nil {
		t.Errorf("raw pubkey verify: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub})
	if err := VerifySHA256SUMSSignature(content, sig, pubPEM); err != nil {
		t.Errorf("PEM pubkey verify: %v", err)
	}
}

// 篡改内容 → 签名失败
func TestVerifySHA256SUMSSignature_TamperedContent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	content := []byte("original")
	sig := ed25519.Sign(priv, content)

	tampered := []byte("tampered")
	if err := VerifySHA256SUMSSignature(tampered, sig, pub); err == nil {
		t.Error("篡改后应验签失败")
	}
}

// 错公钥 → 验证失败
func TestVerifySHA256SUMSSignature_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	content := []byte("msg")
	sig := ed25519.Sign(priv, content)

	// 另一个密钥的公钥
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifySHA256SUMSSignature(content, sig, otherPub); err == nil {
		t.Error("错公钥应验签失败")
	}
}

// IsVersionNewer: rollback 防护单测
func TestIsVersionNewer_RollbackProtection(t *testing.T) {
	cases := []struct {
		current, target string
		want            bool
	}{
		{"v1.0.0", "v1.0.1", true},  // 正常升级
		{"v1.0.0", "v1.1.0", true},  // minor bump
		{"v1.0.0", "v2.0.0", true},  // major bump
		{"v1.5.3", "v1.5.3", false}, // 相等不新
		{"v1.5.3", "v1.5.2", false}, // 显式 downgrade —— 必须拒绝
		{"v2.0.0", "v1.9.9", false}, // 跨 major downgrade
		{"v1.0.0", "garbage", false}, // 非法版本号
		{"garbage", "v1.0.0", false}, // 当前版本号非法
	}
	for _, c := range cases {
		got := IsVersionNewer(c.current, c.target)
		if got != c.want {
			t.Errorf("IsVersionNewer(%q, %q) = %v want %v", c.current, c.target, got, c.want)
		}
	}
}

// AuditLogPath returns 合法路径
func TestAuditLogPath_Available(t *testing.T) {
	p, err := AuditLogPath()
	if err != nil {
		t.Skipf("configDir 不可用（CI sandbox）: %v", err)
	}
	if p == "" {
		t.Error("路径应非空")
	}
}
