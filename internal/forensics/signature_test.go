package forensics

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

// 核心正向：签名 → 验证 应成功
func TestSignCustody_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	_ = pub

	c := Custody{
		ToolName:     "DataRecoveryMaster",
		ToolVersion:  "test",
		StartedAt:    time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC),
		CompletedAt:  time.Date(2026, 4, 23, 1, 0, 0, 0, time.UTC),
		SourceDevice: "/dev/null",
		OutputFiles: []CustodyFile{
			{Path: "a.txt", Size: 10, SHA256: "deadbeef"},
		},
	}

	// 不跑 TSA（避免测试依赖网络）
	signed, err := SignCustody(c, priv, []string{"http://127.0.0.1:0"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// TSA 响应字段应为空
	if signed.TSAResponseB64 != "" {
		t.Errorf("不可达 TSA 应留空时间戳字段")
	}

	blob, _ := json.MarshalIndent(signed, "", "  ")
	if err := VerifySignedCustody(blob); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// 反向：篡改任何字段应导致验证失败
func TestSignCustody_TamperDetected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := Custody{ToolName: "original", OutputFiles: []CustodyFile{}}
	signed, err := SignCustody(c, priv, []string{"http://127.0.0.1:0"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// 篡改 ToolName
	signed.ToolName = "evil"
	blob, _ := json.MarshalIndent(signed, "", "  ")
	if err := VerifySignedCustody(blob); err == nil {
		t.Error("篡改后应验证失败")
	}
}

// EnsureKeyPair 幂等性：两次调用返回同 key
func TestEnsureKeyPair_Idempotent(t *testing.T) {
	dir := t.TempDir()
	pub1, priv1, err := EnsureKeyPair(dir)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	pub2, priv2, err := EnsureKeyPair(dir)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(pub1) != string(pub2) || string(priv1) != string(priv2) {
		t.Error("两次调用应返回同一 key pair")
	}
}
