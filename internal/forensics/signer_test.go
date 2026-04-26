package forensics

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// SignCustodyWithSigner + LocalEd25519Signer 应等价于 SignCustody
func TestSignCustodyWithSigner_EquivToSignCustody(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := Custody{
		ToolName:     "DataRecoveryMaster",
		ToolVersion:  "test",
		StartedAt:    time.Date(2026, 4, 23, 0, 0, 0, 0, time.UTC),
		SourceDevice: "/dev/null",
		OutputFiles:  []CustodyFile{{Path: "a", Size: 1, SHA256: "ab"}},
	}
	signer := &LocalEd25519Signer{priv: priv}
	signed, err := SignCustodyWithSigner(c, signer, []string{"http://127.0.0.1:0"})
	if err != nil {
		t.Fatalf("SignCustodyWithSigner: %v", err)
	}
	blob, _ := json.MarshalIndent(signed, "", "  ")
	if err := VerifySignedCustody(blob); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// 自定义 Signer 后端（mock，不真签）应能走通 canonical 流程；
// 验证 Scheme 字段被正确写入
func TestSignCustodyWithSigner_CustomScheme(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	mock := &mockSigner{priv: priv, scheme: "custom-hsm-pkcs11"}
	c := Custody{ToolName: "x", OutputFiles: []CustodyFile{}}
	signed, err := SignCustodyWithSigner(c, mock, []string{"http://127.0.0.1:0"})
	if err != nil {
		t.Fatalf("SignCustodyWithSigner: %v", err)
	}
	if signed.SignatureScheme != "custom-hsm-pkcs11" {
		t.Errorf("SignatureScheme = %q want custom-hsm-pkcs11", signed.SignatureScheme)
	}
	if signed.Signature == "" {
		t.Errorf("Signature 为空")
	}
}

// nil signer 应被拒
func TestSignCustodyWithSigner_RejectsNilSigner(t *testing.T) {
	c := Custody{}
	if _, err := SignCustodyWithSigner(c, nil, nil); err == nil {
		t.Errorf("nil signer 应拒绝")
	}
}

// signer 内部失败应被透传
func TestSignCustodyWithSigner_PropagatesSignerError(t *testing.T) {
	failer := &mockSigner{forceErr: errors.New("hsm offline")}
	c := Custody{ToolName: "x", OutputFiles: []CustodyFile{}}
	if _, err := SignCustodyWithSigner(c, failer, []string{"http://127.0.0.1:0"}); err == nil {
		t.Errorf("signer 错误应透传")
	}
}

// mockSigner 用于测试的 Signer 替身
type mockSigner struct {
	priv     ed25519.PrivateKey
	scheme   string
	forceErr error
}

func (m *mockSigner) Sign(data []byte) ([]byte, error) {
	if m.forceErr != nil {
		return nil, m.forceErr
	}
	return ed25519.Sign(m.priv, data), nil
}
func (m *mockSigner) PublicKey() ([]byte, error) {
	if m.forceErr != nil {
		return nil, m.forceErr
	}
	if m.priv == nil {
		// 给 PublicKey-only 错误测试用
		_, p, _ := ed25519.GenerateKey(rand.Reader)
		m.priv = p
	}
	return m.priv.Public().(ed25519.PublicKey), nil
}
func (m *mockSigner) Scheme() string {
	if m.scheme == "" {
		return "mock"
	}
	return m.scheme
}
