package forensics

// Signer 抽象 —— B2B 场景可插拔签名后端。
//
// 现实里 B2B 客户有不同的合规要求：
//   - 自签（本机 Ed25519 key pair）—— 快速迭代 / 开源项目 / 个人用 ✅ 默认
//   - 硬件 HSM（Yubikey / AWS CloudHSM / Thales）—— 高安全等级
//   - 云 KMS（AWS KMS / Azure Key Vault / GCP KMS）—— 云原生
//   - 外部 CLI 命令（自定义签名流程 / git-annex-remote 风格）—— 零锁定
//
// 本包定义 Signer 接口；SignCustody 未来可换任一实现。
// 当前代码用默认 LocalEd25519Signer（= 之前的 SignCustody 自签路径）。
// 其他实现（HSM/KMS/CLI）作为可选 build tag 或可选依赖，不强制。

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
)

// Signer 签名后端统一接口。
// Sign 必须是确定性 over input（Ed25519 是）；PublicKey 返回公钥 raw bytes。
type Signer interface {
	Sign(data []byte) ([]byte, error)
	PublicKey() ([]byte, error)
	Scheme() string // "ed25519" / "hsm-pkcs11" / "aws-kms" / "external-cli" ...
}

// LocalEd25519Signer 默认实现 —— 本机 key pair 从 $CONFIG_DIR/keys 读/写。
type LocalEd25519Signer struct {
	priv ed25519.PrivateKey
}

// NewLocalEd25519Signer 首次调用自动生成 key pair
func NewLocalEd25519Signer(keysDir string) (*LocalEd25519Signer, error) {
	_, priv, err := EnsureKeyPair(keysDir)
	if err != nil {
		return nil, err
	}
	return &LocalEd25519Signer{priv: priv}, nil
}

// Sign 用 Ed25519 签 data
func (s *LocalEd25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}

// PublicKey 返回对应公钥 raw bytes（32 bytes）
func (s *LocalEd25519Signer) PublicKey() ([]byte, error) {
	return s.priv.Public().(ed25519.PublicKey), nil
}

// Scheme 签名方案标识
func (s *LocalEd25519Signer) Scheme() string { return "ed25519" }

// ExternalCLISigner 外部命令行签名器 —— 零锁定的通用接口。
//
// 调用约定：指定的命令从 stdin 读要签的数据，stdout 输出签名字节（raw 或 base64，
// 由 Format 字段决定），PublicKeyPath 是提前准备的公钥文件。
//
// 示例（用 openssl 做 Ed25519 签名）：
//   signer := &ExternalCLISigner{
//     Command: []string{"openssl", "pkeyutl", "-sign", "-inkey", "/path/to/priv.pem"},
//     PublicKeyPath: "/path/to/pub.pem",
//     SchemeName: "ed25519",
//     Format: "raw",
//   }
//
// 这让客户可以接任何签名工具（公司内部 PKI / signtool / codesign 等），无需
// 改 Go 代码；也方便切到 HSM（通过 pkcs11-tool）或云 KMS（通过 aws/gcloud CLI）。
type ExternalCLISigner struct {
	Command       []string // 命令 + 参数
	PublicKeyPath string   // 公钥文件路径（raw bytes 或 PEM，由调用方约定）
	SchemeName    string   // "ed25519" / "rsa-pss" / ...
	PubKeyReader  func(path string) ([]byte, error) // 自定义读公钥函数；nil 时按 raw bytes 读
}

// Sign 调外部命令行工具签名
func (s *ExternalCLISigner) Sign(data []byte) ([]byte, error) {
	if len(s.Command) == 0 {
		return nil, fmt.Errorf("外部签名命令未配置")
	}
	cmd := exec.Command(s.Command[0], s.Command[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	go func() {
		defer stdin.Close()
		stdin.Write(data)
	}()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("外部签名命令失败: %w", err)
	}
	return out, nil
}

// PublicKey 读 PublicKeyPath 文件
func (s *ExternalCLISigner) PublicKey() ([]byte, error) {
	if s.PublicKeyPath == "" {
		return nil, fmt.Errorf("公钥路径未配置")
	}
	if s.PubKeyReader != nil {
		return s.PubKeyReader(s.PublicKeyPath)
	}
	// 默认按 raw bytes 读
	return rawReadFile(s.PublicKeyPath)
}

// Scheme
func (s *ExternalCLISigner) Scheme() string {
	if s.SchemeName == "" {
		return "external"
	}
	return s.SchemeName
}

func rawReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// SignCustodyWithSigner 用可插拔 Signer 替代默认 LocalEd25519Signer。
//
// 流程与 SignCustody 一致，区别只在签名后端：
//   canonical manifest → signer.Sign → 填 Signature / SignaturePublicKey / Scheme
//   可选申请 TSA 时间戳
func SignCustodyWithSigner(c Custody, signer Signer, tsaURLs []string) (*SignedCustody, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer 为 nil")
	}
	// 对于本机 Ed25519 signer，复用现有 SignCustody 逻辑（正确性已测）
	if eddsa, ok := signer.(*LocalEd25519Signer); ok {
		return SignCustody(c, eddsa.priv, tsaURLs)
	}
	// 其他 Signer：复刻 canonical 流程
	// （当前仅 placeholder；完整实现需要把 SignCustody 重构为接受 Signer）
	return nil, fmt.Errorf("非 LocalEd25519Signer 暂未完整接入；作为接口预留")
}
