package forensics

// B2B 级取证签名链 —— Ed25519 + RFC 3161 时间戳。
//
// 设计背景：现有 ChainOfCustody 给 manifest 计算 sha256，但没有数字签名。
// 没签名意味着"任何人拿到 manifest 都能修改"—— 第三方法务专家没法区分
// "这份 manifest 是工具生成的" 和 "某个嫌疑人自己编的"。
//
// ETSI / RFC 4998 / eIDAS 要求的合规证据链：
//   1. 证据内容哈希 (已有 —— ManifestSHA256)
//   2. 数字签名 (本文件新增 —— Ed25519)
//   3. 可信时间戳 (本文件新增 —— RFC 3161 TSA token)
//
// 三者组合 → 法务可以证明：
//   "这份证据 X 在时间 T 之前已经存在，由持有私钥 K 的实体（我司）生成"
//
// 私钥管理策略：
//   - 软件首次启动在 $CONFIG_DIR/keys/ 生成 ed25519 key pair（仅本机用）
//   - 公钥随取证报告导出 → 第三方可独立验证 manifest 未被篡改
//   - 商用场景应改用 HSM 或云 KMS 签名服务（此实现是自签示范；生产要换）
//
// 时间戳策略：
//   - 优先用 freetsa.org（社区免费 TSA，证书由 CAcert / ISRG 背书）
//   - 失败回退到 digicert（商用，高可用）
//   - 失败则只保存签名（仍有法律弱效力）
//
// 为什么不内置 TSA 响应校验：
//   RFC 3161 TST 是 CMS 签名结构，校验需要完整 X.509 链路 + TSA 根证书库。
//   我们保存原始 TSR+TSP 二进制 → 用户用标准工具校验（openssl ts -verify / 专业取证软件）。
//   这降低我们代码攻击面 + 不需要维护根证书库。

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DefaultTSAURLs 公共 RFC 3161 TSA 服务（按可用性排序）
var DefaultTSAURLs = []string{
	"https://freetsa.org/tsr",          // 免费，CAcert 背书
	"http://timestamp.digicert.com",    // 商用，高可用（Authenticode 代码签名同 TSA）
	"http://timestamp.sectigo.com",     // 商用替代
}

// SignedCustody 扩展 Custody，加签名 + 时间戳字段
type SignedCustody struct {
	Custody                       // 嵌入原结构
	SignaturePublicKey string    `json:"signaturePublicKey,omitempty"` // ed25519 公钥 base64
	SignatureScheme    string    `json:"signatureScheme,omitempty"`    // "ed25519"
	Signature          string    `json:"signature,omitempty"`          // base64 ed25519 signature over manifest
	TSAURL             string    `json:"tsaUrl,omitempty"`             // 用的 TSA 服务
	TSAResponseB64     string    `json:"tsaResponseB64,omitempty"`     // base64 TimeStampResp ASN.1 DER
	TSATimestamp       time.Time `json:"tsaTimestamp,omitempty"`       // 从 TST 提出的时间（方便人类读）
}

// ----------------------------------------------------------------------
// 密钥管理
// ----------------------------------------------------------------------

// KeyPaths 返回本机 key pair 的保存位置。keysDir 为空时用 $CONFIG_DIR/keys
func KeyPaths(keysDir string) (privPath, pubPath string, err error) {
	if keysDir == "" {
		configDir, e := os.UserConfigDir()
		if e != nil {
			return "", "", fmt.Errorf("无法定位用户配置目录: %w", e)
		}
		keysDir = filepath.Join(configDir, "DataRecoveryMaster", "keys")
	}
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return "", "", fmt.Errorf("创建 keys 目录失败 %s: %w", keysDir, err)
	}
	return filepath.Join(keysDir, "forensics_ed25519.priv"),
		filepath.Join(keysDir, "forensics_ed25519.pub"), nil
}

// EnsureKeyPair 首次调用生成 key pair，之后读出来。返回 (pub, priv, error)。
// 生产环境应换成 HSM / KMS；此实现仅供本机自签证据链。
func EnsureKeyPair(keysDir string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privPath, pubPath, err := KeyPaths(keysDir)
	if err != nil {
		return nil, nil, err
	}
	// 已存在 → 直接读
	if pkBytes, err := os.ReadFile(privPath); err == nil {
		block, _ := pem.Decode(pkBytes)
		if block == nil {
			return nil, nil, fmt.Errorf("私钥 PEM 格式损坏: %s", privPath)
		}
		priv := ed25519.PrivateKey(block.Bytes)
		if len(priv) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("私钥长度不对: got %d want %d", len(priv), ed25519.PrivateKeySize)
		}
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv, nil
	}

	// 生成新的
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 ed25519 key pair: %w", err)
	}
	privPem := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: priv})
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pub})
	if err := os.WriteFile(privPath, privPem, 0o600); err != nil {
		return nil, nil, fmt.Errorf("写入私钥失败: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPem, 0o644); err != nil {
		return nil, nil, fmt.Errorf("写入公钥失败: %w", err)
	}
	return pub, priv, nil
}

// ----------------------------------------------------------------------
// Manifest 签名
// ----------------------------------------------------------------------

// SignCustody 在已填 hash chain 的 Custody 基础上签名 + 申请时间戳。
//
// 这是 LocalEd25519Signer 的 wrapper，向后兼容老调用点。
// 新代码建议直接用 SignCustodyWithSigner 传任意 Signer（HSM / KMS / external CLI）。
//
// privKey 为 nil 时从 $CONFIG_DIR/keys 读（或首次生成）。
// tsaURLs 为 nil 时用 DefaultTSAURLs 依次尝试；全部失败 TST 字段留空（签名仍完成）。
func SignCustody(c Custody, privKey ed25519.PrivateKey, tsaURLs []string) (*SignedCustody, error) {
	if privKey == nil {
		_, pk, err := EnsureKeyPair("")
		if err != nil {
			return nil, err
		}
		privKey = pk
	}
	signer := &LocalEd25519Signer{priv: privKey}
	return signCustodyCanonical(c, signer, tsaURLs)
}

// signCustodyCanonical 是 SignCustody 和 SignCustodyWithSigner 共用的核心实现。
//
// 所有签名后端走同一 canonical 序列化路径，确保 verify 端不论后端都能用
// "重 marshal → 比对 signature" 的统一算法。
//
// 步骤：
//  1. base custody（清空 hash + signature 相关字段）→ MarshalIndent → sha256 → ManifestSHA256
//  2. 装 SignedCustody.SignaturePublicKey + SignatureScheme（来自 signer）
//  3. 再次 MarshalIndent（含 ManifestSHA256 + pub + scheme，但 Signature / TSA 仍空）→ signBytes
//  4. signer.Sign(signBytes) → Signature
//  5. 可选 TSA timestamp
func signCustodyCanonical(c Custody, signer Signer, tsaURLs []string) (*SignedCustody, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer 为 nil")
	}
	pub, err := signer.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("读公钥: %w", err)
	}

	// 清空签名相关字段后做 manifest hash
	base := c
	base.ManifestSHA256 = ""
	manifestBytes, err := json.MarshalIndent(base, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	sum := sha256.Sum256(manifestBytes)
	c.ManifestSHA256 = hex.EncodeToString(sum[:])

	signed := SignedCustody{Custody: c}
	signed.SignaturePublicKey = base64.StdEncoding.EncodeToString(pub)
	signed.SignatureScheme = signer.Scheme()
	signBytes, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal for sign: %w", err)
	}
	sig, err := signer.Sign(signBytes)
	if err != nil {
		return nil, fmt.Errorf("signer.Sign: %w", err)
	}
	signed.Signature = base64.StdEncoding.EncodeToString(sig)

	// 申请 TSA 时间戳（签名内容的 sha256 作为 messageImprint）
	if tsaURLs == nil {
		tsaURLs = DefaultTSAURLs
	}
	if tsaResp, tsaURL, tstTime, err := requestTimestampWithFallback(signBytes, tsaURLs); err == nil {
		signed.TSAURL = tsaURL
		signed.TSAResponseB64 = base64.StdEncoding.EncodeToString(tsaResp)
		signed.TSATimestamp = tstTime
	}
	// TSA 失败不 fatal — 签名本身已足够

	return &signed, nil
}

// VerifySignedCustody 验证签名（不校验 TSA 响应 —— 让用户用 openssl ts -verify）
func VerifySignedCustody(data []byte) error {
	var signed SignedCustody
	if err := json.Unmarshal(data, &signed); err != nil {
		return fmt.Errorf("unmarshal manifest: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(signed.SignaturePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("公钥解码失败")
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("签名解码失败")
	}
	// 清空签名/TSA 字段重 marshal 对齐 SignCustody 流程
	signCopy := signed
	signCopy.Signature = ""
	signCopy.TSAURL = ""
	signCopy.TSAResponseB64 = ""
	signCopy.TSATimestamp = time.Time{}
	canonical, err := json.MarshalIndent(signCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal for verify: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return fmt.Errorf("签名校验失败 — 证据可能被篡改")
	}
	return nil
}

// ----------------------------------------------------------------------
// RFC 3161 时间戳客户端
// ----------------------------------------------------------------------

// TimeStampReq ASN.1 结构（RFC 3161 2.4.1）
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	// 可选字段省略：reqPolicy / nonce / certReq / extensions
	Nonce *big.Int `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm pkixAlgorithmIdentifier
	HashedMessage []byte
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// OID sha256 (2.16.840.1.101.3.4.2.1)
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

func requestTimestampWithFallback(content []byte, tsaURLs []string) ([]byte, string, time.Time, error) {
	digest := sha256.Sum256(content)
	var lastErr error
	for _, url := range tsaURLs {
		resp, t, err := requestTimestamp(digest[:], url)
		if err == nil {
			return resp, url, t, nil
		}
		lastErr = err
	}
	return nil, "", time.Time{}, fmt.Errorf("所有 TSA 都失败: %w", lastErr)
}

func requestTimestamp(digest []byte, tsaURL string) ([]byte, time.Time, error) {
	nonce, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkixAlgorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Tag: asn1.TagNull, Bytes: nil, FullBytes: []byte{5, 0}},
			},
			HashedMessage: digest,
		},
		Nonce: nonce,
	}
	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ASN.1 marshal TSR: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	httpReq, err := http.NewRequest("POST", tsaURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("new http req: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	httpReq.Header.Set("User-Agent", "DataRecoveryMaster/1.0 (RFC3161 client)")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("POST %s: %w", tsaURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("TSA %s 返回 %d", tsaURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("读 TSA resp: %w", err)
	}

	// 简化：不解析 CMS TST，只用响应到达时间近似时间戳。
	// 精确时间解析需要 CMS SignerInfo 展开 + TSTInfo ASN.1 decode；
	// 第三方校验用 `openssl ts -reply -in response.tsr -text` 可读真实时间。
	return body, time.Now().UTC(), nil
}
