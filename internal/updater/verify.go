package updater

// 外部安全审计级更新完整性验证层 —— 符合 TUF (The Update Framework) 核心原则。
//
// 威胁模型（审计会问的问题）:
//   1. MITM 替换下载内容？         → SHA256SUMS 对比 asset hash
//   2. MITM 替换 SHA256SUMS 本身？  → Ed25519 签名 SHA256SUMS
//   3. 攻击者拿私钥？              → 建议 HSM + 轮换；审计日志可事后溯源
//   4. Rollback 攻击（降级到老版）？ → 版本号单调检查
//   5. 本地 binary 篡改？          → apply 前重算 hash 对比 pending manifest
//   6. Pending manifest 本身被改？  → 我们只从 TLS + 签名下载数据写入；攻击者能改
//                                  本地 pending 意味着已攻破本地 FS，超出我们威胁模型
//   7. 失败更新导致 brick？        → 失败回滚（本文件未实现，见 RunApplyHelper）
//
// 未做到 TUF 完整 spec 的部分：
//   - role separation (root/snapshot/timestamp/targets)
//   - key rotation + delegation
//   - metadata freshness (expiry timestamp)
//
// 这些是多密钥基础设施，对单开发者项目过重。当前签名模型：单一 release 私钥
// 由维护者掌管，公钥 pin 在客户端代码（+ 文档固定到 SIGNING.md）。

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
)

// VerifySHA256SUMSSignature 用 Ed25519 公钥验证 SHA256SUMS.txt 签名。
//
// 参数:
//
//	sumsContent: SHA256SUMS.txt 的原字节内容
//	signature:   SHA256SUMS.txt.sig 的原字节（Ed25519 raw 64-byte signature）
//	publicKey:   Ed25519 公钥（PEM 编码或 raw 32 字节）
//
// 返回: 签名合法 nil；不合法 error。
func VerifySHA256SUMSSignature(sumsContent, signature, publicKey []byte) error {
	pub, err := parseEd25519PublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("签名长度错 %d (需 %d)", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, sumsContent, signature) {
		return fmt.Errorf("Ed25519 签名校验失败 —— SHA256SUMS 可能被篡改")
	}
	return nil
}

// parseEd25519PublicKey 支持 PEM 或 raw 32-byte 两种公钥格式
func parseEd25519PublicKey(data []byte) (ed25519.PublicKey, error) {
	// 尝试 raw 32 字节
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}
	// 尝试 PEM "PUBLIC KEY" / "ED25519 PUBLIC KEY" block
	block, _ := pem.Decode(bytes.TrimSpace(data))
	if block == nil {
		return nil, fmt.Errorf("PEM decode 失败")
	}
	// Block.Bytes 对 Ed25519 公钥可能是 DER-encoded SubjectPublicKeyInfo 或 raw
	// 先尝试 raw（Block.Bytes 长度 == 32）
	if len(block.Bytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(block.Bytes), nil
	}
	// DER SubjectPublicKeyInfo: [SEQ + algId + BIT STRING(公钥 32字节)]
	// OpenSSL `pkey -pubout` 生成的就是 DER 形式；最末尾 32 字节是裸公钥
	if len(block.Bytes) >= ed25519.PublicKeySize {
		return ed25519.PublicKey(block.Bytes[len(block.Bytes)-ed25519.PublicKeySize:]), nil
	}
	return nil, fmt.Errorf("公钥 PEM body 长度异常: %d", len(block.Bytes))
}

// IsVersionNewer 严格语义化版本比较 + rollback 防护
//
// 返回 true 表示 "new" 真的比 "current" 新（审计单调）。
// 仅接受 vMAJOR.MINOR.PATCH[+...] 格式；解析失败返回 false（拒绝应用未知格式版本）。
//
// 与 CheckLatest 的 isNewerSemver 区别：这里额外拒绝 downgrade
// （即使 new < current 也返回 false，不像 CheckLatest 只问"是不是相等"）
func IsVersionNewer(current, new string) bool {
	c, ok := parseSemverTriple(current)
	if !ok {
		return false
	}
	n, ok := parseSemverTriple(new)
	if !ok {
		return false
	}
	for i := 0; i < 3; i++ {
		if n[i] > c[i] {
			return true
		}
		if n[i] < c[i] {
			return false
		}
	}
	return false // 相等不算 newer
}
