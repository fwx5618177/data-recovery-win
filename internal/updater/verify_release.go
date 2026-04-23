package updater

// 从 GitHub Release 取 SHA256SUMS.txt + 其 Ed25519 签名 + 公钥，做端到端完整性验证。
//
// 流程（符合外部安全审计 checklist）：
//   1. HTTPS 下载 SHA256SUMS.txt                → 内容
//   2. HTTPS 下载 SHA256SUMS.txt.sig             → 签名
//   3. 公钥：优先用代码内 pin（EmbeddedPublicKey），退到 release 里的 release_pubkey.pem
//   4. Ed25519 verify(内容, 签名, 公钥) → 判真伪
//
// 为什么需要"代码内 pin"？
//   如果攻击者能替换 release 里的 release_pubkey.pem 同时替换 .sig，就绕过了校验。
//   代码内 pin 才是 root-of-trust —— 攻击者要改就得先 compromise 我们的代码仓库。
//
// 为什么也保留 release 公钥的 fallback？
//   当前 EmbeddedPublicKey 为空（build time -ldflags 可注入）；空时走 release 公钥
//   让 MVP 阶段 flow 跑通，生产发布前会把真实公钥 pin 进 build。

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EmbeddedPublicKey 是编译时通过 -ldflags 注入的 **代码内 pin** 的 Ed25519 公钥（PEM）。
// 空值 → 走 release 附带的 release_pubkey.pem 兜底（开发期）。
// 生产发布前 build 命令：
//   go build -ldflags "-X data-recovery/internal/updater.EmbeddedPublicKey=$(base64 < pubkey.pem)"
//
// 或直接把 PEM 文本 embedded 进来（不用 -ldflags）。
var EmbeddedPublicKey = ""

// VerifySumsSignatureFromRelease 下载并验证 SHA256SUMS.txt 的 Ed25519 签名。
// 成功返回 nil；签名文件不存在或校验失败返回 error（调用方决定是否阻塞 apply）。
func VerifySumsSignatureFromRelease(ctx context.Context, owner, repo, version string) error {
	if owner == "" || repo == "" {
		return fmt.Errorf("owner/repo 未配置")
	}
	tag := version
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	baseURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s", owner, repo, tag)

	// 1. 下载 SHA256SUMS.txt
	sumsBytes, err := fetchFile(ctx, baseURL+"/SHA256SUMS.txt")
	if err != nil {
		return fmt.Errorf("获取 SHA256SUMS.txt: %w", err)
	}
	// 2. 下载 .sig
	sigBytes, err := fetchFile(ctx, baseURL+"/SHA256SUMS.txt.sig")
	if err != nil {
		return fmt.Errorf("获取签名: %w", err)
	}
	// 3. 选公钥
	var pubBytes []byte
	if EmbeddedPublicKey != "" {
		// ldflags 注入的是 base64 编码的 PEM（避免 newline 在 ldflags 里的转义问题）
		// 先尝试 base64 decode；失败则当 PEM 原文
		if decoded, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(EmbeddedPublicKey)); decErr == nil {
			pubBytes = decoded
		} else {
			pubBytes = []byte(EmbeddedPublicKey)
		}
	} else {
		pubBytes, err = fetchFile(ctx, baseURL+"/release_pubkey.pem")
		if err != nil {
			return fmt.Errorf("获取公钥: %w（生产请用 -ldflags 嵌入 EmbeddedPublicKey）", err)
		}
	}
	// 4. 验签
	if err := VerifySHA256SUMSSignature(sumsBytes, sigBytes, pubBytes); err != nil {
		return fmt.Errorf("Ed25519 签名验证失败: %w", err)
	}
	return nil
}

// fetchFile GET 任意 URL，返回完整 body（限 1MB 防异常大文件）
func fetchFile(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// SHA256SUMS.txt 通常 < 10KB；防巨文件攻击
	const maxSize = 1 << 20 // 1 MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, err
	}
	if len(body) == maxSize {
		return nil, fmt.Errorf("文件超 1MB 异常")
	}
	return body, nil
}
