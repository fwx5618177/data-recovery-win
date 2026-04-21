package updater

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchSHA256SUMS 从 GitHub Release 的 SHA256SUMS.txt 取预期 hash 表。
// 格式与 coreutils `sha256sum` 一致：
//
//	<64-hex>  <filename>
//
// 发版 CI 要先跑:
//
//	sha256sum DataRecovery-* > SHA256SUMS.txt
//
// 并把 SHA256SUMS.txt 一起 upload 到 Release。
func FetchSHA256SUMS(ctx context.Context, owner, repo, version string) (map[string]string, error) {
	url := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/SHA256SUMS.txt",
		owner, repo, version)
	c := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("下载 SHA256SUMS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("SHA256SUMS HTTP %d", resp.StatusCode)
	}
	return parseSHA256SUMS(resp.Body)
}

func parseSHA256SUMS(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "<hash>  <filename>" 或 "<hash> *<filename>"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := strings.ToLower(fields[0])
		name := fields[len(fields)-1]
		if strings.HasPrefix(name, "*") {
			name = name[1:]
		}
		if len(hash) == 64 {
			out[name] = hash
		}
	}
	return out, scanner.Err()
}

// VerifyAssetChecksum 核对下载文件的 sha256 vs SHA256SUMS 里的预期值。
//
// 调用方：ApplyPendingUpdate 前：
//
//	sums, _ := FetchSHA256SUMS(ctx, owner, repo, version)
//	if err := VerifyAssetChecksum(pending.BinaryName, pending.SHA256, sums); err != nil {
//	    return fmt.Errorf("下载的二进制 checksum 不匹配发版记录: %w", err)
//	}
//
// 预期 hash 表里找不到 filename → 返回警告级错误，调用方可选择继续（向后兼容老版本
// 未发布 SHA256SUMS.txt 的 release）。
func VerifyAssetChecksum(assetName, actualSHA256 string, sums map[string]string) error {
	expected, ok := sums[assetName]
	if !ok {
		return fmt.Errorf("SHA256SUMS 里未找到 %s（可能此 release 未产出校验文件）", assetName)
	}
	if strings.ToLower(actualSHA256) != expected {
		return fmt.Errorf("sha256 不匹配：期望 %s，实际 %s", expected, actualSHA256)
	}
	return nil
}
