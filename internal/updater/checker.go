// Package updater 向 GitHub Releases API 查询是否有新版。
//
// 故意**不做**全自动替换二进制：
//   - Windows 上运行中的 exe 不能被替换（需辅助进程 / 重启生效），工程复杂度高
//   - 数据恢复工具在扫描/恢复过程中替换进程会让用户丢数据，风险远大于便利
//   - 业界同类工具（DMDE / R-Studio）都是"检测 + 提示用户"，不是静默更新
//
// 本包只负责"有没有新版 + 下载页链接"。真正的下载由用户浏览器完成。
// 校验下载包的 SHA256 是后续加强的点（GitHub Release 本身走 HTTPS，已有基础安全保障）。
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Version 当前构建的版本号。
// 正式发版时通过 ldflags 注入：go build -ldflags "-X data-recovery/internal/updater.Version=v1.3.1"
// 未注入时保持 "dev"，checker 会把任何非 dev 的 upstream 版本都视为"新版"。
var Version = "dev"

// githubRelease 是 GitHub API 原始响应结构（字段名与 API 契约绑定），
// 仅用于解析，不对外暴露 —— 外部用下方的 Asset / CheckResult。
type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	HTMLURL     string        `json:"html_url"`
	Body        string        `json:"body"`
	PublishedAt time.Time     `json:"published_at"`
	Prerelease  bool          `json:"prerelease"`
	Draft       bool          `json:"draft"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"browser_download_url"`
}

// Asset 是对外（前端）暴露的下载资源，camelCase JSON tag 与项目其他类型一致。
// 前端读 `.name / .size / .downloadUrl`，无须关心 GitHub API 契约。
type Asset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"downloadUrl"`
}

// CheckResult 是 CheckLatest 的返回体，明确表达"是否有更新"。
// JSON 标签采用 camelCase 与前端其他类型保持一致。
type CheckResult struct {
	HasUpdate      bool    `json:"hasUpdate"`
	CurrentVersion string  `json:"currentVersion"`
	LatestVersion  string  `json:"latestVersion"`
	DownloadPage   string  `json:"downloadPage"`
	ReleaseNotes   string  `json:"releaseNotes"`
	Assets         []Asset `json:"assets"`
}

// httpClient 全局共用一个 client，设置合理超时防止因为网络卡死挂起启动逻辑
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// CheckLatest 查询 github.com/<owner>/<repo> 的 latest release，比较版本号。
//
// 调用方：app 启动后起一个 goroutine 调用，不阻塞主流程；
// ctx 可用于取消（例如扫描中用户不想让更新检查干扰网络）。
func CheckLatest(ctx context.Context, owner, repo string) (*CheckResult, error) {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("owner/repo 不能为空")
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// 标识下 UA，让 GitHub 限流统计更准确
	req.Header.Set("User-Agent", "data-recovery/"+Version)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 GitHub API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// 仓库没有 release 不是错误，算"没有更新"
		return &CheckResult{HasUpdate: false, CurrentVersion: Version}, nil
	}
	if resp.StatusCode != http.StatusOK {
		// 读取一点 body 辅助定位（比如 403 rate limit）
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GitHub API 返回 %d: %s", resp.StatusCode, string(body))
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	// 略过草稿 / 预发布
	if rel.Draft || rel.Prerelease {
		return &CheckResult{HasUpdate: false, CurrentVersion: Version}, nil
	}

	// 把 githubAsset → Asset（显式 map 因为 JSON tag 不同：browser_download_url → downloadUrl）
	// 不能用类型转换 Asset(a) —— struct literal 是有意的
	assets := make([]Asset, 0, len(rel.Assets))
	for _, a := range rel.Assets {
		//lint:ignore S1016 JSON tag 差异，struct literal 是故意的
		assets = append(assets, Asset{
			Name:        a.Name,
			Size:        a.Size,
			DownloadURL: a.DownloadURL,
		})
	}

	result := &CheckResult{
		CurrentVersion: Version,
		LatestVersion:  rel.TagName,
		DownloadPage:   rel.HTMLURL,
		ReleaseNotes:   rel.Body,
		Assets:         assets,
	}
	result.HasUpdate = isNewerSemver(Version, rel.TagName)
	return result, nil
}

// isNewerSemver 比较两个 SemVer 字符串，判断 remote 是否比 local 新。
//
// 支持：
//   - "v1.2.3" / "1.2.3"（前缀 v 可选）
//   - 忽略预发版尾巴（"v1.2.3-rc1" 只比 major/minor/patch）
//   - local 是 "dev" / 空 / 格式非法时，只要 remote 合法就认为有更新
//
// 故意不用第三方 semver 库——我们的版本号格式极简单，手写 20 行搞定避免依赖。
func isNewerSemver(local, remote string) bool {
	rParts, rOK := parseSemverTriple(remote)
	if !rOK {
		return false // remote 版本号都解不出来，不提示更新
	}
	lParts, lOK := parseSemverTriple(local)
	if !lOK {
		return true // local 是 "dev" 之类，远端有正式版就提示
	}
	for i := 0; i < 3; i++ {
		if rParts[i] > lParts[i] {
			return true
		}
		if rParts[i] < lParts[i] {
			return false
		}
	}
	return false
}

// parseSemverTriple 取前三段数字（major.minor.patch），忽略 "v" 前缀和 "-..." 尾巴
func parseSemverTriple(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V"))
	if s == "" {
		return out, false
	}
	// 砍掉预发版后缀 "-rc1" / "-beta" / "+build"
	for _, sep := range []string{"-", "+"} {
		if idx := strings.Index(s, sep); idx >= 0 {
			s = s[:idx]
		}
	}
	parts := strings.SplitN(s, ".", 4)
	if len(parts) < 1 {
		return out, false
	}
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
