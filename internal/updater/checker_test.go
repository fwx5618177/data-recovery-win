package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsNewerSemver(t *testing.T) {
	cases := []struct {
		local, remote string
		want          bool
		reason        string
	}{
		{"v1.2.3", "v1.2.4", true, "patch 升级"},
		{"v1.2.3", "v1.3.0", true, "minor 升级"},
		{"v1.2.3", "v2.0.0", true, "major 升级"},
		{"v1.2.3", "v1.2.3", false, "同版本"},
		{"v1.2.4", "v1.2.3", false, "本地更新"},
		{"v1.2.3-rc1", "v1.2.3", false, "去掉预发版后同版本"},
		{"v1.2.3", "v1.2.3-rc1", false, "预发版不提示"},
		// 历史回归（fix in v2.3.1）：dev 构建不该看到"新版可用"banner，
		// 因为 verify.IsVersionNewer 会拒绝 anti-downgrade，UX 反直觉。
		// 一致语义：dev 当本地视为"我已经是最新"，不提示更新。
		{"dev", "v1.0.0", false, "dev 不提示更新（与 anti-downgrade 一致）"},
		{"dev", "v999.0.0", false, "dev 即便很大新版本也不提示"},
		{"", "v1.0.0", false, "空版本同 dev 处理"},
		{"v1.0.0", "not-a-version", false, "远端格式非法不提示"},
		{"1.2.3", "1.2.4", true, "无 v 前缀也支持"},
	}
	for _, c := range cases {
		got := isNewerSemver(c.local, c.remote)
		if got != c.want {
			t.Errorf("isNewerSemver(%q, %q) = %v, want %v  [%s]",
				c.local, c.remote, got, c.want, c.reason)
		}
	}
}

// 跨函数一致性：isNewerSemver 和 IsVersionNewer 必须对同一对 (current, new)
// 给出相同结论，否则会出现"UI 提示新版可用 → 用户点下载 → anti-downgrade
// 拒绝"的 UX 矛盾。
func TestVersionCheckers_AreConsistent(t *testing.T) {
	pairs := [][2]string{
		{"v1.2.3", "v1.2.4"},
		{"v1.2.3", "v1.2.3"},
		{"v1.2.4", "v1.2.3"},
		{"dev", "v1.0.0"},
		{"dev", "v999.0.0"},
		{"", "v1.0.0"},
		{"v1.0.0", "junk"},
		{"v2.0.0", "v1.99.99"},
	}
	for _, p := range pairs {
		current, target := p[0], p[1]
		offered := isNewerSemver(current, target)
		applied := IsVersionNewer(current, target)
		if offered != applied {
			t.Errorf("不一致: isNewerSemver(%q, %q)=%v vs IsVersionNewer=%v —— "+
				"两者必须一致，否则 UI 提示和 anti-downgrade 会冲突",
				current, target, offered, applied)
		}
	}
}

func TestParseSemverTriple(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
		ok   bool
	}{
		{"v1.2.3", [3]int{1, 2, 3}, true},
		{"1.2.3", [3]int{1, 2, 3}, true},
		{"v1.2.3-rc1", [3]int{1, 2, 3}, true},
		{"v1.2.3+build.5", [3]int{1, 2, 3}, true},
		{"v1.2", [3]int{1, 2, 0}, true},
		{"dev", [3]int{0, 0, 0}, false},
		{"", [3]int{0, 0, 0}, false},
	}
	for _, c := range cases {
		got, ok := parseSemverTriple(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseSemverTriple(%q) = %v,%v; want %v,%v",
				c.in, got, ok, c.want, c.ok)
		}
	}
}

// mockedGitHubResponse 是 GitHub releases API 的最小响应
const mockedGitHubResponse = `{
  "tag_name": "v1.4.0",
  "name": "数据恢复大师 v1.4.0",
  "html_url": "https://github.com/owner/repo/releases/tag/v1.4.0",
  "body": "## 本次更新\n- 新加 exFAT 支持",
  "published_at": "2026-04-19T12:00:00Z",
  "prerelease": false,
  "draft": false,
  "assets": [
    {
      "name": "DataRecovery-windows-amd64.exe",
      "size": 12345678,
      "browser_download_url": "https://github.com/owner/repo/releases/download/v1.4.0/DataRecovery-windows-amd64.exe"
    }
  ]
}`

func TestCheckLatest_WithMockServer(t *testing.T) {
	// 把 GitHub API 重定向到本地测试服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/releases/latest" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockedGitHubResponse))
	}))
	defer server.Close()

	// 猴子补丁 httpClient，让 CheckLatest 打到测试服务器
	origTransport := httpClient.Transport
	httpClient.Transport = &rewritingTransport{targetBase: server.URL}
	defer func() { httpClient.Transport = origTransport }()

	// 本地版本是 v1.3.0，上游返回 v1.4.0 → 应提示更新
	origVersion := Version
	Version = "v1.3.0"
	defer func() { Version = origVersion }()

	res, err := CheckLatest(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if !res.HasUpdate {
		t.Error("应提示有更新 (v1.3.0 → v1.4.0)")
	}
	if res.LatestVersion != "v1.4.0" {
		t.Errorf("LatestVersion 错: %q", res.LatestVersion)
	}
	if res.DownloadPage == "" {
		t.Error("DownloadPage 应非空")
	}
	if len(res.Assets) != 1 {
		t.Fatalf("Assets 数量错: %d", len(res.Assets))
	}
	// 显式检查 DownloadURL 字段从 GitHub 的 browser_download_url 被正确映射过来（回归 Bug #2）
	if res.Assets[0].DownloadURL != "https://github.com/owner/repo/releases/download/v1.4.0/DataRecovery-windows-amd64.exe" {
		t.Errorf("Assets[0].DownloadURL 映射错: %q", res.Assets[0].DownloadURL)
	}
	if res.Assets[0].Name != "DataRecovery-windows-amd64.exe" {
		t.Errorf("Assets[0].Name 错: %q", res.Assets[0].Name)
	}
	// 序列化 CheckResult → 确认 Wails 输出给前端的 JSON 字段是 camelCase
	// （Bug #2 根因就是 Asset 没有 camelCase tag，前端读不到）
	raw, _ := json.Marshal(res.Assets[0])
	s := string(raw)
	if !strings.Contains(s, `"downloadUrl"`) {
		t.Errorf("Asset JSON tag 应为 downloadUrl，实际: %s", s)
	}
	if strings.Contains(s, `"browser_download_url"`) {
		t.Errorf("不应把 GitHub 的 snake_case 泄露到前端: %s", s)
	}
}

func TestCheckLatest_SameVersion_NoUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(mockedGitHubResponse))
	}))
	defer server.Close()

	origTransport := httpClient.Transport
	httpClient.Transport = &rewritingTransport{targetBase: server.URL}
	defer func() { httpClient.Transport = origTransport }()

	Version = "v1.4.0"
	res, err := CheckLatest(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if res.HasUpdate {
		t.Error("同版本不应提示更新")
	}
}

func TestCheckLatest_EmptyOwnerRejected(t *testing.T) {
	if _, err := CheckLatest(context.Background(), "", "repo"); err == nil {
		t.Error("空 owner 应返回错误")
	}
}

// rewritingTransport 把对 api.github.com 的请求重定向到 targetBase
type rewritingTransport struct {
	targetBase string
}

func (rt *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme = "http"
	// 从 targetBase 提取 host
	u.Host = req.Host
	if rt.targetBase != "" {
		if idx := indexOf(rt.targetBase, "://"); idx >= 0 {
			u.Host = rt.targetBase[idx+3:]
			u.Scheme = rt.targetBase[:idx]
		}
	}
	r := req.Clone(req.Context())
	r.URL = &u
	r.Host = u.Host
	return http.DefaultTransport.RoundTrip(r)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
