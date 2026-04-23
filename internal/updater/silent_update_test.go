package updater

import (
	"testing"
)

// 模拟 app.go 里 pickPlatformAsset 的核心匹配逻辑（单独独立测试）。
// 这里复刻策略保持 updater 包自测没依赖 app 层 —— 测试规则本身。
//
// 实际实现在 app.go::pickPlatformAsset，两处要保持一致。
func TestAssetMatching_Rules(t *testing.T) {
	cases := []struct {
		name   string
		assets []string
		os     string
		arch   string
		want   string // 期望命中的 asset name；"" = 都不匹配
	}{
		{"windows amd64 基础", []string{"data-recovery-windows-amd64.exe", "data-recovery-darwin-arm64.tar.gz"},
			"windows", "amd64", "data-recovery-windows-amd64.exe"},
		{"macOS universal", []string{"data-recovery-darwin-universal.tar.gz", "data-recovery-windows-amd64.exe"},
			"darwin", "arm64", "data-recovery-darwin-universal.tar.gz"},
		{"仅 OS 匹配 fallback", []string{"data-recovery-linux.deb"}, "linux", "amd64", "data-recovery-linux.deb"},
		{"无匹配", []string{"data-recovery-freebsd-amd64.tar.gz"}, "windows", "amd64", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var assets []Asset
			for _, n := range c.assets {
				assets = append(assets, Asset{Name: n})
			}
			got := pickAssetForTest(assets, c.os, c.arch)
			if got == "" && c.want == "" {
				return
			}
			if got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

// pickAssetForTest 复刻 app.go 里 pickPlatformAsset 的规则（保持单测独立）
// 真实代码在 app.go；这里是**规则副本**做契约测试
func pickAssetForTest(assets []Asset, osName, arch string) string {
	osName = lower(osName)
	arch = lower(arch)
	// 优先：name 含 os + (arch 或 "universal")
	for _, a := range assets {
		n := lower(a.Name)
		if contains(n, osName) && (contains(n, arch) || contains(n, "universal")) {
			return a.Name
		}
	}
	// Fallback：仅 os 匹配
	for _, a := range assets {
		n := lower(a.Name)
		if contains(n, osName) {
			return a.Name
		}
	}
	return ""
}

func lower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return string(out)
}

func contains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
