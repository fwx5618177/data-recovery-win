package updater

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Pending 保存一次"已下载，等下次启动时应用"的更新信息。
// manifest.json 放在用户配置目录下 `<config>/data-recovery/update.pending/manifest.json`。
type Pending struct {
	Version    string `json:"version"`    // 目标版本（e.g. "v1.4.0"）
	BinaryPath string `json:"binaryPath"` // 下载好的新 exe 完整路径
	SHA256     string `json:"sha256"`     // 下载时计算的 SHA-256
	SizeBytes  int64  `json:"sizeBytes"`
	StagedAt   string `json:"stagedAt"` // ISO-8601
}

// PendingDir 返回本平台下 pending 目录的路径。
// 不存在时调用方应自行 MkdirAll。
func PendingDir() (string, error) {
	base, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "data-recovery", "update.pending"), nil
}

// ManifestPath 返回 manifest.json 完整路径
func ManifestPath() (string, error) {
	dir, err := PendingDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "manifest.json"), nil
}

// SavePending 把 pending 信息落盘
func SavePending(p Pending) error {
	dir, err := PendingDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建 pending 目录失败: %w", err)
	}
	mp, _ := ManifestPath()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(mp, data, 0o644)
}

// LoadPending 尝试读出 pending；返回 (nil, nil) 表示无 pending。
// 会做基础一致性校验：manifest 里的 BinaryPath 必须仍然存在且文件大小匹配，
// 否则视为陈旧状态返回 nil 让调用方当"没有 pending"处理。
func LoadPending() (*Pending, error) {
	mp, err := ManifestPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(mp)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var p Pending
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("manifest 解析失败: %w", err)
	}
	// 一致性校验：binary 文件是否还在 + 大小是否匹配
	if p.BinaryPath == "" {
		return nil, nil
	}
	info, err := os.Stat(p.BinaryPath)
	if err != nil || info.IsDir() {
		return nil, nil
	}
	if p.SizeBytes > 0 && info.Size() != p.SizeBytes {
		return nil, nil
	}
	return &p, nil
}

// ClearPending 把 pending 状态整个清掉（更新已应用 / 用户取消）
func ClearPending() error {
	dir, err := PendingDir()
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// configDir 挑一个本平台"用户配置目录"作为 pending 存放根。
// Windows: %APPDATA%；macOS: ~/Library/Application Support；Linux: ~/.config
func configDir() (string, error) {
	// Go 1.13+ 的 os.UserConfigDir 已经处理好跨平台
	d, err := os.UserConfigDir()
	if err == nil && d != "" {
		return d, nil
	}
	// 兜底：$HOME
	home, _ := os.UserHomeDir()
	if home == "" {
		return "", fmt.Errorf("找不到用户配置目录")
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Roaming"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Application Support"), nil
	default:
		return filepath.Join(home, ".config"), nil
	}
}
