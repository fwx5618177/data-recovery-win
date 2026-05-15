package ios

// ============================================================================
// iOS 备份目录发现 + 元数据解析
//
// iTunes / Finder 把 iOS 备份放在：
//   macOS:   ~/Library/Application Support/MobileSync/Backup/<UDID>
//   Windows 1: %APPDATA%/Apple Computer/MobileSync/Backup/<UDID>    (iTunes 经典版)
//   Windows 2: %USERPROFILE%/Apple/MobileSync/Backup/<UDID>          (Microsoft Store 版)
//
// 每个 <UDID> 目录下：
//   Info.plist       — 设备信息（品牌、型号、iOS 版本、电话号码）
//   Manifest.plist   — 备份状态，含是否加密 + BackupKeyBag
//   Manifest.db      — SQLite，Files 表列出所有文件及其 domain/path/size
//   Status.plist     — 最后一次 snapshot 状态
//   <xx>/<40-hex>    — 实际文件内容，按 SHA1(domain-relativePath) 的前 2 hex 分桶
//
// 发现策略：用 runtime.GOOS 决定根目录；遍历一级子目录，每个看起来像 UUID 的
// 目录都当成一个备份候选，再用 Info.plist 存在性 + 解析确认。
// ============================================================================

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Backup 描述本地一份已发现的 iOS 备份
type Backup struct {
	UDID           string    // 设备 UDID（目录名），通常是 40 个十六进制字符
	Root           string    // 绝对路径
	DeviceName     string    // 如 "Alice 的 iPhone"
	ProductType    string    // 如 "iPhone14,5"
	ProductVersion string    // 如 "17.3.1"
	IsEncrypted    bool      // Manifest.plist 里的 IsEncrypted
	LastBackup     time.Time // Info.plist 里的 Last Backup Date

	// 底层文件路径，方便下游复用
	InfoPlistPath     string
	ManifestPlistPath string
	ManifestDBPath    string
}

// BackupSearchRoots 返回当前用户应该被扫描的 iOS 备份根目录。
// 在所有平台都返回 slice，方便跨平台统一处理。
//
// 只返回"存在"的路径（os.Stat 通过），不存在的不返回 —— 让 UI 不必显示 "路径不存在，错误"。
func BackupSearchRoots() []string {
	var roots []string

	switch runtime.GOOS {
	case "darwin":
		if home := os.Getenv("HOME"); home != "" {
			roots = append(roots, filepath.Join(home, "Library", "Application Support", "MobileSync", "Backup"))
		}
	case "windows":
		// iTunes 经典版
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			roots = append(roots, filepath.Join(appdata, "Apple Computer", "MobileSync", "Backup"))
		}
		// Microsoft Store 版（Windows 10/11）
		if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
			roots = append(roots, filepath.Join(userProfile, "Apple", "MobileSync", "Backup"))
		}
	case "linux":
		// Linux 没官方 iTunes，但 libimobiledevice 生态的用户可能把备份放这里；尽力尝试
		if home := os.Getenv("HOME"); home != "" {
			roots = append(roots, filepath.Join(home, ".config", "libimobiledevice", "Backup"))
		}
	}

	// 过滤：只保留真实存在的目录。
	// roots 仅含我们硬编码的已知 iOS backup 路径（~/Library/Application Support/MobileSync/Backup
	// 等 OS 标准位置），不是用户输入路径，无 path traversal 风险。
	var existing []string
	for _, r := range roots {
		// #nosec G304 G703 -- iOS 备份硬编码路径，由 OS 定义不是用户控
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			existing = append(existing, r)
		}
	}
	return existing
}

// DiscoverBackups 扫描所有已知根目录，返回所有看起来是 iOS 备份的子目录。
//
// "看起来是 iOS 备份"的判定：
//  1. 目录名是 UDID 格式（40 位 hex；也接受 iOS 16+ 的 25-char UUID 变体）
//  2. 存在 Manifest.plist（最可靠的指纹）
//
// 解析失败的备份也返回 —— UI 里让用户看到"有个备份但损坏"，好过隐藏。
func DiscoverBackups() ([]*Backup, error) {
	roots := BackupSearchRoots()
	if len(roots) == 0 {
		return nil, nil
	}

	var out []*Backup
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if !looksLikeUDID(e.Name()) {
				continue
			}
			bkPath := filepath.Join(root, e.Name())
			if b, err := OpenBackup(bkPath); err == nil {
				out = append(out, b)
			}
		}
	}
	return out, nil
}

// OpenBackup 打开指定路径的备份，读 Info.plist + Manifest.plist。
// 不打开 Manifest.db（那步推迟到真正 scan 时，且要先过加密处理）。
func OpenBackup(path string) (*Backup, error) {
	b := &Backup{
		Root:              path,
		UDID:              filepath.Base(path),
		InfoPlistPath:     filepath.Join(path, "Info.plist"),
		ManifestPlistPath: filepath.Join(path, "Manifest.plist"),
		ManifestDBPath:    filepath.Join(path, "Manifest.db"),
	}

	if _, err := os.Stat(b.ManifestPlistPath); err != nil {
		return nil, fmt.Errorf("不是 iOS 备份（缺 Manifest.plist）: %w", err)
	}

	// Info.plist 不是所有备份都有（Status.plist 里也有部分信息），读失败不致命
	if info, err := os.ReadFile(b.InfoPlistPath); err == nil {
		if v, err := ParsePlist(info); err == nil {
			b.DeviceName = v.GetString("Device Name")
			b.ProductType = v.GetString("Product Type")
			b.ProductVersion = v.GetString("Product Version")
			// 时间字段名各版本略有不同，按优先级尝试
			if t, ok := extractTime(v, "Last Backup Date", "Last Backup", "SnapshotDate"); ok {
				b.LastBackup = t
			}
		}
	}

	manifest, err := os.ReadFile(b.ManifestPlistPath)
	if err != nil {
		return nil, fmt.Errorf("读 Manifest.plist 失败: %w", err)
	}
	mv, err := ParsePlist(manifest)
	if err != nil {
		return nil, fmt.Errorf("解析 Manifest.plist 失败: %w", err)
	}
	b.IsEncrypted = mv.GetBool("IsEncrypted", false)

	if b.DeviceName == "" {
		// 有些新版 Manifest.plist 里也有 Lockdown dict 存设备名
		if ld := mv.GetDict("Lockdown"); ld != nil {
			b.DeviceName = ld.GetString("DeviceName")
			if b.ProductType == "" {
				b.ProductType = ld.GetString("ProductType")
			}
			if b.ProductVersion == "" {
				b.ProductVersion = ld.GetString("ProductVersion")
			}
		}
	}
	return b, nil
}

// ReadManifestPlist 重新读 Manifest.plist 并返回解析后的根节点。
// 加密流程需要从这里取 BackupKeyBag / ManifestKey / Salt / Iterations 等字段。
func (b *Backup) ReadManifestPlist() (*Value, error) {
	data, err := os.ReadFile(b.ManifestPlistPath)
	if err != nil {
		return nil, err
	}
	return ParsePlist(data)
}

// IsValid 一个备份至少必须：存在 Manifest.plist + 能识别 encrypted 标志
func (b *Backup) IsValid() bool {
	if b == nil {
		return false
	}
	if _, err := os.Stat(b.ManifestPlistPath); err != nil {
		return false
	}
	return true
}

// looksLikeUDID 简单的 UUID/UDID 形态校验：
//   - 长度 25（iOS 16+ 的 alphanumeric UUID）
//   - 长度 40（经典 iOS UDID，40 hex）
//   - 带一个 hyphen 的 40-char UDID（iPhone 12+）
func looksLikeUDID(name string) bool {
	clean := strings.ReplaceAll(name, "-", "")
	if len(clean) == 25 || len(clean) == 40 {
		for _, c := range clean {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}
	return false
}

// extractTime 按优先顺序从 dict 里找 date 字段
func extractTime(v *Value, keys ...string) (time.Time, bool) {
	if v == nil || v.Kind != KindDict {
		return time.Time{}, false
	}
	for _, k := range keys {
		if item, ok := v.Dict[k]; ok && item != nil && item.Kind == KindDate {
			return item.Time, true
		}
	}
	return time.Time{}, false
}

// ErrEncrypted 表示尝试操作加密备份但没给密码/keybag。
var ErrEncrypted = errors.New("备份已加密，需要 Manifest.plist 的 BackupKeyBag + 用户密码解密")
