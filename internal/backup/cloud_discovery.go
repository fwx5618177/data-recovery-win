package backup

// 云端备份本地发现 —— 扫用户已同步到本地磁盘的云盘文件夹（iCloud/OneDrive/
// Google Drive/Dropbox），找其中的 iOS/Android 备份文件。
//
// 这是"零网络"哲学的延伸：我们**不**对接任何云 API（不要 OAuth、不要 token
// 轮转、不上传任何东西）。但用户实际上 95% 的"云备份"已经被同步客户端拉到本地
// 磁盘了——iCloud Drive 的 com~apple~CloudDocs 文件夹、OneDrive sync、Drive 桌面版
// 都有标准本地路径。我们只是**把这些路径加进搜索范围**，让 iOS/Android 备份
// 发现器顺便扫到。
//
// 用户体验：
//   - 装了 OneDrive 桌面版 → 自动发现 OneDrive 里的 iPhone 备份
//   - 用 Google Drive 桌面版 → 自动发现 Drive 里的 Android backup .ab 文件
//   - 没装 → 这些路径不存在，跳过，无副作用
//
// 不覆盖：纯网页云盘（如 web 端 iCloud.com 的备份，需要 Apple ID 登录拉取，
// 是 OAuth/2FA 范畴，违反零网络原则）。

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CloudProvider 标识同步客户端类型
type CloudProvider string

const (
	ProviderICloud      CloudProvider = "iCloud"
	ProviderOneDrive    CloudProvider = "OneDrive"
	ProviderGoogleDrive CloudProvider = "GoogleDrive"
	ProviderDropbox     CloudProvider = "Dropbox"
	ProviderBox         CloudProvider = "Box"
	ProviderMega        CloudProvider = "MEGA"
	ProviderPCloud      CloudProvider = "pCloud"
	ProviderNextcloud   CloudProvider = "Nextcloud"
)

// CloudSyncRoot 表示一个本地同步根目录
type CloudSyncRoot struct {
	Provider CloudProvider
	Path     string // 绝对路径
	// Reason 是简短人话，向用户解释为什么这个目录是 X 云的同步点
	Reason string
}

// DiscoverCloudSyncRoots 返回所有发现的云同步根目录（仅返回真实存在的）
//
// 跨平台路径策略（macOS / Windows / Linux）：
//
//	macOS：
//	  iCloud Drive：    ~/Library/Mobile Documents/com~apple~CloudDocs
//	  OneDrive：        ~/OneDrive、~/OneDrive - <org>
//	  Google Drive：    ~/Google Drive、~/Library/CloudStorage/GoogleDrive-*
//	  Dropbox：         ~/Dropbox、~/Library/CloudStorage/Dropbox
//	  Box：             ~/Library/CloudStorage/Box-Box
//
//	Windows：
//	  OneDrive：        %USERPROFILE%\OneDrive、%USERPROFILE%\OneDrive - <org>
//	  Google Drive：    %USERPROFILE%\Google Drive
//	                    G:\、H:\ 等盘符（Drive File Stream 默认 G:）
//	  Dropbox：         %USERPROFILE%\Dropbox
//	  iCloud：          %USERPROFILE%\iCloudDrive
//	  Box：             %USERPROFILE%\Box
//
//	Linux：
//	  Nextcloud：       ~/Nextcloud
//	  Dropbox：         ~/Dropbox
//	  MEGA：            ~/MEGA
//	  Google Drive：    ~/google-drive-ocamlfuse 等第三方挂载点
func DiscoverCloudSyncRoots() []CloudSyncRoot {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var candidates []CloudSyncRoot

	switch runtime.GOOS {
	case "darwin":
		candidates = append(candidates, macOSCandidates(home)...)
	case "windows":
		candidates = append(candidates, windowsCandidates(home)...)
	case "linux":
		candidates = append(candidates, linuxCandidates(home)...)
	}

	// 过滤：只保留真实存在的目录
	var found []CloudSyncRoot
	for _, c := range candidates {
		st, err := os.Stat(c.Path)
		if err != nil || !st.IsDir() {
			continue
		}
		found = append(found, c)
	}
	return found
}

func macOSCandidates(home string) []CloudSyncRoot {
	libCloudStorage := filepath.Join(home, "Library", "CloudStorage")
	out := []CloudSyncRoot{
		{ProviderICloud, filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs"),
			"macOS iCloud Drive 标准同步点（由系统 cloud daemon 维护）"},
		{ProviderDropbox, filepath.Join(home, "Dropbox"),
			"Dropbox macOS 桌面版默认同步路径"},
	}
	// Library/CloudStorage 下面的 OneDrive-X / GoogleDrive-X / Dropbox / Box-Box 等
	if entries, err := os.ReadDir(libCloudStorage); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			lower := strings.ToLower(name)
			full := filepath.Join(libCloudStorage, name)
			switch {
			case strings.HasPrefix(lower, "onedrive"):
				out = append(out, CloudSyncRoot{ProviderOneDrive, full,
					"macOS Files Provider OneDrive 同步点 (" + name + ")"})
			case strings.HasPrefix(lower, "googledrive"):
				out = append(out, CloudSyncRoot{ProviderGoogleDrive, full,
					"macOS Files Provider Google Drive 同步点 (" + name + ")"})
			case strings.HasPrefix(lower, "dropbox"):
				out = append(out, CloudSyncRoot{ProviderDropbox, full,
					"macOS Files Provider Dropbox 同步点"})
			case strings.HasPrefix(lower, "box"):
				out = append(out, CloudSyncRoot{ProviderBox, full,
					"macOS Files Provider Box 同步点"})
			case strings.HasPrefix(lower, "mega"):
				out = append(out, CloudSyncRoot{ProviderMega, full,
					"macOS Files Provider MEGA 同步点"})
			case strings.HasPrefix(lower, "pcloud"):
				out = append(out, CloudSyncRoot{ProviderPCloud, full,
					"macOS Files Provider pCloud 同步点"})
			}
		}
	}
	// 老路径 / 旧版客户端
	out = append(out, []CloudSyncRoot{
		{ProviderOneDrive, filepath.Join(home, "OneDrive"), "OneDrive 旧版默认路径"},
		{ProviderGoogleDrive, filepath.Join(home, "Google Drive"), "Google Drive 旧 Backup-and-Sync 客户端"},
	}...)
	// OneDrive 企业版（OneDrive - <org>）
	if entries, err := os.ReadDir(home); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, "OneDrive - ") {
				out = append(out, CloudSyncRoot{ProviderOneDrive, filepath.Join(home, name),
					"OneDrive for Business (" + name + ")"})
			}
		}
	}
	return out
}

func windowsCandidates(home string) []CloudSyncRoot {
	out := []CloudSyncRoot{
		{ProviderOneDrive, filepath.Join(home, "OneDrive"), "OneDrive 默认同步路径"},
		{ProviderGoogleDrive, filepath.Join(home, "Google Drive"), "Google Drive Backup-and-Sync 默认路径"},
		{ProviderDropbox, filepath.Join(home, "Dropbox"), "Dropbox Windows 桌面版默认路径"},
		{ProviderBox, filepath.Join(home, "Box"), "Box Drive Windows 默认路径"},
		{ProviderICloud, filepath.Join(home, "iCloudDrive"), "iCloud for Windows 同步路径"},
	}
	// OneDrive - <org> 企业版
	if entries, err := os.ReadDir(home); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, "OneDrive - ") {
				out = append(out, CloudSyncRoot{ProviderOneDrive, filepath.Join(home, name),
					"OneDrive for Business (" + name + ")"})
			}
		}
	}
	// Google Drive 文件流：默认挂在 G:、H: 盘符（用户可改）
	for _, drive := range []string{"G:\\", "H:\\", "I:\\", "J:\\"} {
		// Drive File Stream 的根目录里有 "我的云端硬盘" / "My Drive" 文件夹
		myDrive := filepath.Join(drive, "My Drive")
		out = append(out, CloudSyncRoot{ProviderGoogleDrive, myDrive,
			"Google Drive File Stream 挂载点 (" + drive + ")"})
		myDriveZH := filepath.Join(drive, "我的云端硬盘")
		out = append(out, CloudSyncRoot{ProviderGoogleDrive, myDriveZH,
			"Google Drive File Stream 挂载点 (中文 UI, " + drive + ")"})
	}
	return out
}

func linuxCandidates(home string) []CloudSyncRoot {
	return []CloudSyncRoot{
		{ProviderNextcloud, filepath.Join(home, "Nextcloud"), "Nextcloud 桌面客户端默认路径"},
		{ProviderDropbox, filepath.Join(home, "Dropbox"), "Dropbox Linux 桌面版默认路径"},
		{ProviderMega, filepath.Join(home, "MEGA"), "MEGAsync Linux 默认路径"},
		// google-drive-ocamlfuse / rclone 挂载
		{ProviderGoogleDrive, filepath.Join(home, "GoogleDrive"), "rclone/google-drive-ocamlfuse 常用挂载点"},
	}
}

// CloudBackupHit 表示在某个云同步根下发现的具体备份
type CloudBackupHit struct {
	Provider    CloudProvider
	BackupKind  string // "iOS-MobileSync" / "Android-AB" / "Other"
	Path        string // 备份文件 / 目录的绝对路径
	SizeBytes   int64
	CloudRoot   string // 它所在的同步根目录（用户可读"它在 OneDrive 里"）
	Description string
}

// FindBackupsInCloudRoots 遍历所有云同步根，找其中的 iOS/Android 备份。
//
// 启发式（保守 + 高精度，不出 false positive 给用户）：
//
//	iOS 备份：找名为 Manifest.plist 的文件 → 父目录是 backup root
//	Android 备份：找扩展名 .ab 的文件，且头部 4 字节 = "ANDROID BACKUP"
//	             （文件起头 "ANDROID BACKUP\n" 是 .ab 格式 magic）
//
// maxDepth 防止深递归（5 层够找正常云盘里的备份）
func FindBackupsInCloudRoots(roots []CloudSyncRoot, maxDepth int) []CloudBackupHit {
	if maxDepth <= 0 {
		maxDepth = 5
	}
	var hits []CloudBackupHit
	for _, root := range roots {
		_ = filepath.WalkDir(root.Path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // 权限错误跳过
			}
			// depth 控制
			rel, _ := filepath.Rel(root.Path, p)
			if depth(rel) > maxDepth {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			lower := strings.ToLower(name)

			// iOS：Manifest.plist 在 backup root 里
			if !d.IsDir() && lower == "manifest.plist" {
				parent := filepath.Dir(p)
				st, _ := os.Stat(parent)
				size := dirSize(parent, 3) // 浅扫子目录大小
				_ = st
				hits = append(hits, CloudBackupHit{
					Provider: root.Provider, BackupKind: "iOS-MobileSync",
					Path: parent, SizeBytes: size, CloudRoot: root.Path,
					Description: "iOS MobileSync 备份目录（含 Manifest.plist）",
				})
				return filepath.SkipDir // 不深入这个 backup
			}
			// Android .ab
			if !d.IsDir() && strings.HasSuffix(lower, ".ab") {
				if isAndroidBackup(p) {
					info, _ := d.Info()
					var sz int64
					if info != nil {
						sz = info.Size()
					}
					hits = append(hits, CloudBackupHit{
						Provider: root.Provider, BackupKind: "Android-AB",
						Path: p, SizeBytes: sz, CloudRoot: root.Path,
						Description: "Android adb backup 文件 (.ab，magic OK)",
					})
				}
			}
			return nil
		})
	}
	return hits
}

// depth 返回相对路径里的层数（"a/b/c" → 2 个分隔符 → depth 3）
func depth(rel string) int {
	if rel == "" || rel == "." {
		return 0
	}
	d := 1
	for _, c := range rel {
		if c == filepath.Separator {
			d++
		}
	}
	return d
}

// isAndroidBackup 检查文件首 16 字节是否是 "ANDROID BACKUP\n"
func isAndroidBackup(path string) bool {
	f, err := os.Open(path) // #nosec G304 — 工具核心功能：扫用户指定路径
	if err != nil {
		return false
	}
	defer f.Close()
	var buf [16]byte
	n, _ := f.Read(buf[:])
	if n < 15 {
		return false
	}
	return string(buf[:15]) == "ANDROID BACKUP\n"
}

// dirSize 浅算目录字节数（最多深 maxDepth 层，避免深递归慢）
func dirSize(root string, maxDepth int) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if depth(rel) > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			info, _ := d.Info()
			if info != nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}
