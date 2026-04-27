package backup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// 调用真实环境，只做"不 panic + 返回结构合法"测试
func TestDiscoverCloudSyncRoots_NoPanic(t *testing.T) {
	roots := DiscoverCloudSyncRoots()
	for _, r := range roots {
		if r.Path == "" {
			t.Errorf("空 path: %+v", r)
		}
		if r.Provider == "" {
			t.Errorf("空 Provider: %+v", r)
		}
		// 路径必须真实存在（DiscoverCloudSyncRoots 已过滤）
		st, err := os.Stat(r.Path)
		if err != nil || !st.IsDir() {
			t.Errorf("path 不是目录: %s", r.Path)
		}
	}
	t.Logf("发现 %d 个云同步根:", len(roots))
	for _, r := range roots {
		t.Logf("  [%s] %s — %s", r.Provider, r.Path, r.Reason)
	}
}

// 测 isAndroidBackup magic 检测
func TestIsAndroidBackup(t *testing.T) {
	tmp := t.TempDir()

	// 真 magic
	good := filepath.Join(tmp, "good.ab")
	os.WriteFile(good, []byte("ANDROID BACKUP\n5\n0\nnone\n"), 0644)
	if !isAndroidBackup(good) {
		t.Error("合法 .ab magic 没识别")
	}

	// 假 magic
	bad := filepath.Join(tmp, "bad.ab")
	os.WriteFile(bad, []byte("not an android backup at all"), 0644)
	if isAndroidBackup(bad) {
		t.Error("非法 .ab 错认")
	}

	// 太短
	tiny := filepath.Join(tmp, "tiny.ab")
	os.WriteFile(tiny, []byte("ANDROID"), 0644)
	if isAndroidBackup(tiny) {
		t.Error("太短文件错认")
	}
}

// 模拟一个云同步根，里面塞 iOS MobileSync 目录 + Android .ab，
// 验证 FindBackupsInCloudRoots 都能找到
func TestFindBackupsInCloudRoots_FindsBoth(t *testing.T) {
	tmp := t.TempDir()
	cloudRoot := filepath.Join(tmp, "FakeCloud")
	if err := os.MkdirAll(cloudRoot, 0755); err != nil {
		t.Fatal(err)
	}

	// 1. 假 iOS backup
	iosDir := filepath.Join(cloudRoot, "Backups", "iPhone-12345")
	os.MkdirAll(iosDir, 0755)
	os.WriteFile(filepath.Join(iosDir, "Manifest.plist"), []byte("<plist></plist>"), 0644)
	os.WriteFile(filepath.Join(iosDir, "Info.plist"), []byte("<plist></plist>"), 0644)
	// 一个文件防止 dirSize=0
	os.WriteFile(filepath.Join(iosDir, "00", "00", "0000abcd"), []byte("xxxxxxxxx"), 0644)
	os.MkdirAll(filepath.Join(iosDir, "00"), 0755)

	// 2. 假 Android .ab
	androidPath := filepath.Join(cloudRoot, "AndroidBackups", "phone-2024.ab")
	os.MkdirAll(filepath.Dir(androidPath), 0755)
	os.WriteFile(androidPath, []byte("ANDROID BACKUP\n5\n0\nnone\nbinarydata"), 0644)

	// 3. 一个不是 backup 的文件，不应被识别
	os.WriteFile(filepath.Join(cloudRoot, "random.txt"), []byte("random"), 0644)

	roots := []CloudSyncRoot{
		{Provider: ProviderOneDrive, Path: cloudRoot, Reason: "test"},
	}
	hits := FindBackupsInCloudRoots(roots, 5)

	var iosHits, androidHits int
	for _, h := range hits {
		switch h.BackupKind {
		case "iOS-MobileSync":
			iosHits++
			if h.Path != iosDir {
				t.Errorf("iOS path: got %s want %s", h.Path, iosDir)
			}
		case "Android-AB":
			androidHits++
			if h.Path != androidPath {
				t.Errorf("Android path: got %s want %s", h.Path, androidPath)
			}
		}
		if h.CloudRoot != cloudRoot {
			t.Errorf("CloudRoot: got %s want %s", h.CloudRoot, cloudRoot)
		}
		if h.Provider != ProviderOneDrive {
			t.Errorf("Provider: got %s want OneDrive", h.Provider)
		}
	}
	if iosHits != 1 {
		t.Errorf("iOS hits: got %d want 1", iosHits)
	}
	if androidHits != 1 {
		t.Errorf("Android hits: got %d want 1", androidHits)
	}
}

// macOS 上至少应能找到 iCloud Drive 路径（如果 user 启用了 iCloud）
func TestDiscoverCloudSyncRoots_macOS_iCloud(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("仅 macOS")
	}
	home, _ := os.UserHomeDir()
	icloudPath := filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs")
	if _, err := os.Stat(icloudPath); err != nil {
		t.Skipf("用户没启用 iCloud Drive (%v)", err)
	}
	roots := DiscoverCloudSyncRoots()
	found := false
	for _, r := range roots {
		if r.Provider == ProviderICloud && r.Path == icloudPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("用户启用了 iCloud 但没发现")
	}
}
