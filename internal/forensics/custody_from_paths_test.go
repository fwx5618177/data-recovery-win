package forensics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuildAndWriteFromPaths_OnlyHashesProvidedFiles 锁住 v2.8.30 的本质修复：
//
// v2.8.21 用户报"恢复进度跑完之后依然在读取磁盘"——根因是 post-recovery 自动
// 跑 BuildAndWrite(outputDir) 会 filepath.Walk(outputDir) + 每个文件 SHA256。
// 用户的 outputDir 经常是 C:\ 或者盘根目录，整盘几十 GB 都被 hash 一遍，
// 磁盘 IO 持续几分钟到几小时。
//
// v2.8.30: BuildAndWriteFromPaths 只 hash 显式提供的文件列表，不 walk 任何目录。
//
// 测试做法：
//  1. 在临时目录里造 2 个"恢复出来的文件" + 1 个"无关大文件"（模拟 outputDir 里
//     恰好有用户其它的 100GB 视频之类）
//  2. 调 BuildAndWriteFromPaths 只传 2 个恢复文件的路径
//  3. 断言 custody.json 里 outputFiles 只有 2 条，不含那个"无关大文件"
//
// 如果将来谁不小心把 post-recovery 切回 walk 模式，"无关大文件"会出现在 manifest 里
// 让这个测试 fail，磁盘 IO 噩梦的回归就被钉死了。
func TestBuildAndWriteFromPaths_OnlyHashesProvidedFiles(t *testing.T) {
	dir := t.TempDir()

	// 2 个恢复文件
	recA := filepath.Join(dir, "recovered_a.jpg")
	recB := filepath.Join(dir, "subdir", "recovered_b.png")
	_ = os.MkdirAll(filepath.Dir(recB), 0o755)
	if err := os.WriteFile(recA, []byte("fake-a"), 0o644); err != nil {
		t.Fatalf("write A: %v", err)
	}
	if err := os.WriteFile(recB, []byte("fake-b-content"), 0o644); err != nil {
		t.Fatalf("write B: %v", err)
	}

	// 1 个"无关大文件"——模拟用户 C:\ 目录里恰好有自己的视频之类的，**不该**被 hash
	unrelated := filepath.Join(dir, "user_own_video.mp4")
	if err := os.WriteFile(unrelated, []byte("100GB-of-data-fake"), 0o644); err != nil {
		t.Fatalf("write unrelated: %v", err)
	}

	custody := Custody{
		ToolName:     "DataRecovery",
		ToolVersion:  "test",
		SourceDevice: "\\\\.\\PhysicalDrive0",
		StartedAt:    time.Now().UTC(),
	}

	manifestPath, err := BuildAndWriteFromPaths(dir, custody, []string{recA, recB})
	if err != nil {
		t.Fatalf("BuildAndWriteFromPaths: %v", err)
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var manifest Custody
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// 必须正好 2 条记录 —— 不含 user_own_video.mp4
	if len(manifest.OutputFiles) != 2 {
		t.Fatalf("outputFiles 长度应为 2，实际 %d。如果含 user_own_video.mp4 说明 walk 模式回归了！\n%s",
			len(manifest.OutputFiles), string(raw))
	}
	for _, f := range manifest.OutputFiles {
		if strings.Contains(f.Path, "user_own_video.mp4") {
			t.Errorf("无关文件 %q 不该出现在 manifest —— v2.8.21 磁盘 IO 噩梦回归了！", f.Path)
		}
	}

	// manifest 自身的 sha256 必须被算好
	if manifest.ManifestSHA256 == "" {
		t.Error("manifest.ManifestSHA256 应该被自动算好")
	}
}

// TestBuildAndWriteFromPaths_EmptyPathsStillWritesManifest 验证恢复 0 个文件
// 也能写成功（manifest 含元数据但 outputFiles 为空）。
func TestBuildAndWriteFromPaths_EmptyPathsStillWritesManifest(t *testing.T) {
	dir := t.TempDir()
	custody := Custody{ToolName: "DR", ToolVersion: "test"}
	manifestPath, err := BuildAndWriteFromPaths(dir, custody, nil)
	if err != nil {
		t.Fatalf("空路径列表也应成功，实际 err: %v", err)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Errorf("manifest 没真落地: %v", err)
	}
}

// TestBuildAndWriteFromPaths_SkipsMissingFiles 个别文件已被删/不存在不阻塞流程。
func TestBuildAndWriteFromPaths_SkipsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "ok.txt")
	if err := os.WriteFile(existing, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "does-not-exist.txt")

	manifestPath, err := BuildAndWriteFromPaths(dir, Custody{ToolName: "DR"}, []string{existing, missing})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	raw, _ := os.ReadFile(manifestPath)
	var m Custody
	_ = json.Unmarshal(raw, &m)
	if len(m.OutputFiles) != 1 {
		t.Errorf("应有 1 条记录（存在的那个），实际 %d", len(m.OutputFiles))
	}
}
