package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"data-recovery/internal/recovery"
)

// TestBuildCustody_OnlyHashesRecoveredFiles 锁住 v2.8.39 的本质修复：
//
// 用户截图：刚恢复 1 个文件，手动点 "🛡 生成保管链 (custody.json)" 工具，
// 进程开始大量读取 outputDir 下所有 MP4 文件 —— 因为 BuildCustody 之前
// 调的是 forensics.BuildAndWrite，里头 filepath.Walk(outputDir) 走整个目录。
//
// v2.8.39 fix：BuildCustody 先看 engine.GetLastRecoveryResult()，有记录就只
// hash 那些 OutputPath，不再 walk。这个测试在 outputDir 里放 1 个"恢复出来的
// 文件" + 1 个"无关大文件"，期望 custody.json 里只见前者，证明没 walk。
func TestBuildCustody_OnlyHashesRecoveredFiles(t *testing.T) {
	dir := t.TempDir()

	recovered := filepath.Join(dir, "recovered.bin")
	if err := os.WriteFile(recovered, []byte("real recovered data"), 0o600); err != nil {
		t.Fatalf("write recovered: %v", err)
	}
	// 模拟 outputDir 里"碰巧有用户另外的大量文件"（截图里那堆 MP4）
	junk := filepath.Join(dir, "junk_user_video.mp4")
	if err := os.WriteFile(junk, []byte("不该被 hash 的大文件占位"), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}

	app := &App{engine: recovery.NewEngine()}
	defer app.engine.Shutdown()

	// 注入"上次恢复记录"：只 1 条，指向 recovered.bin
	app.engine.SetLastRecoveryForTesting([]*recovery.FileRecoveryRecord{
		{
			FileID:     "id-1",
			State:      recovery.RecoveryStateSuccess,
			OutputPath: recovered,
		},
	})

	manifestPath, err := app.BuildCustody(dir, "FakeDevice", "tester")
	if err != nil {
		t.Fatalf("BuildCustody err: %v", err)
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest 解析失败: %v\n内容: %s", err, data)
	}

	// 把 manifest 转字符串，直接 grep 路径名 —— 比深入 json 结构稳
	body := string(data)
	if !strings.Contains(body, "recovered.bin") {
		t.Errorf("manifest 缺 recovered.bin（应该被 hash）：%s", body)
	}
	if strings.Contains(body, "junk_user_video.mp4") {
		t.Errorf("manifest 不该含 junk_user_video.mp4（说明 BuildCustody 又开始 walk outputDir 了，"+
			"这是 v2.8.21 用户报 'IO 不停' 的旧 bug 回归）：\n%s", body)
	}
}

// TestBuildCustody_NoRecordsFallsBackToWalk 没有 lastRecovery 时（用户独立用
// 本工具），回退到 BuildAndWrite walk 整个 dir —— 这是合理的 fallback，
// 不能因为 fix 把"独立模式"也搞坏了。
func TestBuildCustody_NoRecordsFallsBackToWalk(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	app := &App{engine: recovery.NewEngine()}
	defer app.engine.Shutdown()
	// 不注入任何 record → lastRecovery 为空 → 走 fallback

	manifestPath, err := app.BuildCustody(dir, "FakeDevice", "tester")
	if err != nil {
		t.Fatalf("BuildCustody err: %v", err)
	}
	data, _ := os.ReadFile(manifestPath)
	body := string(data)
	// fallback 应该 walk 整个 dir，两个 .txt 都进去
	if !strings.Contains(body, "a.txt") || !strings.Contains(body, "b.txt") {
		t.Errorf("没有 lastRecovery 时 fallback 应 walk 整个 dir 含 a.txt+b.txt：\n%s", body)
	}
}
