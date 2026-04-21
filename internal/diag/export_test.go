package diag

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExport_WritesExpectedZipContents(t *testing.T) {
	tmp := t.TempDir()
	logDir := filepath.Join(tmp, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 日志：一个 .log 合法，一个 .bin 非法（应被过滤掉）
	if err := os.WriteFile(filepath.Join(logDir, "app.log"), []byte("hello log"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "secret.bin"), []byte("DO NOT EXPORT"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Session snapshot
	sessPath := filepath.Join(tmp, "session.json")
	if err := os.WriteFile(sessPath, []byte(`{"files":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	destDir := filepath.Join(tmp, "out")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	zipPath, err := Export(Options{
		DestPath:    destDir,
		AppVersion:  "v9.9.9",
		LogDir:      logDir,
		SessionFile: sessPath,
		ExtraNotes:  "this is a test",
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if !strings.HasSuffix(zipPath, ".zip") {
		t.Errorf("zip 扩展名错: %s", zipPath)
	}

	// 校验 zip 内容
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()

	names := make(map[string]bool)
	for _, f := range r.File {
		names[f.Name] = true
	}
	// 必含的
	for _, want := range []string{"logs/app.log", "session/snapshot.json", "metadata.json"} {
		if !names[want] {
			t.Errorf("缺失 %s", want)
		}
	}
	// 必不含的（非白名单扩展名）
	for _, bad := range []string{"logs/secret.bin"} {
		if names[bad] {
			t.Errorf("不应包含 %s", bad)
		}
	}

	// metadata.json 内容正确
	for _, f := range r.File {
		if f.Name != "metadata.json" {
			continue
		}
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		var md Metadata
		if err := json.Unmarshal(data, &md); err != nil {
			t.Fatalf("metadata.json 解析失败: %v", err)
		}
		if md.AppVersion != "v9.9.9" {
			t.Errorf("AppVersion 错: %s", md.AppVersion)
		}
		if md.ExtraNotes != "this is a test" {
			t.Errorf("ExtraNotes 错: %s", md.ExtraNotes)
		}
		if len(md.LogFiles) != 1 || md.LogFiles[0] != "app.log" {
			t.Errorf("LogFiles 错: %v", md.LogFiles)
		}
	}
}

func TestExport_ExplicitDestPath(t *testing.T) {
	tmp := t.TempDir()
	dest := filepath.Join(tmp, "mybundle.zip")
	got, err := Export(Options{DestPath: dest})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got != dest {
		t.Errorf("DestPath 不是目录时应当作完整路径: got %s want %s", got, dest)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("zip 未创建: %v", err)
	}
}
