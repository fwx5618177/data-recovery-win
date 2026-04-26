package forensics

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"data-recovery/internal/ios"
)

// custodyToValue + EncodePlist + ParsePlist round-trip：所有字段保留
func TestWriteCustodyPlist_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// 在 dir 里塞两个文件，让 BuildAndWrite 真的能算出 outputFiles
	mustWrite := func(name string, content []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("a.txt", []byte("aaaa"))
	mustWrite("b.bin", []byte{1, 2, 3, 4, 5})

	c := Custody{
		ToolName:     "DataRecoveryMaster",
		ToolVersion:  "test-1.0",
		OperatorUser: "alice",
		StartedAt:    time.Date(2026, 4, 26, 10, 0, 0, 0, time.UTC),
		SourceDevice: "/dev/null",
		SourceSize:   1024,
		SourceSHA256: "deadbeef",
	}

	if _, err := BuildAndWrite(dir, c); err != nil {
		t.Fatalf("BuildAndWrite: %v", err)
	}

	// 验证 custody.plist 存在且能被 ParsePlist 反向解析
	plistPath := filepath.Join(dir, "custody.plist")
	plistBytes, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("custody.plist 应存在: %v", err)
	}
	if !bytes.HasPrefix(plistBytes, []byte("bplist00")) {
		t.Fatalf("应是 bplist00 格式, head=%q", plistBytes[:8])
	}
	parsed, err := ios.ParsePlist(plistBytes)
	if err != nil {
		t.Fatalf("ParsePlist 反向: %v", err)
	}

	// 字段验证
	if parsed.GetString("toolName") != "DataRecoveryMaster" {
		t.Errorf("toolName 丢失")
	}
	if parsed.GetString("toolVersion") != "test-1.0" {
		t.Errorf("toolVersion 丢失")
	}
	if parsed.GetString("operatorUser") != "alice" {
		t.Errorf("operatorUser 丢失")
	}
	if parsed.GetString("sourceDevice") != "/dev/null" {
		t.Errorf("sourceDevice 丢失")
	}
	if size, ok := parsed.GetInt("sourceSize"); !ok || size != 1024 {
		t.Errorf("sourceSize = %d ok=%v", size, ok)
	}
	if parsed.GetString("sourceSHA256") != "deadbeef" {
		t.Errorf("sourceSHA256 丢失")
	}

	// outputFiles 数组：应有 a.txt + b.bin（custody.json 不算自己；但 plist 也不算）
	files := parsed.Dict["outputFiles"]
	if files == nil || files.Kind != ios.KindArray {
		t.Fatal("outputFiles 缺失")
	}
	if len(files.Array) < 2 {
		t.Errorf("outputFiles 数 < 2, got %d", len(files.Array))
	}

	// 每个 entry 应是 dict {path, size, sha256}
	for i, e := range files.Array {
		if e.Kind != ios.KindDict {
			t.Errorf("outputFiles[%d] 不是 dict", i)
			continue
		}
		if e.GetString("path") == "" {
			t.Errorf("outputFiles[%d] path 缺失", i)
		}
		if e.GetString("sha256") == "" {
			t.Errorf("outputFiles[%d] sha256 缺失", i)
		}
		if size, ok := e.GetInt("size"); !ok || size <= 0 {
			t.Errorf("outputFiles[%d] size 错: %d", i, size)
		}
	}

	// startedAt 是 KindDate
	d := parsed.Dict["startedAt"]
	if d == nil || d.Kind != ios.KindDate {
		t.Fatal("startedAt 缺失或类型错")
	}
	if d.Time.Year() != 2026 {
		t.Errorf("startedAt year = %d", d.Time.Year())
	}

	// manifestSHA256 应非空（BuildAndWrite 算出来的）
	if parsed.GetString("manifestSHA256") == "" {
		t.Errorf("manifestSHA256 缺失")
	}
}

// 空 outputDir 拒绝
func TestWriteCustodyPlist_RejectsEmptyDir(t *testing.T) {
	if _, err := WriteCustodyPlist("", Custody{}); err == nil {
		t.Errorf("空 outputDir 应拒绝")
	}
}
