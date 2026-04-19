package recovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"data-recovery/internal/types"
)

func TestExportManifestJSON_WritesValidSchema(t *testing.T) {
	dir := t.TempDir()

	mt := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	files := []*types.RecoveredFile{
		{
			ID:           "ntfs_0_42",
			Source:       "ntfs",
			FileName:     "report.docx",
			Extension:    "docx",
			Category:     types.CategoryDocument,
			Size:         1024,
			SizeHuman:    "1 KB",
			Offset:       4096,
			Confidence:   0.95,
			IsValid:      true,
			SHA256:       strings.Repeat("a", 64),
			OriginalPath: "Users/Alice/Documents/report.docx",
			ModifiedTime: &mt,
		},
		{
			ID:        "carve_8192",
			Source:    "carver",
			FileName:  "jpg_0x2000_000001.jpg",
			Extension: "jpg",
			Category:  types.CategoryImage,
			Size:      2048,
			Offset:    0x2000,
			SHA256:    strings.Repeat("b", 64),
			IsValid:   true,
		},
	}
	records := []*FileRecoveryRecord{
		{FileID: "ntfs_0_42", FileName: "report.docx", Size: 1024, SizeHuman: "1 KB",
			Category: "document", State: RecoveryStateSuccess, OutputPath: "/out/ntfs/.../report.docx",
			CompletedAt: mt},
		{FileID: "carve_8192", FileName: "jpg_0x2000_000001.jpg", Size: 2048,
			Category: "image", State: RecoveryStateSuccess, OutputPath: "/out/carver/.../f.jpg",
			CompletedAt: mt},
	}

	path, err := ExportManifestJSON(records, files, dir)
	if err != nil {
		t.Fatalf("ExportManifestJSON 失败: %v", err)
	}
	if filepath.Base(path) != "manifest.json" {
		t.Errorf("manifest 文件名应为 manifest.json，实际 %s", filepath.Base(path))
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 manifest 失败: %v", err)
	}

	var got Manifest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("manifest 不是合法 JSON: %v", err)
	}

	if got.SchemaVersion == "" {
		t.Error("schemaVersion 不应为空")
	}
	if got.Summary.Total != 2 || got.Summary.Success != 2 {
		t.Errorf("summary 计数错: %+v", got.Summary)
	}
	if len(got.Files) != 2 {
		t.Fatalf("files 数量错: got %d want 2", len(got.Files))
	}

	// 字段展开：offsetHex / sha256 / originalPath 都应写入
	ntfsEntry := got.Files[0]
	if ntfsEntry.OffsetHex != "0x1000" {
		t.Errorf("offsetHex 期望 0x1000，实际 %s", ntfsEntry.OffsetHex)
	}
	if ntfsEntry.SHA256 != strings.Repeat("a", 64) {
		t.Errorf("SHA256 未正确回填: %s", ntfsEntry.SHA256)
	}
	if ntfsEntry.OriginalPath == "" {
		t.Error("NTFS 条目应保留 OriginalPath")
	}
	if ntfsEntry.ModifiedTime == nil || !ntfsEntry.ModifiedTime.Equal(mt) {
		t.Errorf("ModifiedTime 未透传: %v", ntfsEntry.ModifiedTime)
	}
}

func TestExportManifestJSON_CountsDuplicatesInSummary(t *testing.T) {
	dir := t.TempDir()

	files := []*types.RecoveredFile{
		{ID: "a", Source: "ntfs", Extension: "png"},
		{ID: "b", Source: "carver", Extension: "png"},
	}
	records := []*FileRecoveryRecord{
		{FileID: "a", State: RecoveryStateSuccess, CompletedAt: time.Now()},
		{FileID: "b", State: RecoveryStateSkipped,
			Message: "与已恢复文件内容重复 (SHA256=abc...)", CompletedAt: time.Now()},
	}

	path, err := ExportManifestJSON(records, files, dir)
	if err != nil {
		t.Fatalf("ExportManifestJSON 失败: %v", err)
	}

	raw, _ := os.ReadFile(path)
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析 manifest 失败: %v", err)
	}

	if m.Summary.Success != 1 {
		t.Errorf("Summary.Success 期望 1，实际 %d", m.Summary.Success)
	}
	if m.Summary.Skipped != 1 {
		t.Errorf("Summary.Skipped 期望 1，实际 %d", m.Summary.Skipped)
	}
	if m.Summary.Duplicates != 1 {
		t.Errorf("Summary.Duplicates 期望 1 (由'重复'关键词识别)，实际 %d", m.Summary.Duplicates)
	}
}

func TestExportManifestJSON_EmptyDirErrors(t *testing.T) {
	if _, err := ExportManifestJSON(nil, nil, ""); err == nil {
		t.Error("空目录应返回错误")
	}
}

func TestExportManifestJSON_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	// 先写一份旧 manifest
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("stale"), 0o644); err != nil {
		t.Fatalf("预写旧 manifest 失败: %v", err)
	}

	files := []*types.RecoveredFile{{ID: "x", Source: "carver", Extension: "png"}}
	records := []*FileRecoveryRecord{
		{FileID: "x", State: RecoveryStateSuccess, CompletedAt: time.Now()},
	}
	if _, err := ExportManifestJSON(records, files, dir); err != nil {
		t.Fatalf("导出失败: %v", err)
	}

	raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if string(raw) == "stale" {
		t.Error("旧 manifest 应被覆盖")
	}
	// 覆盖后应是合法 JSON
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Errorf("覆盖后 manifest 不是合法 JSON: %v", err)
	}
}
