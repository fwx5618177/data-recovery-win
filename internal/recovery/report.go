package recovery

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"data-recovery/internal/types"
)

// ExportReportCSV 把一次恢复的每文件记录写成 CSV 文件，便于用户事后核对。
// path 必须是用户可写的目录；真正的文件名由本函数决定，带时间戳避免覆盖。
// 返回最终落地的文件绝对路径。
func ExportReportCSV(records []*FileRecoveryRecord, dir string) (string, error) {
	if len(records) == 0 {
		return "", fmt.Errorf("没有可导出的恢复记录")
	}
	if dir == "" {
		return "", fmt.Errorf("导出目录为空")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建导出目录失败: %w", err)
	}

	filename := fmt.Sprintf("recovery-report-%s.csv", time.Now().Format("20060102-150405"))
	fullPath := filepath.Join(dir, filename)

	f, err := os.Create(fullPath)
	if err != nil {
		return "", fmt.Errorf("创建报告文件失败: %w", err)
	}
	defer f.Close()

	// UTF-8 BOM，让 Windows Excel 打开时中文不乱码
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return "", fmt.Errorf("写入 BOM 失败: %w", err)
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"file_id", "file_name", "category", "size_bytes", "size_human",
		"state", "output_path", "message", "duration_ms", "completed_at"}
	if err := w.Write(header); err != nil {
		return "", fmt.Errorf("写入 CSV 头失败: %w", err)
	}

	for _, r := range records {
		row := []string{
			r.FileID,
			r.FileName,
			r.Category,
			strconv.FormatInt(r.Size, 10),
			r.SizeHuman,
			string(r.State),
			r.OutputPath,
			r.Message,
			strconv.FormatInt(r.DurationMs, 10),
			r.CompletedAt.Format(time.RFC3339),
		}
		if err := w.Write(row); err != nil {
			return "", fmt.Errorf("写入 CSV 行失败: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("CSV flush 失败: %w", err)
	}
	return fullPath, nil
}

// ManifestEntry 是 manifest.json 中每个文件的完整元数据记录。
//
// 字段比 CSV 报告更全，面向机读消费（外部取证脚本 / 回归对比 / 批量重扫）。
// 对齐 PhotoRec 的 photorec.log 与 R-Studio 的 recovery_report 的覆盖面。
type ManifestEntry struct {
	FileID        string            `json:"fileId"`
	FileName      string            `json:"fileName"`
	Extension     string            `json:"extension"`
	Category      string            `json:"category"`
	Source        string            `json:"source"` // ntfs / carver
	Size          int64             `json:"size"`
	SizeHuman     string            `json:"sizeHuman"`
	Offset        int64             `json:"offset"`
	OffsetHex     string            `json:"offsetHex"`
	Confidence    float64           `json:"confidence"`
	IsValid       bool              `json:"isValid"`
	ValidationMsg string            `json:"validationMsg,omitempty"`
	SHA256        string            `json:"sha256,omitempty"`
	OriginalPath  string            `json:"originalPath,omitempty"`
	IsDeleted     bool              `json:"isDeleted,omitempty"`
	CreatedTime   *time.Time        `json:"createdTime,omitempty"`
	ModifiedTime  *time.Time        `json:"modifiedTime,omitempty"`
	OutputPath    string            `json:"outputPath,omitempty"`
	State         FileRecoveryState `json:"state"`
	Message       string            `json:"message,omitempty"`
	CompletedAt   time.Time         `json:"completedAt"`
}

// Manifest 是 manifest.json 的顶层结构。
type Manifest struct {
	SchemaVersion string           `json:"schemaVersion"`
	GeneratedAt   time.Time        `json:"generatedAt"`
	Summary       ManifestSummary  `json:"summary"`
	Files         []*ManifestEntry `json:"files"`
}

// ManifestSummary 恢复结果的快速概览，便于脚本在不解析 files 的情况下判断成功率。
type ManifestSummary struct {
	Total      int `json:"total"`
	Success    int `json:"success"`
	Partial    int `json:"partial"`
	Failed     int `json:"failed"`
	Duplicates int `json:"duplicates"`
	Skipped    int `json:"skipped"`
}

// ExportManifestJSON 把每文件记录 + 原始 RecoveredFile 元数据合并成一份 manifest.json。
// dir 必须是用户可写目录，文件名固定为 manifest.json；已存在则覆盖（每次恢复以最新为准）。
// 返回最终 manifest 的绝对路径。
func ExportManifestJSON(records []*FileRecoveryRecord, files []*types.RecoveredFile, dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("导出目录为空")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建导出目录失败: %w", err)
	}

	// 以 FileID 索引原始文件元数据
	fileByID := make(map[string]*types.RecoveredFile, len(files))
	for _, f := range files {
		if f == nil {
			continue
		}
		fileByID[f.ID] = f
	}

	entries := make([]*ManifestEntry, 0, len(records))
	summary := ManifestSummary{Total: len(records)}

	for _, r := range records {
		if r == nil {
			continue
		}

		entry := &ManifestEntry{
			FileID:      r.FileID,
			FileName:    r.FileName,
			Category:    r.Category,
			Size:        r.Size,
			SizeHuman:   r.SizeHuman,
			State:       r.State,
			Message:     r.Message,
			OutputPath:  r.OutputPath,
			CompletedAt: r.CompletedAt,
		}

		if f := fileByID[r.FileID]; f != nil {
			entry.Extension = f.Extension
			entry.Source = f.Source
			entry.Offset = f.Offset
			entry.OffsetHex = fmt.Sprintf("0x%x", f.Offset)
			entry.Confidence = f.Confidence
			entry.IsValid = f.IsValid
			entry.ValidationMsg = f.ValidationMsg
			entry.SHA256 = f.SHA256
			entry.OriginalPath = f.OriginalPath
			entry.IsDeleted = f.IsDeleted
			entry.CreatedTime = f.CreatedTime
			entry.ModifiedTime = f.ModifiedTime
		}

		switch r.State {
		case RecoveryStateSuccess:
			summary.Success++
		case RecoveryStatePartial:
			summary.Partial++
		case RecoveryStateFailed:
			summary.Failed++
		case RecoveryStateSkipped:
			// 跨源去重与低置信度跳过都记在这里；从 Message 里可以进一步区分
			summary.Skipped++
			if r.Message != "" && containsCaseInsensitive(r.Message, "重复") {
				summary.Duplicates++
			}
		}

		entries = append(entries, entry)
	}

	manifest := Manifest{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now(),
		Summary:       summary,
		Files:         entries,
	}

	fullPath := filepath.Join(dir, "manifest.json")
	f, err := os.Create(fullPath)
	if err != nil {
		return "", fmt.Errorf("创建 manifest 文件失败: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		return "", fmt.Errorf("写入 manifest 失败: %w", err)
	}
	return fullPath, nil
}

// containsCaseInsensitive 判断 substr 是否以大小写不敏感方式出现在 s 中。
// 仅用于简单关键词识别（如"重复"），不做 Unicode 归一化。
func containsCaseInsensitive(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	// 对中文直接比较即可；这里主要处理英文大小写
	lower := []byte(s)
	target := []byte(substr)
	for i := range lower {
		if lower[i] >= 'A' && lower[i] <= 'Z' {
			lower[i] += 'a' - 'A'
		}
	}
	for i := range target {
		if target[i] >= 'A' && target[i] <= 'Z' {
			target[i] += 'a' - 'A'
		}
	}
	for i := 0; i+len(target) <= len(lower); i++ {
		match := true
		for j := range target {
			if lower[i+j] != target[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
