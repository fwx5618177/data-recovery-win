package recovery

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"data-recovery/internal/disk"
	"data-recovery/internal/ntfs"
	"data-recovery/internal/types"
)

// SafeWriter 安全文件写入器 — 确保恢复的文件正确写入磁盘
type SafeWriter struct {
	reader    disk.DiskReader
	outputDir string
	bufSize   int // 写入缓冲大小，默认 4MB
}

// PartialWriteError 表示文件已导出，但仅恢复了部分内容。
type PartialWriteError struct {
	OutputPath string
	Expected   int64
	Written    int64
}

func (e *PartialWriteError) Error() string {
	return fmt.Sprintf(
		"文件仅恢复了部分内容: %s（期望 %d 字节，实际 %d 字节）",
		e.OutputPath,
		e.Expected,
		e.Written,
	)
}

// NewSafeWriter 创建安全文件写入器
func NewSafeWriter(reader disk.DiskReader, outputDir string) *SafeWriter {
	return &SafeWriter{
		reader:    reader,
		outputDir: outputDir,
		bufSize:   4 * 1024 * 1024, // 4MB
	}
}

// WriteFile 安全写入恢复的文件（基于偏移量的通用方式）
//
// 流程:
//  1. 创建目标目录
//  2. 创建临时文件 (.tmp)
//  3. 分块从磁盘读取数据并写入，同时计算 SHA256
//  4. 验证写入大小
//  5. 重命名临时文件为目标文件
//  6. 重新读取目标文件计算 SHA256，与写入时的对比
//  7. 校验失败则删除文件并返回错误
func (w *SafeWriter) WriteFile(file *types.RecoveredFile, outputPath string) error {
	if file == nil {
		return fmt.Errorf("文件信息为空")
	}
	if file.Size <= 0 {
		return fmt.Errorf("文件大小无效: %d", file.Size)
	}

	// 1. 创建目标目录
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败 [%s]: %w", dir, err)
	}

	// 2. 创建临时文件
	tmpPath := outputPath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("创建临时文件失败 [%s]: %w", tmpPath, err)
	}

	// 确保异常退出时清理临时文件
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	// 3. 分块从磁盘读取数据并写入，同时计算 SHA256
	writeHasher := sha256.New()
	buf := make([]byte, w.bufSize)
	remaining := file.Size
	currentOffset := file.Offset
	totalWritten := int64(0)

	for remaining > 0 {
		readSize := int64(w.bufSize)
		if readSize > remaining {
			readSize = remaining
		}

		n, err := w.reader.ReadAt(buf[:readSize], currentOffset)
		if err != nil && n == 0 {
			return fmt.Errorf("读取磁盘数据失败 (偏移: %d, 大小: %d): %w", currentOffset, readSize, err)
		}

		// 写入临时文件
		written, err := tmpFile.Write(buf[:n])
		if err != nil {
			return fmt.Errorf("写入临时文件失败: %w", err)
		}

		// 同时更新 SHA256
		writeHasher.Write(buf[:n])

		totalWritten += int64(written)
		currentOffset += int64(n)
		remaining -= int64(n)
	}

	// 刷新并关闭临时文件
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("刷新临时文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}

	// 4. 验证写入大小
	if totalWritten != file.Size {
		return fmt.Errorf("写入大小不匹配: 期望 %d 字节, 实际 %d 字节", file.Size, totalWritten)
	}

	writeSHA := writeHasher.Sum(nil)

	// 5. 重命名临时文件为目标文件
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return fmt.Errorf("重命名临时文件失败 [%s -> %s]: %w", tmpPath, outputPath, err)
	}
	cleanupTmp = false // 重命名成功，不再需要清理临时文件

	// 6. 重新读取目标文件计算 SHA256 验证数据完整性
	verifySHA, err := fileSHA256(outputPath)
	if err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("验证文件 SHA256 失败: %w", err)
	}

	// 7. 对比 SHA256
	if !sha256Equal(writeSHA, verifySHA) {
		os.Remove(outputPath)
		return fmt.Errorf("SHA256 校验失败: 写入=%x, 验证=%x — 数据可能损坏", writeSHA, verifySHA)
	}

	log.Printf("[SafeWriter] 文件写入成功: %s (%s, SHA256: %x)",
		outputPath, types.FormatSize(totalWritten), writeSHA[:8])
	return nil
}

// WriteNTFSFile 使用 NTFS MFT 条目的 DataRuns 恢复文件
//
// 对于 NTFS 恢复的文件，数据可能分散在多个 DataRun 中，
// 需要依次从每个 run 读取并拼接完整文件。
func (w *SafeWriter) WriteNTFSFile(
	file *types.RecoveredFile,
	entry *ntfs.MFTEntry,
	boot *ntfs.BootSector,
	partitionOffset int64,
	outputPath string,
) error {
	if file == nil || entry == nil || boot == nil {
		return fmt.Errorf("参数无效: file=%v, entry=%v, boot=%v", file != nil, entry != nil, boot != nil)
	}

	if entry.IsResident && len(entry.ResidentData) > 0 {
		return w.writeResidentFile(file, entry.ResidentData, outputPath)
	}

	if len(entry.DataRuns) == 0 {
		// 没有 DataRuns，回退到通用写入
		log.Printf("[SafeWriter] MFT 条目无 DataRuns，回退通用写入: %s", file.FileName)
		return w.WriteFile(file, outputPath)
	}

	// 创建目标目录
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败 [%s]: %w", dir, err)
	}

	// 创建临时文件
	tmpPath := outputPath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("创建临时文件失败 [%s]: %w", tmpPath, err)
	}

	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	writeHasher := sha256.New()
	buf := make([]byte, w.bufSize)
	totalWritten := int64(0)
	bytesPerCluster := int64(boot.BytesPerSector) * int64(boot.SectorsPerCluster)

	// 遍历 DataRuns，从每个 run 读取数据
	for _, run := range entry.DataRuns {
		// 计算此 run 在磁盘上的绝对偏移
		runOffset := partitionOffset + run.ClusterOffset*bytesPerCluster
		runLength := run.ClusterCount * bytesPerCluster

		// 如果已经写够了，停止（文件大小可能小于所有 run 的总大小）
		remaining := file.Size - totalWritten
		if remaining <= 0 {
			break
		}
		if runLength > remaining {
			runLength = remaining
		}

		// 分块读取此 run 的数据
		runRemaining := runLength
		runCurrentOffset := runOffset

		for runRemaining > 0 {
			readSize := int64(w.bufSize)
			if readSize > runRemaining {
				readSize = runRemaining
			}

			n, err := w.reader.ReadAt(buf[:readSize], runCurrentOffset)
			if err != nil && n == 0 {
				return fmt.Errorf("读取 DataRun 数据失败 (偏移: %d): %w", runCurrentOffset, err)
			}

			written, err := tmpFile.Write(buf[:n])
			if err != nil {
				return fmt.Errorf("写入临时文件失败: %w", err)
			}

			writeHasher.Write(buf[:n])

			totalWritten += int64(written)
			runCurrentOffset += int64(n)
			runRemaining -= int64(n)
		}
	}

	// 刷新并关闭临时文件
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("刷新临时文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}

	// 验证写入大小
	sizeMismatch := totalWritten != file.Size
	if totalWritten != file.Size {
		log.Printf("[SafeWriter] NTFS 文件大小不完全匹配: 期望 %d, 实际 %d (可能 DataRun 不完整)",
			file.Size, totalWritten)
	}

	writeSHA := writeHasher.Sum(nil)

	// 重命名临时文件为目标文件
	if err := os.Rename(tmpPath, outputPath); err != nil {
		return fmt.Errorf("重命名临时文件失败: %w", err)
	}
	cleanupTmp = false

	// SHA256 验证
	verifySHA, err := fileSHA256(outputPath)
	if err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("验证文件 SHA256 失败: %w", err)
	}

	if !sha256Equal(writeSHA, verifySHA) {
		os.Remove(outputPath)
		return fmt.Errorf("NTFS 文件 SHA256 校验失败: 写入=%x, 验证=%x", writeSHA, verifySHA)
	}

	log.Printf("[SafeWriter] NTFS 文件写入成功: %s (%s, SHA256: %x)",
		outputPath, types.FormatSize(totalWritten), writeSHA[:8])

	if sizeMismatch {
		return &PartialWriteError{
			OutputPath: outputPath,
			Expected:   file.Size,
			Written:    totalWritten,
		}
	}

	return nil
}

// GenerateOutputPath 生成输出文件路径
//
// 按分类创建子目录 (images/, documents/, videos/ 等)，
// 根据文件来源生成文件名，并处理冲突。
func (w *SafeWriter) GenerateOutputPath(file *types.RecoveredFile, baseDir string) string {
	var fullPath string
	if file.Source == "ntfs" {
		fullPath = filepath.Join(baseDir, "ntfs", buildNTFSRelativePath(file))
	} else {
		subDir := categoryToDir(file.Category)
		dir := filepath.Join(baseDir, subDir)

		// Carver 来源使用 recovered_{offset}.{ext} 格式
		ext := file.Extension
		if ext == "" {
			ext = "bin"
		}
		fileName := fmt.Sprintf("recovered_%d.%s", file.Offset, ext)
		fullPath = filepath.Join(dir, fileName)
	}

	// 处理文件名冲突
	fullPath = resolveConflict(fullPath)

	return fullPath
}

func (w *SafeWriter) writeResidentFile(file *types.RecoveredFile, data []byte, outputPath string) error {
	if len(data) == 0 {
		return fmt.Errorf("驻留数据为空")
	}

	expectedSize := int64(len(data))
	if file != nil && file.Size > 0 && file.Size < expectedSize {
		expectedSize = file.Size
		data = data[:int(expectedSize)]
	}

	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败 [%s]: %w", dir, err)
	}

	tmpPath := outputPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("写入驻留临时文件失败 [%s]: %w", tmpPath, err)
	}

	writeSHA := sha256.Sum256(data)
	if err := os.Rename(tmpPath, outputPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("重命名驻留临时文件失败 [%s -> %s]: %w", tmpPath, outputPath, err)
	}

	verifySHA, err := fileSHA256(outputPath)
	if err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("验证驻留文件 SHA256 失败: %w", err)
	}

	if !sha256Equal(writeSHA[:], verifySHA) {
		os.Remove(outputPath)
		return fmt.Errorf("驻留文件 SHA256 校验失败: 写入=%x, 验证=%x", writeSHA, verifySHA)
	}

	log.Printf("[SafeWriter] 驻留文件写入成功: %s (%s, SHA256: %x)",
		outputPath, types.FormatSize(expectedSize), writeSHA[:8])
	return nil
}

// ===================== 辅助函数 =====================

// sanitizeFilename 清理文件名，替换非法字符
func sanitizeFilename(name string) string {
	if name == "" {
		return "unnamed"
	}

	// 替换 Windows 非法字符: < > : " / \ | ? *
	illegalChars := []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"}
	result := name
	for _, ch := range illegalChars {
		result = strings.ReplaceAll(result, ch, "_")
	}

	// 去除控制字符 (ASCII 0-31, 127)
	cleaned := make([]byte, 0, len(result))
	for i := 0; i < len(result); i++ {
		b := result[i]
		if b >= 0x20 && b != 0x7F {
			cleaned = append(cleaned, b)
		}
	}
	result = string(cleaned)

	// 去除首尾空格和点
	result = strings.TrimSpace(result)
	result = strings.TrimRight(result, ".")

	// 限制长度（最长 200 字符）
	if len(result) > 200 {
		// 保留扩展名
		ext := filepath.Ext(result)
		base := result[:200-len(ext)]
		result = base + ext
	}

	// 空名用 "unnamed" 替代
	if result == "" {
		return "unnamed"
	}

	return result
}

func buildNTFSRelativePath(file *types.RecoveredFile) string {
	rawPath := strings.TrimSpace(file.OriginalPath)
	if rawPath == "" {
		return fallbackRecoveredName(file)
	}

	rawPath = strings.ReplaceAll(rawPath, "\\", "/")
	parts := strings.Split(rawPath, "/")
	cleanParts := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." {
			continue
		}

		cleanParts = append(cleanParts, sanitizeFilename(part))
	}

	if len(cleanParts) == 0 {
		return fallbackRecoveredName(file)
	}

	if len(cleanParts[len(cleanParts)-1]) == 0 {
		cleanParts[len(cleanParts)-1] = fallbackRecoveredName(file)
	}

	return filepath.Join(cleanParts...)
}

func fallbackRecoveredName(file *types.RecoveredFile) string {
	if file != nil && file.FileName != "" {
		return sanitizeFilename(file.FileName)
	}

	ext := "bin"
	if file != nil && file.Extension != "" {
		ext = file.Extension
	}

	var offset int64
	if file != nil {
		offset = file.Offset
	}
	return fmt.Sprintf("unnamed_%d.%s", offset, ext)
}

// resolveConflict 处理文件名冲突
// 如果文件已存在，在文件名后添加 _1, _2... 后缀
func resolveConflict(path string) string {
	// 如果文件不存在，直接返回
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}

	dir := filepath.Dir(path)
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(filepath.Base(path), ext)

	// 最多尝试 10000 次
	for i := 1; i <= 10000; i++ {
		newName := fmt.Sprintf("%s_%d%s", base, i, ext)
		newPath := filepath.Join(dir, newName)
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
	}

	// 极端情况：10000 次都冲突，使用时间戳
	log.Printf("[SafeWriter] 文件名冲突超过 10000 次: %s", path)
	newName := fmt.Sprintf("%s_%d%s", base, os.Getpid(), ext)
	return filepath.Join(dir, newName)
}

// categoryToDir 将文件分类映射到子目录名
func categoryToDir(category types.FileCategory) string {
	switch category {
	case types.CategoryImage:
		return "images"
	case types.CategoryDocument:
		return "documents"
	case types.CategoryVideo:
		return "videos"
	case types.CategoryAudio:
		return "audio"
	case types.CategoryArchive:
		return "archives"
	case types.CategoryDatabase:
		return "databases"
	default:
		return "other"
	}
}

// fileSHA256 计算文件的 SHA256 哈希值
func fileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("计算 SHA256 失败: %w", err)
	}

	return h.Sum(nil), nil
}

// sha256Equal 比较两个 SHA256 哈希值是否相等
func sha256Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
