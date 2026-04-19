package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/ntfs"
	"data-recovery/internal/signature"
	"data-recovery/internal/types"
)

// writer.go 与 engine.go 同属 recovery 包，共享 engine.go 中定义的 logger 变量。

// 业界（PhotoRec 等）普遍做法：单个分类目录下文件过多会严重拖慢文件系统；
// 按每 500 个文件切一个 batch 子目录，兼顾浏览体验与文件系统性能。
const carverBatchSize = 500

// LowConfidenceThreshold 低于该置信度的雕刻文件改写到 _low_confidence/，
// 避免污染主恢复目录。NTFS 文件不受该阈值影响。
const LowConfidenceThreshold = 0.5

// SafeWriter 安全文件写入器 — 确保恢复的文件正确写入磁盘
type SafeWriter struct {
	reader    disk.DiskReader
	outputDir string
	bufSize   int // 写入缓冲大小，默认 4MB

	// sigDB 用于写入前的 magic-bytes 复查，保证扩展名与内容一致
	sigDB *signature.SignatureDB

	// carver 每个 (category, confidence_tier) 的计数器，用于 batch_NNN 分桶
	batchMu      sync.Mutex
	batchCounter map[string]int
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
		reader:       reader,
		outputDir:    outputDir,
		bufSize:      4 * 1024 * 1024, // 4MB
		sigDB:        signature.NewSignatureDB(),
		batchCounter: make(map[string]int),
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
	headVerified := false

	for remaining > 0 {
		readSize := int64(w.bufSize)
		if readSize > remaining {
			readSize = remaining
		}

		n, err := w.reader.ReadAt(buf[:readSize], currentOffset)
		if err != nil && n == 0 {
			return fmt.Errorf("读取磁盘数据失败 (偏移: %d, 大小: %d): %w", currentOffset, readSize, err)
		}

		// 写入前的首块 magic-bytes 复查：与声明扩展名不一致立即拒写，
		// 避免把误报的数据片段落地成错误格式文件
		if !headVerified {
			if verr := w.verifyMagicBytes(file, buf[:n]); verr != nil {
				return fmt.Errorf("写入前内容校验失败: %w", verr)
			}
			headVerified = true
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

	// 回填 SHA256 以供 manifest 导出与跨源去重使用
	file.SHA256 = hex.EncodeToString(writeSHA)

	logger.Info("文件写入成功",
		"path", outputPath,
		"size", types.FormatSize(totalWritten),
		"sha256_prefix", fmt.Sprintf("%x", writeSHA[:8]))
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
		// 没有 DataRuns 也没有驻留数据 —— 无数据可恢复
		// 不能回退到按 Offset 读取，因为 file.Offset 只指向第一段，碎片文件会导出错误数据
		return fmt.Errorf("NTFS 文件 %q 缺少 DataRuns 且无驻留数据，无法安全恢复", file.FileName)
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
	zeroBuf := make([]byte, w.bufSize)
	totalWritten := int64(0)
	bytesPerCluster := int64(boot.BytesPerSector) * int64(boot.SectorsPerCluster)

	// 遍历 DataRuns，从每个 run 读取数据
	for _, run := range entry.DataRuns {
		runLength := run.ClusterCount * bytesPerCluster

		// 如果已经写够了，停止（文件大小可能小于所有 run 的总大小）
		remaining := file.Size - totalWritten
		if remaining <= 0 {
			break
		}
		if runLength > remaining {
			runLength = remaining
		}

		// 稀疏段：写零而不是读磁盘（ClusterOffset 对真实数据无意义）
		if run.Sparse {
			runRemaining := runLength
			for runRemaining > 0 {
				writeSize := int64(w.bufSize)
				if writeSize > runRemaining {
					writeSize = runRemaining
				}
				written, err := tmpFile.Write(zeroBuf[:writeSize])
				if err != nil {
					return fmt.Errorf("写入稀疏段失败: %w", err)
				}
				writeHasher.Write(zeroBuf[:writeSize])
				totalWritten += int64(written)
				runRemaining -= int64(written)
			}
			continue
		}

		// 计算此 run 在磁盘上的绝对偏移
		runOffset := partitionOffset + run.ClusterOffset*bytesPerCluster

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
	if sizeMismatch {
		logger.Warn("NTFS 文件大小不完全匹配(可能 DataRun 不完整)",
			"expected", file.Size, "actual", totalWritten)
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

	// 部分写入不登记 SHA256 / 不恢复时间戳——调用方会删除这个不完整文件
	if sizeMismatch {
		logger.Warn("NTFS 文件部分写入，返回 PartialWriteError",
			"path", outputPath,
			"expected", file.Size,
			"actual", totalWritten)
		return &PartialWriteError{
			OutputPath: outputPath,
			Expected:   file.Size,
			Written:    totalWritten,
		}
	}

	// 回填 SHA256 并恢复 MFT 中记录的时间戳
	file.SHA256 = hex.EncodeToString(writeSHA)
	applyTimestamps(outputPath, file)

	logger.Info("NTFS 文件写入成功",
		"path", outputPath,
		"size", types.FormatSize(totalWritten),
		"sha256_prefix", fmt.Sprintf("%x", writeSHA[:8]))

	return nil
}

// GenerateOutputPath 生成输出文件路径。
//
// 目录结构（遵循 PhotoRec / R-Studio 的主流做法）：
//
//	<baseDir>/
//	├── ntfs/<原路径>/<原名>.<原扩展名>          // 元数据驱动恢复，保留目录树与时间戳
//	└── carver/
//	    ├── <category>/batch_NNN/<name>.<ext>    // 正常置信度
//	    └── _low_confidence/<category>/batch_NNN/<name>.<ext>
//
// 已显式移除 .bin 兜底：雕刻来源没有合法扩展名时返回错误让上层跳过。
func (w *SafeWriter) GenerateOutputPath(file *types.RecoveredFile, baseDir string) (string, error) {
	if file == nil {
		return "", fmt.Errorf("文件信息为空")
	}

	if file.Source == "ntfs" {
		return resolveConflict(filepath.Join(baseDir, "ntfs", buildNTFSRelativePath(file))), nil
	}

	// carver 分支：没有合法扩展名就拒绝写出，避免 .bin 等垃圾文件
	ext := strings.ToLower(strings.TrimSpace(file.Extension))
	if ext == "" {
		return "", fmt.Errorf("雕刻来源文件缺少扩展名，拒绝落地: id=%s offset=0x%x", file.ID, file.Offset)
	}

	fileName := strings.TrimSpace(file.FileName)
	if fileName == "" {
		// 理论上 carver/engine.go 已经生成了名字，这里只是兜底，
		// 仍然使用带偏移的规范格式，不给 FILE_<offset> 之类占位名。
		fileName = fmt.Sprintf("%s_0x%x.%s", ext, file.Offset, ext)
	}

	// 低置信度 / 未通过验证：单独放 _low_confidence/ 目录，避免污染主输出
	confBucket := "normal"
	if !file.IsValid || file.Confidence < LowConfidenceThreshold {
		confBucket = "low"
	}

	cat := categoryToDir(file.Category)
	batchNo := w.nextBatchNo(confBucket, cat)
	batchDir := fmt.Sprintf("batch_%03d", batchNo)

	var fullPath string
	if confBucket == "low" {
		fullPath = filepath.Join(baseDir, "carver", "_low_confidence", cat, batchDir, fileName)
	} else {
		fullPath = filepath.Join(baseDir, "carver", cat, batchDir, fileName)
	}

	return resolveConflict(fullPath), nil
}

// nextBatchNo 为给定 (confBucket, category) 选一个当前未满 carverBatchSize 的批次号。
// 并发安全：内部持锁计数。
func (w *SafeWriter) nextBatchNo(confBucket, cat string) int {
	w.batchMu.Lock()
	defer w.batchMu.Unlock()

	if w.batchCounter == nil {
		w.batchCounter = make(map[string]int)
	}

	key := confBucket + "/" + cat
	count := w.batchCounter[key]
	batchNo := count/carverBatchSize + 1
	w.batchCounter[key] = count + 1
	return batchNo
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

	// 回填 SHA256 并恢复时间戳
	file.SHA256 = hex.EncodeToString(writeSHA[:])
	applyTimestamps(outputPath, file)

	logger.Info("驻留文件写入成功",
		"path", outputPath,
		"size", types.FormatSize(expectedSize),
		"sha256_prefix", fmt.Sprintf("%x", writeSHA[:8]))
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

// fallbackRecoveredName 仅用于 NTFS OriginalPath 被清洗干净后的兜底。
// NTFS 文件一定有 FileName（MFT 保证），因此不再给出 .bin 这种通用扩展名。
func fallbackRecoveredName(file *types.RecoveredFile) string {
	if file != nil && file.FileName != "" {
		return sanitizeFilename(file.FileName)
	}

	// NTFS 路径不应走到这里；若真发生，用 recovered_<offset> 避免捏造扩展名
	var offset int64
	if file != nil {
		offset = file.Offset
	}
	return fmt.Sprintf("recovered_0x%x", offset)
}

// verifyMagicBytes 读取文件头 N 字节，与扩展名对应的签名做匹配。
// 仅对 carver 来源启用：NTFS 文件走 MFT 恢复，数据片段不一定是完整文件。
//
// 返回 nil 表示内容与声明扩展名一致（或签名库里没这个扩展名，跳过校验）。
func (w *SafeWriter) verifyMagicBytes(file *types.RecoveredFile, head []byte) error {
	if file == nil || w.sigDB == nil {
		return nil
	}
	if file.Source != "carver" {
		return nil
	}

	ext := strings.ToLower(strings.TrimSpace(file.Extension))
	if ext == "" {
		return fmt.Errorf("扩展名为空")
	}

	sig := w.sigDB.ByExtension(ext)
	if sig == nil || len(sig.Headers) == 0 {
		// 容器类子扩展名（docx/xlsx/wav/avi 等）依赖底层 zip/riff 已经在 carver 细分过，
		// 这里没有直接签名也认为可接受，不做误拦。
		return nil
	}

	for _, header := range sig.Headers {
		if len(head) >= len(header) && bytes.Equal(head[:len(header)], header) {
			return nil
		}
	}
	return fmt.Errorf("magic-bytes 与扩展名 .%s 不匹配 (前 %d 字节: %x)",
		ext, minInt(len(head), 16), head[:minInt(len(head), 16)])
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// applyTimestamps 把 MFT 中记录的 CreatedTime / ModifiedTime 写回落盘文件。
// 失败只记日志不报错 —— 时间戳恢复失败不应影响数据恢复本身。
func applyTimestamps(path string, file *types.RecoveredFile) {
	if file == nil {
		return
	}
	// 仅 NTFS 路径有可靠时间戳；carver 文件没有原始元数据
	if file.Source != "ntfs" {
		return
	}

	var atime, mtime time.Time
	if file.ModifiedTime != nil {
		mtime = *file.ModifiedTime
	}
	if file.CreatedTime != nil {
		atime = *file.CreatedTime
	}
	if atime.IsZero() && mtime.IsZero() {
		return
	}
	if atime.IsZero() {
		atime = mtime
	}
	if mtime.IsZero() {
		mtime = atime
	}

	if err := os.Chtimes(path, atime, mtime); err != nil {
		logger.Debug("恢复文件时间戳失败", "path", path, "err", err)
	}
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
	logger.Warn("文件名冲突超过 10000 次", "path", path)
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
