package carver

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/signature"
	"data-recovery/internal/types"
)

// chunk 表示从磁盘读取的一个数据块
type chunk struct {
	Data   []byte // 数据内容
	Offset int64  // 在磁盘上的起始偏移
	Size   int    // 有效数据长度（可能比 Data 小因为 overlap）
}

// rawMatch 是 AC 匹配器的原始匹配结果
type rawMatch struct {
	Offset    int64
	Signature *types.FileSignature
	Pattern   []byte
}

// Config 雕刻引擎配置
type Config struct {
	ChunkSize   int64 // 每次读取块大小，默认 4MB
	Workers     int   // 工作 goroutine 数量，默认 runtime.NumCPU()
	Overlap     int   // 块重叠字节数（自动根据最大签名长度设置）
	MaxFileSize int64 // 单文件最大大小限制，默认 4GB
}

// DefaultConfig 返回默认配置
func DefaultConfig() Config {
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	return Config{
		ChunkSize:   4 * 1024 * 1024, // 4MB
		Workers:     workers,
		MaxFileSize: 4 * 1024 * 1024 * 1024, // 4GB
	}
}

// Engine 文件雕刻引擎
// 通过多线程流水线扫描磁盘原始数据，使用 Aho-Corasick 签名匹配找到文件，
// 然后用格式专用解析器确定文件边界。
type Engine struct {
	reader  disk.DiskReader
	sigDB   *signature.SignatureDB
	matcher *signature.AhoCorasick
	config  Config

	// 统计
	bytesScanned atomic.Int64
	filesFound   atomic.Int32

	// 控制
	cancel context.CancelFunc
}

// NewEngine 创建文件雕刻引擎
// 从 sigDB 获取所有 HeaderEntry，构建 AhoCorasick 自动机，
// 设置 overlap = sigDB.MaxHeaderLen() - 1（至少 64）
func NewEngine(reader disk.DiskReader, sigDB *signature.SignatureDB, cfg Config) *Engine {
	// 从签名数据库获取所有头部条目
	headers := sigDB.AllHeaders()

	// 构建 Aho-Corasick 多模式匹配自动机（使用 builder 模式）
	matcher := signature.NewAhoCorasick()
	for _, entry := range headers {
		matcher.AddPattern(entry.Pattern, entry.Signature)
	}
	matcher.Build()

	// 设置 overlap 为最大签名长度 - 1，保证跨块边界的签名不会被遗漏
	overlap := sigDB.MaxHeaderLen() - 1
	if overlap < 64 {
		overlap = 64
	}
	cfg.Overlap = overlap

	return &Engine{
		reader:  reader,
		sigDB:   sigDB,
		matcher: matcher,
		config:  cfg,
	}
}

// Scan 执行核心扫描
//
// 流水线架构:
//
//	IO Goroutine → [chunkCh] → N Worker Goroutines → [matchCh] → Collector Goroutine
//
// startOffset/endOffset 指定扫描的磁盘字节范围。
// onProgress 每秒回调一次当前进度。
// onFound 每发现一个文件回调一次。
func (e *Engine) Scan(
	parentCtx context.Context,
	startOffset, endOffset int64,
	onProgress func(types.ScanProgress),
	onFound func(*types.RecoveredFile),
) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	e.cancel = cancel

	// 重置统计
	e.bytesScanned.Store(0)
	e.filesFound.Store(0)

	totalBytes := endOffset - startOffset
	if totalBytes <= 0 {
		return fmt.Errorf("无效的扫描范围: start=0x%X end=0x%X", startOffset, endOffset)
	}

	startTime := time.Now()

	// ---- 创建流水线 channel ----
	chunkCh := make(chan *chunk, e.config.Workers*2) // IO → Workers
	matchCh := make(chan *rawMatch, 1000)            // Workers → Collector

	var wgWorkers sync.WaitGroup
	var wgCollector sync.WaitGroup

	// ================================================================
	// IO Goroutine（1 个）：顺序读取磁盘数据块
	// ================================================================
	go func() {
		defer close(chunkCh)

		offset := startOffset
		overlap64 := int64(e.config.Overlap)
		buf := make([]byte, e.config.ChunkSize+overlap64)

		for offset < endOffset {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// 计算本次实际读取大小（包含 overlap）
			readSize := e.config.ChunkSize + overlap64
			if readSize > endOffset-offset {
				readSize = endOffset - offset
			}

			n, err := e.reader.ReadAt(buf[:readSize], offset)
			if n > 0 {
				// 复制数据，避免多个 worker 之间的竞争
				data := make([]byte, n)
				copy(data, buf[:n])

				select {
				case chunkCh <- &chunk{Data: data, Offset: offset, Size: n}:
				case <-ctx.Done():
					return
				}
			}

			if err != nil && n == 0 {
				log.Printf("[carver] IO: 读取偏移 0x%X 失败 (跳过): %v", offset, err)
				// 跳过此块，继续下一个
			}

			// 步进 chunkSize（不含 overlap），使下一块与本块有 overlap 字节的重叠
			offset += e.config.ChunkSize
			scanned := e.config.ChunkSize
			if offset > endOffset {
				scanned = e.config.ChunkSize - (offset - endOffset)
			}
			e.bytesScanned.Add(scanned)
		}
	}()

	// ================================================================
	// Worker Goroutines（N 个）：对每个 chunk 执行 AC 签名匹配
	// ================================================================
	for i := 0; i < e.config.Workers; i++ {
		wgWorkers.Add(1)
		go func(workerID int) {
			defer wgWorkers.Done()
			for c := range chunkCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// 使用 AC 自动机在数据块中搜索所有签名
				matches := e.matcher.Search(c.Data, c.Offset)
				for _, m := range matches {
					select {
					case matchCh <- &rawMatch{
						Offset:    m.Offset,
						Signature: m.Signature,
						Pattern:   m.Pattern,
					}:
					case <-ctx.Done():
						return
					}
				}
			}
		}(i)
	}

	// Workers 全部完成后关闭 matchCh，通知 Collector 结束
	go func() {
		wgWorkers.Wait()
		close(matchCh)
	}()

	// ================================================================
	// Progress Goroutine：每秒报告一次扫描进度
	// ================================================================
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if onProgress == nil {
					continue
				}

				scanned := e.bytesScanned.Load()
				found := int(e.filesFound.Load())
				elapsed := time.Since(startTime)

				// 计算百分比
				var percent float64
				if totalBytes > 0 {
					percent = float64(scanned) / float64(totalBytes) * 100.0
					if percent > 100.0 {
						percent = 100.0
					}
				}

				// 计算速度 (bytes/sec)
				var speed int64
				elapsedSec := elapsed.Seconds()
				if elapsedSec > 0.1 {
					speed = int64(float64(scanned) / elapsedSec)
				}

				// 计算 ETA
				var eta string
				if speed > 0 {
					remaining := totalBytes - scanned
					if remaining < 0 {
						remaining = 0
					}
					etaSec := float64(remaining) / float64(speed)
					eta = types.FormatDuration(etaSec)
				} else {
					eta = "计算中..."
				}

				onProgress(types.ScanProgress{
					Phase:        "carving",
					Percent:      percent,
					BytesScanned: scanned,
					TotalBytes:   totalBytes,
					FilesFound:   found,
					Speed:        speed,
					ETA:          eta,
					Elapsed:      types.FormatDuration(elapsedSec),
				})
			}
		}
	}()

	// ================================================================
	// Collector Goroutine（1 个）：去重、解析文件大小、分类、回调
	// ================================================================
	wgCollector.Add(1)
	go func() {
		defer wgCollector.Done()

		// 用 map 去重，同一偏移只处理一次
		seen := make(map[int64]bool)

		for m := range matchCh {
			// 去重
			if seen[m.Offset] {
				continue
			}
			seen[m.Offset] = true

			// 调用格式解析器确定文件大小
			fileSize := e.determineFileSize(e.reader, m.Offset, m.Signature, m.Pattern)
			if fileSize <= 0 {
				continue
			}

			// 限制最大文件大小
			if fileSize > e.config.MaxFileSize {
				fileSize = e.config.MaxFileSize
			}

			ext := m.Signature.Extension
			cat := m.Signature.Category

			// 对容器格式进行细分类
			switch ext {
			case "riff":
				if subExt, subCat := e.classifyRIFF(e.reader, m.Offset); subExt != "" {
					ext = subExt
					cat = subCat
				}
			case "ole2":
				if subExt, subCat := e.classifyOLE2(e.reader, m.Offset); subExt != "" {
					ext = subExt
					cat = subCat
				}
			case "zip":
				if subExt, subCat := e.classifyZIP(e.reader, m.Offset, fileSize); subExt != "" {
					ext = subExt
					cat = subCat
				}
			}

			// 构建恢复文件信息
			file := &types.RecoveredFile{
				ID:         fmt.Sprintf("carve_%d", m.Offset),
				Source:     "carver",
				FileName:   fmt.Sprintf("recovered_%d.%s", m.Offset, ext),
				Extension:  ext,
				Category:   cat,
				Size:       fileSize,
				SizeHuman:  types.FormatSize(fileSize),
				Offset:     m.Offset,
				Confidence: 0.7, // 雕刻的基础置信度
			}

			e.filesFound.Add(1)

			if onFound != nil {
				onFound(file)
			}
		}
	}()

	// ---- 等待 Collector 完成（意味着所有匹配已处理）----
	wgCollector.Wait()

	// 停止 Progress Goroutine
	cancel()
	<-progressDone

	// 发送最终 100% 进度
	if onProgress != nil {
		elapsed := time.Since(startTime)
		onProgress(types.ScanProgress{
			Phase:        "carving",
			Percent:      100.0,
			BytesScanned: totalBytes,
			TotalBytes:   totalBytes,
			FilesFound:   int(e.filesFound.Load()),
			Speed:        0,
			ETA:          "0.0 秒",
			Elapsed:      types.FormatDuration(elapsed.Seconds()),
		})
	}

	// 仅当外部调用者主动取消时才返回错误
	if parentCtx.Err() != nil {
		return parentCtx.Err()
	}

	return nil
}

// Stop 停止正在进行的扫描
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
}

// BytesScanned 返回已扫描字节数
func (e *Engine) BytesScanned() int64 {
	return e.bytesScanned.Load()
}

// FilesFound 返回已发现文件数
func (e *Engine) FilesFound() int32 {
	return e.filesFound.Load()
}

// RecoverFile 从磁盘 offset 处读取 file.Size 字节，写入 outputPath
// 分块读取（每次 4MB），避免大文件 OOM
func (e *Engine) RecoverFile(
	file *types.RecoveredFile,
	reader disk.DiskReader,
	outputPath string,
) error {
	if file == nil {
		return fmt.Errorf("file 不能为 nil")
	}
	if file.Size <= 0 {
		return fmt.Errorf("无效的文件大小: %d", file.Size)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败 %s: %w", outputPath, err)
	}
	defer outFile.Close()

	const bufSize = 4 * 1024 * 1024 // 4MB
	buf := make([]byte, bufSize)

	remaining := file.Size
	offset := file.Offset

	for remaining > 0 {
		readLen := int64(bufSize)
		if readLen > remaining {
			readLen = remaining
		}

		n, err := reader.ReadAt(buf[:readLen], offset)
		if n > 0 {
			if _, writeErr := outFile.Write(buf[:n]); writeErr != nil {
				return fmt.Errorf("写入输出文件失败: %w", writeErr)
			}
			offset += int64(n)
			remaining -= int64(n)
		}
		if err != nil {
			if n == 0 {
				return fmt.Errorf("读取偏移 0x%X 失败: %w", offset, err)
			}
			// n > 0 时部分读取成功，继续
		}
	}

	return nil
}

// =========================================================================
// 辅助方法
// =========================================================================

// determineFileSize 根据签名类型调用对应的格式解析器确定文件大小
func (e *Engine) determineFileSize(
	reader disk.DiskReader,
	offset int64,
	sig *types.FileSignature,
	headerData []byte,
) int64 {
	maxSize := sig.MaxSize
	if maxSize <= 0 {
		maxSize = e.config.MaxFileSize
	}
	if maxSize > e.config.MaxFileSize {
		maxSize = e.config.MaxFileSize
	}

	var size int64

	switch sig.Extension {
	case "jpg", "jpeg":
		size = detectJPEGSize(reader, offset, maxSize)
	case "png":
		size = detectPNGSize(reader, offset, maxSize)
	case "pdf":
		size = detectPDFSize(reader, offset, maxSize)
	case "zip":
		size = detectZIPSize(reader, offset, maxSize)
	case "mp4", "mov", "m4a", "3gp":
		size = detectMP4Size(reader, offset, maxSize)
	case "mp3":
		size = detectMP3Size(reader, offset, maxSize)
	case "riff", "avi", "wav":
		size = detectRIFFSize(reader, offset, maxSize)
	case "ole2", "doc", "xls", "ppt":
		size = detectOLE2Size(reader, offset, maxSize)
	default:
		// 对未知格式，如果有 footer，搜索 footer 来确定文件边界
		if len(sig.Footers) > 0 {
			size = searchFooter(reader, offset, maxSize, sig.Footers)
		}
	}

	// 检测失败时返回合理默认值（不返回 0）
	if size <= 0 {
		defaultSize := int64(1 * 1024 * 1024) // 默认 1MB
		if sig.MaxSize > 0 && sig.MaxSize < defaultSize {
			defaultSize = sig.MaxSize
		}
		return defaultSize
	}

	return size
}

// searchFooter 在 [offset, offset+maxSize) 范围内搜索 footer 签名来确定文件大小
func searchFooter(reader disk.DiskReader, offset int64, maxSize int64, footers [][]byte) int64 {
	const blockSize = 64 * 1024 // 64KB
	buf := make([]byte, blockSize)

	// 计算最长 footer 长度，用于块重叠
	maxFooterLen := 0
	for _, f := range footers {
		if len(f) > maxFooterLen {
			maxFooterLen = len(f)
		}
	}
	if maxFooterLen == 0 {
		return 0
	}

	var lastFound int64 // 记录最后一次匹配的文件结束偏移

	pos := offset
	endLimit := offset + maxSize

	for pos < endLimit {
		readLen := int64(blockSize)
		if readLen > endLimit-pos {
			readLen = endLimit - pos
		}

		n, err := reader.ReadAt(buf[:readLen], pos)
		if n <= 0 {
			break
		}

		for _, footer := range footers {
			fLen := len(footer)
			if fLen == 0 || n < fLen {
				continue
			}
			// 在 buf[:n] 中搜索 footer
			for i := 0; i <= n-fLen; i++ {
				match := true
				for j := 0; j < fLen; j++ {
					if buf[i+j] != footer[j] {
						match = false
						break
					}
				}
				if match {
					candidate := pos + int64(i) + int64(fLen) - offset
					if candidate > lastFound {
						lastFound = candidate
					}
				}
			}
		}

		// 块重叠避免跨边界漏匹配
		advance := int64(n) - int64(maxFooterLen) + 1
		if advance < 1 {
			advance = int64(n)
		}
		pos += advance

		if err != nil {
			break
		}
	}

	return lastFound
}

// classifyRIFF 读取 RIFF 偏移 8 处的 4 字节子类型来细分文件格式
func (e *Engine) classifyRIFF(reader disk.DiskReader, offset int64) (string, types.FileCategory) {
	subType, err := readBytesAt(reader, offset+8, 4)
	if err != nil {
		return "", types.CategoryOther
	}

	switch string(subType) {
	case "WAVE":
		return "wav", types.CategoryAudio
	case "AVI ":
		return "avi", types.CategoryVideo
	case "WEBP":
		return "webp", types.CategoryImage
	case "RMID":
		return "mid", types.CategoryAudio
	case "CDDA":
		return "cda", types.CategoryAudio
	case "ACON":
		return "ani", types.CategoryImage
	default:
		return "riff", types.CategoryOther
	}
}

// classifyOLE2 检查 OLE2 容器内容来细分格式
// 简化方法：读取前 4KB 搜索特征字符串
func (e *Engine) classifyOLE2(reader disk.DiskReader, offset int64) (string, types.FileCategory) {
	data, err := readBytesAt(reader, offset, 4096)
	if err != nil || len(data) < 512 {
		return "", types.CategoryDocument
	}

	s := string(data)

	// Word 文档: 目录流中通常包含 "WordDocument"
	if strings.Contains(s, "WordDocument") || strings.Contains(s, "W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t") {
		return "doc", types.CategoryDocument
	}
	// Excel: 通常包含 "Workbook" 或 "Book"
	if strings.Contains(s, "Workbook") || strings.Contains(s, "W\x00o\x00r\x00k\x00b\x00o\x00o\x00k") {
		return "xls", types.CategoryDocument
	}
	// PowerPoint
	if strings.Contains(s, "PowerPoint") || strings.Contains(s, "P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t") {
		return "ppt", types.CategoryDocument
	}
	// Visio
	if strings.Contains(s, "Visio") {
		return "vsd", types.CategoryDocument
	}

	return "ole2", types.CategoryDocument
}

// classifyZIP 检查 ZIP 内部文件名来细分格式
// 读取第一个 local file header 中的文件名进行判断
func (e *Engine) classifyZIP(reader disk.DiskReader, offset int64, size int64) (string, types.FileCategory) {
	// ZIP local file header: PK\x03\x04 ...
	// 偏移 26: 文件名长度 (2 bytes LE)
	// 偏移 28: extra field 长度 (2 bytes LE)
	// 偏移 30: 文件名
	header, err := readBytesAt(reader, offset, 256)
	if err != nil || len(header) < 30 {
		return "", types.CategoryArchive
	}

	nameLen := int(header[26]) | int(header[27])<<8
	if nameLen <= 0 || nameLen > 220 || 30+nameLen > len(header) {
		return "", types.CategoryArchive
	}
	extraLen := int(header[28]) | int(header[29])<<8

	firstName := string(header[30 : 30+nameLen])

	// --- Office Open XML (DOCX/XLSX/PPTX) ---
	if firstName == "[Content_Types].xml" || firstName == "_rels/.rels" || firstName == "_rels/" {
		// 读取更多数据以区分具体类型
		readSize := int64(8192)
		if readSize > size && size > 0 {
			readSize = size
		}
		data, err := readBytesAt(reader, offset, int(readSize))
		if err == nil {
			dataStr := string(data)
			if strings.Contains(dataStr, "word/") || strings.Contains(dataStr, "word\\") {
				return "docx", types.CategoryDocument
			}
			if strings.Contains(dataStr, "xl/") || strings.Contains(dataStr, "xl\\") {
				return "xlsx", types.CategoryDocument
			}
			if strings.Contains(dataStr, "ppt/") || strings.Contains(dataStr, "ppt\\") {
				return "pptx", types.CategoryDocument
			}
		}
		// 无法进一步区分，但确实是 OOXML
		return "zip", types.CategoryArchive
	}

	// --- EPUB ---
	if firstName == "mimetype" {
		dataOffset := offset + 30 + int64(nameLen) + int64(extraLen)
		mimeData, err := readBytesAt(reader, dataOffset, 40)
		if err == nil && strings.Contains(string(mimeData), "epub") {
			return "epub", types.CategoryDocument
		}
	}

	// --- JAR ---
	if firstName == "META-INF/" || firstName == "META-INF/MANIFEST.MF" {
		return "jar", types.CategoryArchive
	}

	// --- APK ---
	if firstName == "AndroidManifest.xml" || firstName == "classes.dex" {
		return "apk", types.CategoryArchive
	}

	// --- OpenDocument (ODT/ODS/ODP) ---
	if firstName == "mimetype" {
		dataOffset := offset + 30 + int64(nameLen) + int64(extraLen)
		mimeData, err := readBytesAt(reader, dataOffset, 60)
		if err == nil {
			mime := string(mimeData)
			if strings.Contains(mime, "opendocument.text") {
				return "odt", types.CategoryDocument
			}
			if strings.Contains(mime, "opendocument.spreadsheet") {
				return "ods", types.CategoryDocument
			}
			if strings.Contains(mime, "opendocument.presentation") {
				return "odp", types.CategoryDocument
			}
		}
	}

	return "zip", types.CategoryArchive
}
