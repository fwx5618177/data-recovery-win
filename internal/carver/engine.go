package carver

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/logging"
	"data-recovery/internal/signature"
	"data-recovery/internal/types"
)

var logger = logging.L().With("component", "carver")

// chunk 表示从磁盘读取的一个数据块。
//
// Data 是池化的大缓冲区（容量固定为 ChunkSize+Overlap），处理完后必须归还：
// 调用方（worker）在做完 AC 搜索后用 release() 把它还给 Engine.chunkPool。
// matcher.Search 返回的 Pattern 是引用 AC 树里的常量字节，不是 Data 的切片，
// 因此归还 Data 不会让后续 Collector 用到悬空引用。
type chunk struct {
	Data    []byte     // 池化的数据缓冲区（归还前 worker 会用 Data[:Size] 做匹配）
	Offset  int64      // 在磁盘上的起始偏移
	Size    int        // 有效数据长度（可能比 cap(Data) 小，因为 overlap 不足或到达末尾）
	release func()     // 把 Data 归还到 Engine.chunkPool
}

// rawMatch 是 AC 匹配器的原始匹配结果
type rawMatch struct {
	Offset    int64
	Signature *types.FileSignature
	Pattern   []byte
}

// Config 深度扫描引擎配置
type Config struct {
	ChunkSize   int64 // 每次读取块大小，默认 4MB
	Workers     int   // 工作 goroutine 数量，默认 runtime.NumCPU()
	Overlap     int   // 块重叠字节数（自动根据最大签名长度设置）
	MaxFileSize int64 // 单文件最大大小限制，默认 4GB

	// DisabledExtensions 深度扫描时跳过的签名扩展名（小写）。
	// 业界主流实践（参考 PhotoRec 默认 profile）：
	//   - 被重置/格式化的 Windows 盘在自由空间里会残留大量 .exe / .ico / .elf 等系统文件碎片，
	//     这些文件基本不是用户想要的数据，却会淹没真正的照片、文档等用户内容。
	//   - ICO 头部仅 4 字节近零值（`00 00 01 00`），在未初始化扇区里误报率极高。
	//   - EXE 头部只有 2 字节（`MZ`）也是一样。
	// 所以默认把 ico/exe/elf 从深度扫描集合中剔除；用户如需恢复系统文件可显式启用。
	DisabledExtensions []string
}

// DefaultConfig 返回默认配置
func DefaultConfig() Config {
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	return Config{
		ChunkSize:          4 * 1024 * 1024, // 4MB
		Workers:            workers,
		MaxFileSize:        4 * 1024 * 1024 * 1024, // 4GB
		DisabledExtensions: []string{"ico", "exe", "elf"},
	}
}

// Engine 深度扫描引擎
// 通过多线程流水线扫描磁盘原始数据，使用 Aho-Corasick 签名匹配找到文件，
// 然后用格式专用解析器确定文件边界。
type Engine struct {
	reader  disk.DiskReader
	sigDB   *signature.SignatureDB
	matcher *signature.AhoCorasick
	config  Config

	// chunkPool 复用 IO 读块的大缓冲（容量 = ChunkSize + Overlap）。
	// 扫 64GB 盘 = 16k 个 chunk，不池化会产生 ~64GB 累计分配，GC 会越跑越慢；
	// 池化后稳定在 "Workers+chanBuf+1" 个对象上。
	chunkPool sync.Pool

	// 统计
	bytesScanned atomic.Int64
	filesFound   atomic.Int32

	// 每签名的 AC 命中数 / 最终产出数，便于在日志里定位"哪类签名在制造噪声"。
	// 在 Scan() 开始时初始化。
	hitsByExt    sync.Map // map[string]*int64 — 通过 AC 的裸命中数
	emittedByExt sync.Map // map[string]*int64 — 成功产出 RecoveredFile 的数量

	// 控制
	cancel context.CancelFunc
}

// bumpCounter 把 sync.Map 里指定 key 的计数 +1；不存在则插入。
func bumpCounter(m *sync.Map, key string) {
	if v, ok := m.Load(key); ok {
		atomic.AddInt64(v.(*int64), 1)
		return
	}
	n := int64(1)
	actual, loaded := m.LoadOrStore(key, &n)
	if loaded {
		atomic.AddInt64(actual.(*int64), 1)
	}
}

// counterSnapshot 把 sync.Map 快照成一张可排序的 map，便于日志输出。
func counterSnapshot(m *sync.Map) map[string]int64 {
	out := make(map[string]int64)
	m.Range(func(k, v any) bool {
		out[k.(string)] = atomic.LoadInt64(v.(*int64))
		return true
	})
	return out
}

// logCarverCounters 把本次扫描每签名的 AC 命中 vs 最终产出打印成一行易读日志。
// 用途：当某类文件数量异常（例如"全是 MP3"），日志会直接暴露是签名筛选太松还是检测器太宽。
func logCarverCounters(hits, emitted map[string]int64) {
	// 把两个 map 合并成"ext -> hits/emitted"字符串。
	keys := make(map[string]struct{}, len(hits)+len(emitted))
	for k := range hits {
		keys[k] = struct{}{}
	}
	for k := range emitted {
		keys[k] = struct{}{}
	}
	// 按命中数倒序稳定排序，最先看到"噪音签名"
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return hits[ordered[i]] > hits[ordered[j]]
	})

	// 简要行：ac_hits 总数 + emitted 总数
	var totalHits, totalEmitted int64
	for _, v := range hits {
		totalHits += v
	}
	for _, v := range emitted {
		totalEmitted += v
	}
	logger.Info("carver 签名统计汇总",
		"ac_hits_total", totalHits,
		"emitted_total", totalEmitted,
		"drop_rate", dropRate(totalHits, totalEmitted),
	)

	// 明细行：ext=hits→emitted
	for _, ext := range ordered {
		h := hits[ext]
		e := emitted[ext]
		logger.Info("carver 签名明细",
			"ext", ext,
			"ac_hits", h,
			"emitted", e,
			"pass_rate", passRate(h, e),
		)
	}
}

func passRate(hits, emitted int64) string {
	if hits == 0 {
		return "--"
	}
	return fmt.Sprintf("%.1f%%", float64(emitted)/float64(hits)*100)
}

func dropRate(hits, emitted int64) string {
	if hits == 0 {
		return "--"
	}
	return fmt.Sprintf("%.1f%%", float64(hits-emitted)/float64(hits)*100)
}

// NewEngine 创建深度扫描引擎
// 从 sigDB 获取所有 HeaderEntry，构建 AhoCorasick 自动机，
// 设置 overlap = sigDB.MaxHeaderLen() - 1（至少 64）
func NewEngine(reader disk.DiskReader, sigDB *signature.SignatureDB, cfg Config) *Engine {
	// 从签名数据库获取所有头部条目
	headers := sigDB.AllHeaders()

	// 应用 DisabledExtensions 过滤：被禁用的扩展名不进入 AC 自动机，
	// 从而彻底避免对应签名造成的命中噪声（而不是事后丢弃，浪费扫描 CPU）。
	disabled := make(map[string]struct{}, len(cfg.DisabledExtensions))
	for _, ext := range cfg.DisabledExtensions {
		disabled[strings.ToLower(strings.TrimSpace(ext))] = struct{}{}
	}

	// 构建 Aho-Corasick 多模式匹配自动机（使用 builder 模式）
	matcher := signature.NewAhoCorasick()
	registered := 0
	skipped := 0
	for _, entry := range headers {
		if entry.Signature != nil {
			if _, drop := disabled[strings.ToLower(entry.Signature.Extension)]; drop {
				skipped++
				continue
			}
		}
		matcher.AddPattern(entry.Pattern, entry.Signature)
		registered++
	}
	matcher.Build()
	if len(disabled) > 0 {
		logger.Info("深度扫描签名过滤",
			"registered", registered,
			"skipped", skipped,
			"disabled_exts", cfg.DisabledExtensions,
		)
	}

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

	// 初始化 chunkPool（容量固定）—— 每次 Scan 都重建以避免跨 Scan 复用老 overlap 的缓冲
	bufCap := int(e.config.ChunkSize) + e.config.Overlap
	e.chunkPool = sync.Pool{
		New: func() any {
			b := make([]byte, bufCap)
			return &b
		},
	}

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

		for offset < endOffset {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// 从池里拿一块大缓冲
			bufPtr := e.chunkPool.Get().(*[]byte)
			buf := *bufPtr

			// 计算本次实际读取大小（包含 overlap）
			readSize := e.config.ChunkSize + overlap64
			if readSize > endOffset-offset {
				readSize = endOffset - offset
			}

			n, err := e.reader.ReadAt(buf[:readSize], offset)
			if n > 0 {
				// 不再做拷贝：worker 直接对池化缓冲做 AC 搜索，
				// 完成后通过 release 归还（AC Match.Pattern 指向签名表，不是数据切片）
				sentBuf := bufPtr
				ch := &chunk{
					Data:   buf,
					Offset: offset,
					Size:   n,
					release: func() {
						e.chunkPool.Put(sentBuf)
					},
				}
				select {
				case chunkCh <- ch:
				case <-ctx.Done():
					ch.release()
					return
				}
			} else {
				// n==0 没进 channel，缓冲直接归还
				e.chunkPool.Put(bufPtr)
			}

			if err != nil && n == 0 {
				logger.Warn("读取磁盘块失败(跳过)", "offset", fmt.Sprintf("0x%X", offset), "err", err)
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
					if c.release != nil {
						c.release()
					}
					return
				default:
				}

				// 使用 AC 自动机在数据块中搜索所有签名（只看 Size 范围内的有效数据）
				matches := e.matcher.Search(c.Data[:c.Size], c.Offset)
				for _, m := range matches {
					select {
					case matchCh <- &rawMatch{
						Offset:    m.Offset,
						Signature: m.Signature,
						Pattern:   m.Pattern,
					}:
					case <-ctx.Done():
						if c.release != nil {
							c.release()
						}
						return
					}
				}

				// AC 搜索结果里的 Pattern 引用签名表常量，与 c.Data 无关，
				// 因此这里立刻归还缓冲安全。
				if c.release != nil {
					c.release()
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

		// 用 map 去重，同一偏移只处理一次。
		// IO 顺序读使偏移近似单调递增——当 map 过大时丢掉"远远落在水位线后面"的旧偏移，
		// 避免扫大盘时 map 无限膨胀（千万级 entry 会恶化 GC，让扫描越跑越慢）。
		//
		// 保留窗口必须 >= Worker 乱序处理引起的最大延迟，否则过早删除的条目可能在
		// overlap 区因另一个 chunk 再次命中被误判为新条目：
		//   - N 个 worker 并行处理，最迟到达的 chunk 可能落后 ~N * ChunkSize
		//   - 再留 chunkCh / matchCh 的缓冲余量
		seen := make(map[int64]bool)
		const seenSoftCap = 200_000 // 达到这个规模就尝试裁剪
		lagChunks := int64(e.config.Workers)*4 + 16
		keepLagBytes := lagChunks * e.config.ChunkSize
		var maxSeenOffset int64

		// 每种扩展名的序号计数器，用于生成可读文件名
		extCounter := make(map[string]int)

		for m := range matchCh {
			// 追踪最大偏移作为水位线
			if m.Offset > maxSeenOffset {
				maxSeenOffset = m.Offset
			}

			// 去重
			if seen[m.Offset] {
				continue
			}
			seen[m.Offset] = true

			// 超阈值时裁剪：删掉距水位线太远的老条目
			if len(seen) > seenSoftCap {
				cutoff := maxSeenOffset - keepLagBytes
				for k := range seen {
					if k < cutoff {
						delete(seen, k)
					}
				}
			}

			// 诊断：记录 AC 命中
			bumpCounter(&e.hitsByExt, m.Signature.Extension)

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
			desc := m.Signature.Description

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
			case "mp4":
				// ftyp 容器涵盖 MP4/MOV/M4A/3GP/HEIC/HEIF/AVIF/CR3 等多种现代格式，
				// 仅靠 magic 分不清。读取 brand 字段（offset 8-11）细分类。
				if subExt, subCat := e.classifyFTYP(e.reader, m.Offset); subExt != "" {
					ext = subExt
					cat = subCat
				}
			case "tiff":
				// TIFF 也是一大票 RAW 格式的壳：Canon CR2、Nikon NEF、Sony ARW、Adobe DNG
				if subExt, subCat := e.classifyTIFF(e.reader, m.Offset); subExt != "" {
					ext = subExt
					cat = subCat
				}
			}

			// 根据细分后的实际扩展名更新描述
			switch ext {
			case "wav":
				desc = "WAV 音频"
			case "avi":
				desc = "AVI 视频"
			case "webp":
				desc = "WebP 图片"
			case "doc":
				desc = "Word 文档 (DOC)"
			case "xls":
				desc = "Excel 表格 (XLS)"
			case "ppt":
				desc = "PowerPoint 演示 (PPT)"
			case "docx":
				desc = "Word 文档 (DOCX)"
			case "xlsx":
				desc = "Excel 表格 (XLSX)"
			case "pptx":
				desc = "PowerPoint 演示 (PPTX)"
			case "epub":
				desc = "EPUB 电子书"
			case "odt":
				desc = "OpenDocument 文档"
			case "ods":
				desc = "OpenDocument 表格"
			case "odp":
				desc = "OpenDocument 演示"
			// --- 现代手机/相机照片格式（由 ftyp 容器细分后来到这里）---
			case "heic":
				desc = "HEIC 图片 (iPhone/现代 Android)"
			case "heif":
				desc = "HEIF 图片"
			case "avif":
				desc = "AVIF 图片 (新一代压缩)"
			case "m4a":
				desc = "M4A 音频"
			case "3gp":
				desc = "3GP 移动视频"
			case "cr3":
				desc = "Canon CR3 原始照片"
			// --- TIFF 壳下的 RAW 格式 ---
			case "cr2":
				desc = "Canon CR2 原始照片"
			case "nef":
				desc = "Nikon NEF 原始照片"
			case "arw":
				desc = "Sony ARW 原始照片"
			case "dng":
				desc = "Adobe DNG 原始照片"
			}

			// 生成可读文件名：<ext>_0x<offset>_<seq>.<ext>
			// 偏移是磁盘级唯一坐标，便于从文件名反查扫描位置、做差异核对与复查
			// （PhotoRec 的 f<offset>.<ext> 思路；这里再追加每类序号提高可读性）
			extCounter[ext]++
			seq := extCounter[ext]
			fileName := fmt.Sprintf("%s_0x%x_%06d.%s", ext, m.Offset, seq, ext)

			// 基础置信度：格式解析能得到明确边界时稍高，只能靠 footer 搜索的稍低。
			// 最终置信度由 validator 阶段根据文件结构完整性覆盖。
			baseConfidence := 0.55
			if sizeDetectionReliable(ext) {
				baseConfidence = 0.7
			}

			// 碎片化启发检测：仅对中等以上大小文件做（小文件碎片概率低）。
			// 检测到的"likely fragmented"不阻止恢复 —— 但写入 Description 让用户/manifest 看见。
			if fileSize >= 64*1024 {
				if frag := DetectFragmentation(e.reader, m.Offset, fileSize, ext); frag.LikelyFragmented {
					if desc != "" {
						desc += " · "
					}
					desc += "⚠ 可能碎片化: " + frag.Reason
					// 碎片文件的可信度打折，让低置信度路由把它们筛到 _low_confidence/
					if baseConfidence > 0.4 {
						baseConfidence = 0.4
					}
				}
			}

			// 构建恢复文件信息
			file := &types.RecoveredFile{
				ID:          fmt.Sprintf("carve_%d", m.Offset),
				Source:      "carver",
				FileName:    fileName,
				Extension:   ext,
				Category:    cat,
				Size:        fileSize,
				SizeHuman:   types.FormatSize(fileSize),
				Offset:      m.Offset,
				Confidence:  baseConfidence,
				Description: desc,
			}

			e.filesFound.Add(1)
			// 诊断：记录最终产出（用细分后的 ext，不是原始签名 ext）
			bumpCounter(&e.emittedByExt, ext)

			if onFound != nil {
				onFound(file)
			}
		}
	}()

	// ---- 等待 Collector 完成（意味着所有匹配已处理）----
	wgCollector.Wait()

	// 诊断：打印每签名的 AC 命中 vs 实际产出，帮助定位误报源
	logCarverCounters(counterSnapshot(&e.hitsByExt), counterSnapshot(&e.emittedByExt))

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
	// 所有 ISO Base Media File Format 子格式共享 atom 解析
	// （MP4/MOV/M4A/3GP/HEIC/HEIF/AVIF/CR3 等）
	case "mp4", "mov", "m4a", "3gp", "heic", "heif", "avif", "cr3":
		size = detectMP4Size(reader, offset, maxSize)
	case "mp3":
		size = detectMP3Size(reader, offset, maxSize)
	case "riff", "avi", "wav":
		size = detectRIFFSize(reader, offset, maxSize)
	case "ole2", "doc", "xls", "ppt":
		size = detectOLE2Size(reader, offset, maxSize)
	case "exe":
		size = detectEXESize(reader, offset, maxSize)
	case "bmp":
		size = detectBMPSize(reader, offset, maxSize)
	case "ico":
		size = detectICOSize(reader, offset, maxSize)
	case "aac":
		size = detectAACSize(reader, offset, maxSize)
	case "gif":
		size = detectGIFSize(reader, offset, maxSize)
	// 所有 TIFF 壳格式共享 IFD 链解析（TIFF / CR2 / NEF / ARW / DNG）
	case "tiff", "cr2", "nef", "arw", "dng":
		size = detectTIFFSize(reader, offset, maxSize)
	case "djvu":
		size = detectDjVuSize(reader, offset, maxSize)
	case "mid":
		size = detectMIDISize(reader, offset, maxSize)
	default:
		// 对未知格式，如果有 footer，搜索 footer 来确定文件边界
		if len(sig.Footers) > 0 {
			size = searchFooter(reader, offset, maxSize, sig.Footers)
		}
	}

	// 检测失败统一丢弃：返回凭空猜测的默认大小会把"签名在但实际不是该格式"的
	// 误报变成凭空伪造的垃圾文件，对用户而言比少恢复一个文件更糟。
	if size <= 0 {
		return 0
	}

	return size
}

// sizeDetectionReliable 指示某个签名是否能通过格式解析得到可靠文件大小。
// 用于 collector 判断结果文件的基础置信度。
func sizeDetectionReliable(ext string) bool {
	switch ext {
	case "jpg", "jpeg", "png", "pdf", "zip", "mp4", "mov", "m4a", "3gp",
		"mp3", "riff", "avi", "wav", "ole2", "doc", "xls", "ppt",
		"bmp", "ico", "aac", "gif", "tiff", "exe",
		// ISO Base Media File Format 子类 + TIFF 壳 RAW
		"heic", "heif", "avif", "cr3", "cr2", "nef", "arw", "dng",
		// DjVu / MIDI 结构化大小
		"djvu", "mid",
		// 新一轮：有 footer 或者结构能给出明确边界
		"flv", "vcf", "ics", "evtx", "vhd", "vmdk", "qcow2", "wal",
		"jp2", "exr", "pcap", "pcapng", "m2ts":
		return true
	default:
		return false
	}
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

// classifyFTYP 读取 ISO Base Media File Format 的 major brand（offset 8-11）细分格式。
//
// ftyp 容器里一个共同 magic 覆盖了 MP4/MOV/M4A/3GP/HEIC/HEIF/AVIF/CR3 等一大堆格式，
// 靠 brand 才能分清。手机拍的 .heic 在重置的 Windows 上如果不细分就全部挂成 .mp4 打不开。
//
// 返回空 ext 时保留默认 mp4 分类。
func (e *Engine) classifyFTYP(reader disk.DiskReader, offset int64) (string, types.FileCategory) {
	brand, err := readBytesAt(reader, offset+8, 4)
	if err != nil || len(brand) < 4 {
		return "", types.CategoryOther
	}
	// Brand 4 字节按 ASCII 比较即可；部分规范要求末位空格
	switch string(brand) {
	// HEIC / HEIF：iPhone 自 iOS 11 起默认，Android 近几年也在用
	case "heic", "heix", "heim", "heis", "hevc", "hevx":
		return "heic", types.CategoryImage
	case "mif1", "msf1", "mif2":
		return "heif", types.CategoryImage
	// AVIF：新一代 AV1 编码图片，Chrome/Firefox 原生支持，越来越多
	case "avif", "avis", "avio":
		return "avif", types.CategoryImage
	// 音频 / 视频子类
	case "M4A ", "M4B ":
		return "m4a", types.CategoryAudio
	case "3gp4", "3gp5", "3gp6", "3g2a", "3g2b":
		return "3gp", types.CategoryVideo
	case "qt  ":
		return "mov", types.CategoryVideo
	// Canon 新一代 RAW（CR3）
	case "crx ":
		return "cr3", types.CategoryImage
	}
	return "", types.CategoryOther
}

// classifyTIFF 读取 TIFF IFD 里的 Make / DNG version 等 tag，识别 RAW 格式。
//
// 为了成本可控，这里只做最轻量的检测：
//   - CR2 在 offset 8-11 有 "CR\x02\x00" 的专用 marker（Canon 老 RAW 格式，独一无二）
//   - 其他 RAW（NEF/ARW/DNG）需解析 IFD0 的 Make/DNG tag，复杂度较高，先留扩展点
//
// 返回空 ext 表示无法细分，保持原 tiff 分类。
func (e *Engine) classifyTIFF(reader disk.DiskReader, offset int64) (string, types.FileCategory) {
	// 读完整 header + offset 8 的 4 字节 marker
	head, err := readBytesAt(reader, offset, 12)
	if err != nil || len(head) < 12 {
		return "", types.CategoryOther
	}
	// CR2 marker：第 8-11 字节 "CR\x02\x00"（Canon EOS 相机的老 RAW）
	if head[8] == 'C' && head[9] == 'R' && head[10] == 0x02 && head[11] == 0x00 {
		return "cr2", types.CategoryImage
	}
	// 普通 TIFF / DNG / NEF / ARW 此处未做深度 IFD 解析，保持 tiff 分类
	return "", types.CategoryOther
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
// 读取多个 local file header 中的文件名进行判断
func (e *Engine) classifyZIP(reader disk.DiskReader, offset int64, size int64) (string, types.FileCategory) {
	// 策略1: 读取前 8KB 数据，搜索 OOXML/ODT 特征路径
	// 这比逐个解析 local file header 更健壮，因为即使文件名检查错位也能找到
	readSize := int64(16384)
	if size > 0 && readSize > size {
		readSize = size
	}
	data, err := readBytesAt(reader, offset, int(readSize))
	if err != nil || len(data) < 30 {
		return "", types.CategoryArchive
	}

	dataStr := string(data)

	// --- Office Open XML (DOCX/XLSX/PPTX) ---
	// 检查常见 OOXML 标志
	hasContentTypes := strings.Contains(dataStr, "[Content_Types].xml")
	hasRels := strings.Contains(dataStr, "_rels/")

	if hasContentTypes || hasRels {
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

	// 即使没有 [Content_Types].xml 在前 8KB，也搜索特征路径
	if strings.Contains(dataStr, "word/document.xml") || strings.Contains(dataStr, "word/styles.xml") {
		return "docx", types.CategoryDocument
	}
	if strings.Contains(dataStr, "xl/workbook.xml") || strings.Contains(dataStr, "xl/sharedStrings.xml") || strings.Contains(dataStr, "xl/worksheets/") {
		return "xlsx", types.CategoryDocument
	}
	if strings.Contains(dataStr, "ppt/presentation.xml") || strings.Contains(dataStr, "ppt/slides/") {
		return "pptx", types.CategoryDocument
	}

	// --- 解析第一个 local file header 中的文件名 ---
	nameLen := int(data[26]) | int(data[27])<<8
	if nameLen <= 0 || nameLen > 220 || 30+nameLen > len(data) {
		return "", types.CategoryArchive
	}
	extraLen := int(data[28]) | int(data[29])<<8

	firstName := string(data[30 : 30+nameLen])

	// --- EPUB ---
	if firstName == "mimetype" {
		dataOffset := 30 + nameLen + extraLen
		if dataOffset+40 <= len(data) {
			mimeData := string(data[dataOffset : dataOffset+40])
			if strings.Contains(mimeData, "epub") {
				return "epub", types.CategoryDocument
			}
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
		dataOffset := 30 + nameLen + extraLen
		if dataOffset+60 <= len(data) {
			mime := string(data[dataOffset : dataOffset+60])
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
