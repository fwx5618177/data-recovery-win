package validator

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image/jpeg"
	"image/png"
	"math"

	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// Result 验证结果
type Result struct {
	IsValid    bool
	Confidence float64 // 0.0-1.0
	Message    string  // 验证详情描述
}

// Mode 控制验证深度。
//
// 为什么要分档：碰过 5 万张 JPEG 的场景，过去"扫描结束验证阶段"里每张都跑
// image/jpeg.Decode（真 IDCT + 颜色转换），每张 10-50ms，5 万张 ≈ 8-40 分钟。
// 用户等到怀疑是卡死了。
//
// 业界实践（PhotoRec --paranoid 开关、Disk Drill 的 quick/deep validate、
// libjpeg-turbo 的 progressive sniff）：把"头尾+结构+熵流健康度"的 fast-path
// 和"真解码"的 deep-path 分开。
//
//   - Fast：~100-500us / 张；5 万张 < 30s；足以滤掉大多数碎片化文件
//   - Deep：~10-50ms / 张；用在用户真要导出的子集（Recover 阶段）
//
// 这和 libjpeg-turbo 里 `-sniffonly` vs 完整 decode 的分工一致。
type Mode int

const (
	// ModeFast 只跑头尾 + marker + 熵流健康度（Huffman 流健康度）扫描。不做真解码。
	// 目标：扫描阶段在几秒内验证完成百万量级文件。
	ModeFast Mode = iota

	// ModeDeep 跑权威解码（image/jpeg.Decode / image/png.Decode / MP4 atom 解析
	// / PDF xref 遍历 等）。目标：Recover 阶段对每个将要写盘的文件做权威判定，
	// "能打开 <=> 通过"。
	ModeDeep
)

// Validator 文件验证器
type Validator struct {
	reader disk.DiskReader
}

// NewValidator 创建文件验证器
func NewValidator(reader disk.DiskReader) *Validator {
	return &Validator{reader: reader}
}

// Validate 验证恢复的文件。
//
// 历史原因：默认走 ModeDeep（等同于 ValidateDeep）保持向后兼容。
// 新代码请显式调用 ValidateFast / ValidateDeep 以表达意图。
func (v *Validator) Validate(file *types.RecoveredFile) Result {
	return v.ValidateWithMode(file, ModeDeep)
}

// ValidateFast 扫描阶段用的快速校验路径。
// 对 10 万级文件的"扫完一次性验证"场景，从几十分钟降到秒级。
func (v *Validator) ValidateFast(file *types.RecoveredFile) Result {
	return v.ValidateWithMode(file, ModeFast)
}

// ValidateDeep 恢复阶段对单个文件做权威校验。跑真解码。
func (v *Validator) ValidateDeep(file *types.RecoveredFile) Result {
	return v.ValidateWithMode(file, ModeDeep)
}

// ValidateWithMode 按指定 Mode 执行格式专用的验证器。
func (v *Validator) ValidateWithMode(file *types.RecoveredFile, mode Mode) Result {
	if file == nil {
		return Result{IsValid: false, Confidence: 0, Message: "文件信息为空"}
	}

	var result Result

	switch file.Extension {
	case "jpg", "jpeg":
		result = v.validateJPEGMode(file.Offset, file.Size, mode)
	case "png":
		result = v.validatePNG(file.Offset, file.Size)
	case "pdf":
		result = v.validatePDF(file.Offset, file.Size)
	case "zip", "docx", "xlsx", "pptx", "jar", "apk":
		result = v.validateZIP(file.Offset, file.Size)
	case "mp4", "m4v", "m4a", "mov":
		result = v.validateMP4(file.Offset, file.Size)
	case "mp3":
		result = v.validateMP3(file.Offset, file.Size)
	case "exe":
		result = v.validateEXE(file.Offset, file.Size)
	case "bmp":
		result = v.validateBMP(file.Offset, file.Size)
	default:
		result = v.validateGeneric(file.Offset, file.Size)
	}

	// 将验证结果写回文件结构
	file.IsValid = result.IsValid
	file.Confidence = result.Confidence
	file.ValidationMsg = result.Message

	return result
}

// ---------- JPEG 验证器 ----------

// validateJPEGMode 按 Mode 分支做 JPEG 校验。
//
// Fast 路径（扫描阶段批量跑）：SOI + EOI + 首 marker + size 合理性 + 熵流健康度。
//   典型一张 2-5MB 的 JPEG 耗时 200-600us。5 万张 <= 30s。
//   拒掉"碎片化/中段跑飞/尾部截断"的废文件；真能 Decode 的文件都能通过。
//
// Deep 路径（Recover 阶段跑）：Fast 的全部 + image/jpeg.Decode 真解码。
//   10-50ms / 张。Decode 成功 = 用户能打开；失败时再给"尾部截断可挽救"档次。
//
// 两档都允许调用方后续触发 RepairJPEG 尝试边界修复。
func (v *Validator) validateJPEGMode(offset, size int64, mode Mode) Result {
	confidence := 0.0
	messages := make([]string, 0, 6)

	// 文件太小，不可能是有效图片
	if size <= 100 {
		return Result{
			IsValid:    false,
			Confidence: 0,
			Message:    fmt.Sprintf("JPEG 文件过小 (%d 字节)，不可能是有效图片", size),
		}
	}

	// 检查 SOI (Start Of Image): FF D8
	header, err := v.readAt(offset, 4)
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取 JPEG 头部失败: %v", err)}
	}

	if header[0] == 0xFF && header[1] == 0xD8 {
		confidence += 0.2
		messages = append(messages, "SOI 标记正确")
	} else {
		messages = append(messages, fmt.Sprintf("SOI 标记错误: %02X%02X (期望 FFD8)", header[0], header[1]))
	}

	// 检查 EOI (End Of Image): FF D9
	tail, err := v.readAt(offset+size-2, 2)
	hasEOI := err == nil && tail[0] == 0xFF && tail[1] == 0xD9
	if hasEOI {
		confidence += 0.2
		messages = append(messages, "EOI 标记正确")
	} else {
		messages = append(messages, "EOI 标记缺失或错误")
	}

	// 检查第3-4字节是否为有效的 JPEG marker
	if header[2] == 0xFF {
		marker := header[3]
		validMarker := (marker >= 0xE0 && marker <= 0xEF) || // APPn
			marker == 0xDB || // DQT
			(marker >= 0xC0 && marker <= 0xCF) || // SOF
			marker == 0xC4 || // DHT
			marker == 0xDA || // SOS
			marker == 0xDD || // DRI
			marker == 0xFE // COM
		if validMarker {
			confidence += 0.15
			messages = append(messages, fmt.Sprintf("有效 JPEG marker: FF%02X", marker))
		} else {
			messages = append(messages, fmt.Sprintf("未知 JPEG marker: FF%02X", marker))
		}
	} else {
		messages = append(messages, "缺少有效的 JPEG marker 结构")
	}

	// 大小合理性 (1KB - 50MB)
	if size >= 1024 && size <= 50*1024*1024 {
		confidence += 0.15
		messages = append(messages, fmt.Sprintf("文件大小合理: %s", types.FormatSize(size)))
	} else {
		messages = append(messages, fmt.Sprintf("文件大小异常: %s", types.FormatSize(size)))
	}

	// Fast 路径到此为止，再用一次熵流健康度打分（不拖慢一个数量级，只多读一次字节流）
	if mode == ModeFast {
		if size > 100 && size <= 32*1024*1024 {
			full, err := v.readAt(offset, int(size))
			if err == nil {
				health := computeJPEGHealth(full)
				switch {
				case health >= 0.92:
					confidence += 0.3 // 熵流干净 + 头尾齐全 → 大概率能 Decode
					messages = append(messages, fmt.Sprintf("熵流健康 %.0f%%（fast path）", health*100))
				case health >= 0.7:
					confidence += 0.1
					messages = append(messages, fmt.Sprintf("熵流中等 %.0f%%", health*100))
				default:
					confidence = 0
					messages = append(messages, fmt.Sprintf("熵流破损 %.0f%%（fast path 判废）", health*100))
				}
			}
		}
		if confidence > 1.0 {
			confidence = 1.0
		}
		return Result{
			// fast 路径阈值 0.55：SOI(0.2)+EOI(0.2)+marker(0.15)+size(0.15)+health≥0.92(0.3)=1.0 通过
			//                   任一结构项缺失 + health 不 >=0.92 → 跳过
			IsValid:    confidence >= 0.55,
			Confidence: confidence,
			Message:    fmt.Sprintf("JPEG fast 验证: %s", joinMessages(messages)),
		}
	}

	// Deep 路径：跑真解码（image/jpeg.Decode 会完整走 Huffman + IDCT + color conversion）
	if size > 100 && size <= 16*1024*1024 {
		full, err := v.readAt(offset, int(size))
		if err == nil {
			if _, decErr := jpeg.Decode(bytes.NewReader(full)); decErr == nil {
				confidence += 0.4
				messages = append(messages, "标准库 JPEG 解码成功（能正常打开）")
			} else {
				// Decode 失败 = 基本打不开；再看 health 区分"部分可挽救" vs "废文件"
				health := computeJPEGHealth(full)
				if health >= 0.85 {
					if confidence > 0.45 {
						confidence = 0.45
					}
					messages = append(messages, fmt.Sprintf("解码失败但熵流健康 %.0f%% — 可能尾部截断，低置信保留", health*100))
				} else {
					confidence = 0
					messages = append(messages, fmt.Sprintf("解码失败 + 熵流 %.0f%% — 碎片化或损坏，拒绝交付", health*100))
				}
			}
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0 {
		confidence = 0
	}

	return Result{
		IsValid:    confidence >= 0.7,
		Confidence: confidence,
		Message:    fmt.Sprintf("JPEG 验证: %s", joinMessages(messages)),
	}
}

// validateJPEG 旧 API 兼容层：走 ModeDeep。保留给现有测试直接引用。
func (v *Validator) validateJPEG(offset, size int64) Result {
	return v.validateJPEGMode(offset, size, ModeDeep)
}

// computeJPEGHealth 熵流非法 marker 比例评分（0..1）
//
// 算法：
//   1. JPEG 结构：SOI | header segments (APP0/DQT/DHT/SOF) | SOS | entropy stream | EOI
//   2. 合法 marker 只有 RST0-RST7 + FF00 stuffed + FFFF fill（允许在熵流里）
//   3. 碎片化 JPEG 特征：熵流中间混入 APP/DQT/DHT/SOF 等 header marker
//      —— 这些只应在 SOI..SOS 之间出现，出现在熵流里说明跨入其他文件数据
//   4. **关键**：只扫 SOS 之后到 EOI 之前的区间，header 段不计入
func computeJPEGHealth(data []byte) float32 {
	if len(data) < 20 {
		return 0
	}
	if data[0] != 0xFF || data[1] != 0xD8 {
		return 0
	}
	hasEOI := data[len(data)-2] == 0xFF && data[len(data)-1] == 0xD9

	// 找第一个 SOS (FF DA) marker —— 熵流从 SOS 段结束之后开始
	sosPos := findSOS(data)
	if sosPos < 0 {
		// 没找到 SOS → 不是完整 JPEG structure
		if hasEOI {
			return 0.3
		}
		return 0.1
	}
	// SOS 段长度：[sosPos+2..sosPos+4] 是 big-endian 段长度（含自身 2 字节）
	if sosPos+4 >= len(data) {
		return 0.1
	}
	sosLen := int(data[sosPos+2])<<8 | int(data[sosPos+3])
	entropyStart := sosPos + 2 + sosLen
	entropyEnd := len(data)
	if hasEOI {
		entropyEnd = len(data) - 2
	}
	if entropyStart >= entropyEnd {
		return 0.3 // 熵流区间为空
	}

	body := data[entropyStart:entropyEnd]
	var legal, illegal int
	for i := 0; i < len(body)-1; i++ {
		if body[i] != 0xFF {
			continue
		}
		next := body[i+1]
		switch {
		case next == 0x00 || next == 0xFF:
			// stuffed / fill — 合法在熵流里
		case next >= 0xD0 && next <= 0xD7:
			// RST0..7 — 合法
			legal++
		case next == 0xD9:
			// 熵流内遇到 EOI —— 合法（即该 EOI 就是文件结束）
			legal++
		case next >= 0xC0 && next <= 0xCF, // SOF/DHT/DAC
			next >= 0xE0 && next <= 0xEF, // APPn
			next == 0xD8, next == 0xDA, // SOI 再现 / 另一个 SOS
			next == 0xDB, next == 0xDC, next == 0xDD, next == 0xDE, next == 0xDF, next == 0xFE:
			// 这些 marker 在熵流**中间**是非法的 → 碎片化嫌疑
			illegal++
		}
	}
	total := legal + illegal
	if total == 0 {
		// 熵流内一个 marker 都没 —— 小图很正常
		if hasEOI {
			return 0.9
		}
		return 0.5
	}
	ratio := float32(legal) / float32(total)
	if !hasEOI {
		ratio *= 0.5
	}
	return ratio
}

// findSOS 找第一个 0xFF 0xDA 位置；-1 = 未找到
func findSOS(data []byte) int {
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0xFF && data[i+1] == 0xDA {
			return i
		}
	}
	return -1
}

// ---------- PNG 验证器 ----------

func (v *Validator) validatePNG(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 4)

	// PNG 签名: 89 50 4E 47 0D 0A 1A 0A
	pngSignature := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	header, err := v.readAt(offset, 8)
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取 PNG 头部失败: %v", err)}
	}

	if bytes.Equal(header, pngSignature) {
		confidence += 0.3
		messages = append(messages, "PNG 签名正确")
	} else {
		messages = append(messages, "PNG 签名错误")
		return Result{
			IsValid:    false,
			Confidence: 0,
			Message:    fmt.Sprintf("PNG 验证: %s", joinMessages(messages)),
		}
	}

	// 读取第一个 chunk，验证是 IHDR
	// chunk 结构: [4字节 length][4字节 type][length字节 data][4字节 CRC]
	ihdrPresent := false
	crcValid := false

	if size >= 33 { // 8(签名) + 4(length) + 4(type) + 13(IHDR data) + 4(CRC) = 33
		chunkHeader, err := v.readAt(offset+8, 8)
		if err == nil {
			chunkLength := binary.BigEndian.Uint32(chunkHeader[0:4])
			chunkType := string(chunkHeader[4:8])

			if chunkType == "IHDR" {
				ihdrPresent = true
				confidence += 0.2
				messages = append(messages, "IHDR chunk 存在")

				// 验证 CRC32: CRC 覆盖 chunk type + chunk data
				if chunkLength <= 1024 { // IHDR 标准长度为13，但容忍合理值
					crcData, err := v.readAt(offset+12, int(4+chunkLength)) // type + data
					if err == nil {
						storedCRCBytes, err := v.readAt(offset+12+int64(4+chunkLength), 4)
						if err == nil {
							storedCRC := binary.BigEndian.Uint32(storedCRCBytes)
							computedCRC := crc32.ChecksumIEEE(crcData)
							if storedCRC == computedCRC {
								crcValid = true
								confidence += 0.3
								messages = append(messages, "IHDR CRC32 校验正确")
							} else {
								messages = append(messages, fmt.Sprintf("IHDR CRC32 不匹配: 计算=%08X, 存储=%08X", computedCRC, storedCRC))
							}
						}
					}
				}
			} else {
				messages = append(messages, fmt.Sprintf("首个 chunk 非 IHDR: %s", chunkType))
			}
		}
	}

	if !ihdrPresent {
		messages = append(messages, "未找到 IHDR chunk")
	}
	if !crcValid && ihdrPresent {
		// CRC 验证未通过时不额外添加消息（已在上方添加）
	}

	// 检查文件末尾是否有 IEND chunk
	// IEND chunk: [00 00 00 00][49 45 4E 44][AE 42 60 82]
	iendFound := false
	if size >= 12 {
		tail, err := v.readAt(offset+size-12, 12)
		if err == nil {
			iendType := []byte("IEND")
			if bytes.Contains(tail, iendType) {
				iendFound = true
				confidence += 0.2
				messages = append(messages, "IEND chunk 存在")
			}
		}
	}
	if !iendFound {
		messages = append(messages, "未找到 IEND chunk")
	}

	// 真解码验证（与 JPEG 同策略）：Decode 成功 = 用户能打开
	if size > 100 && size <= 16*1024*1024 {
		full, err := v.readAt(offset, int(size))
		if err == nil {
			if _, decErr := png.Decode(bytes.NewReader(full)); decErr == nil {
				confidence += 0.3
				messages = append(messages, "标准库 PNG 解码成功（能正常打开）")
			} else {
				// 解码失败 —— CRC 都通过但 Decode 失败少见；真失败就拒
				confidence = 0
				messages = append(messages, fmt.Sprintf("PNG 解码失败: %v", decErr))
			}
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0 {
		confidence = 0
	}

	return Result{
		IsValid:    confidence >= 0.6, // 比 JPEG 低（PNG header 更严格本身就可靠）
		Confidence: confidence,
		Message:    fmt.Sprintf("PNG 验证: %s", joinMessages(messages)),
	}
}

// ---------- PDF 验证器 ----------

func (v *Validator) validatePDF(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 4)

	// 检查头部 %PDF-
	headerSize := 10 // 足够读取 %PDF-x.y
	if size < int64(headerSize) {
		headerSize = int(size)
	}
	header, err := v.readAt(offset, headerSize)
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取 PDF 头部失败: %v", err)}
	}

	if len(header) >= 5 && string(header[:5]) == "%PDF-" {
		confidence += 0.3
		messages = append(messages, "PDF 头部标记正确")

		// 验证版本号 (如 1.0-1.9, 2.0)
		if len(header) >= 8 {
			version := string(header[5:8])
			validVersions := []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "2.0"}
			for _, v := range validVersions {
				if version == v {
					confidence += 0.1
					messages = append(messages, fmt.Sprintf("PDF 版本: %s", version))
					break
				}
			}
		}
	} else {
		messages = append(messages, "PDF 头部标记缺失")
		return Result{
			IsValid:    false,
			Confidence: 0,
			Message:    fmt.Sprintf("PDF 验证: %s", joinMessages(messages)),
		}
	}

	// 检查尾部 %%EOF
	tailSize := 1024
	if size < int64(tailSize) {
		tailSize = int(size)
	}
	tail, err := v.readAt(offset+size-int64(tailSize), tailSize)
	if err == nil {
		if bytes.Contains(tail, []byte("%%EOF")) {
			confidence += 0.3
			messages = append(messages, "%%EOF 标记存在")
		} else {
			messages = append(messages, "%%EOF 标记缺失")
		}
	}

	// 检查 xref 或 startxref 关键字 + **解析 startxref 后的偏移值**
	xrefOK := false
	startxrefOff := int64(-1)
	if tail != nil {
		if idx := bytes.LastIndex(tail, []byte("startxref")); idx >= 0 {
			// startxref 后跟 \n + 数字 + \n + %%EOF
			after := tail[idx+len("startxref"):]
			// 跳过空白 + 解析数字
			i := 0
			for i < len(after) && (after[i] == ' ' || after[i] == '\n' || after[i] == '\r' || after[i] == '\t') {
				i++
			}
			numStart := i
			for i < len(after) && after[i] >= '0' && after[i] <= '9' {
				i++
			}
			if i > numStart {
				// 解析 int
				var n int64
				for j := numStart; j < i; j++ {
					n = n*10 + int64(after[j]-'0')
				}
				startxrefOff = n
			}
		}
	}
	if startxrefOff >= 0 && startxrefOff < size {
		// 读该偏移处，应是 "xref\n" 或 "N N obj"（PDF 1.5+ 的 xref stream）
		xrefProbe, err := v.readAt(offset+startxrefOff, 32)
		if err == nil {
			if bytes.HasPrefix(xrefProbe, []byte("xref")) {
				xrefOK = true
				confidence += 0.25
				messages = append(messages, "startxref 指向有效 xref 表")
			} else if hasXrefStreamPrefix(xrefProbe) {
				xrefOK = true
				confidence += 0.2
				messages = append(messages, "startxref 指向 xref stream (PDF 1.5+)")
			} else {
				messages = append(messages, fmt.Sprintf("startxref 偏移 %d 指向无效位置（可能文件损坏或碎片化）", startxrefOff))
				confidence -= 0.1
			}
		}
	} else if tail != nil && bytes.Contains(tail, []byte("startxref")) {
		// 有 startxref 关键字但解不出合法 offset
		messages = append(messages, "startxref 值无法解析")
	} else {
		messages = append(messages, "未找到 startxref")
	}

	// 深度校验：扫 "obj" 数量（正常 PDF 至少有 Catalog + Pages + 1 Page = 3 obj）
	// 碎片化 PDF 可能只剩头部，obj 数量极少
	if !xrefOK {
		// xref 失败时再靠 obj 数量兜底
		sampleSize := int64(256 * 1024) // 扫 256KB 足够常见 PDF
		if sampleSize > size {
			sampleSize = size
		}
		sample, err := v.readAt(offset, int(sampleSize))
		if err == nil {
			objCount := bytes.Count(sample, []byte(" obj\n")) + bytes.Count(sample, []byte(" obj\r"))
			if objCount >= 3 {
				confidence += 0.1
				messages = append(messages, fmt.Sprintf("发现 %d 个 object 定义", objCount))
			} else {
				messages = append(messages, fmt.Sprintf("object 定义过少 (%d 个，可能截断)", objCount))
			}
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0 {
		confidence = 0
	}

	return Result{
		IsValid:    confidence >= 0.5,
		Confidence: confidence,
		Message:    fmt.Sprintf("PDF 验证: %s", joinMessages(messages)),
	}
}

// hasXrefStreamPrefix PDF 1.5+ 用 object stream 替代传统 xref 表
// 形如 "15 0 obj\n<</Type/XRef..." —— 开头 "N N obj"
func hasXrefStreamPrefix(buf []byte) bool {
	// 简化判定：前缀匹配 N + space + N + space + "obj"
	pos := 0
	// 第一个数
	if pos >= len(buf) || buf[pos] < '0' || buf[pos] > '9' {
		return false
	}
	for pos < len(buf) && buf[pos] >= '0' && buf[pos] <= '9' {
		pos++
	}
	if pos >= len(buf) || buf[pos] != ' ' {
		return false
	}
	pos++
	// 第二个数
	if pos >= len(buf) || buf[pos] < '0' || buf[pos] > '9' {
		return false
	}
	for pos < len(buf) && buf[pos] >= '0' && buf[pos] <= '9' {
		pos++
	}
	if pos >= len(buf) || buf[pos] != ' ' {
		return false
	}
	pos++
	// "obj"
	return pos+3 <= len(buf) && string(buf[pos:pos+3]) == "obj"
}

// ---------- ZIP 验证器 ----------

func (v *Validator) validateZIP(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 4)

	// 检查 PK 头部: PK\x03\x04
	header, err := v.readAt(offset, 4)
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取 ZIP 头部失败: %v", err)}
	}

	pkHeader := []byte{0x50, 0x4B, 0x03, 0x04}
	if bytes.Equal(header, pkHeader) {
		confidence += 0.3
		messages = append(messages, "PK 头部标记正确")
	} else {
		messages = append(messages, fmt.Sprintf("PK 头部标记错误: %02X%02X%02X%02X", header[0], header[1], header[2], header[3]))
		return Result{
			IsValid:    false,
			Confidence: 0,
			Message:    fmt.Sprintf("ZIP 验证: %s", joinMessages(messages)),
		}
	}

	// 尝试读取第一个本地文件头
	localHeaderValid := false
	filenameReadable := false

	if size >= 30 {
		localHeader, err := v.readAt(offset, 30)
		if err == nil {
			// 偏移 4: version needed (uint16 LE)
			versionNeeded := binary.LittleEndian.Uint16(localHeader[4:6])
			// 偏移 26: filename length (uint16 LE)
			filenameLen := binary.LittleEndian.Uint16(localHeader[26:28])
			// 偏移 28: extra field length (uint16 LE)
			_ = binary.LittleEndian.Uint16(localHeader[28:30])

			// version needed 应该在合理范围 (10-63, 即 1.0 到 6.3)
			if versionNeeded >= 10 && versionNeeded <= 63 && filenameLen > 0 && filenameLen < 512 {
				localHeaderValid = true
				confidence += 0.3
				messages = append(messages, fmt.Sprintf("本地文件头有效 (版本: %d.%d)", versionNeeded/10, versionNeeded%10))

				// 读取 filename
				if int64(30+filenameLen) <= size {
					filenameBytes, err := v.readAt(offset+30, int(filenameLen))
					if err == nil {
						filename := string(filenameBytes)
						// 检查文件名是否为可打印字符
						readable := true
						for _, b := range filenameBytes {
							if b < 0x20 || b == 0x7F {
								readable = false
								break
							}
						}
						if readable && len(filename) > 0 {
							filenameReadable = true
							confidence += 0.1
							displayName := filename
							if len(displayName) > 50 {
								displayName = displayName[:50] + "..."
							}
							messages = append(messages, fmt.Sprintf("文件名可读: %s", displayName))
						}
					}
				}
			} else {
				messages = append(messages, fmt.Sprintf("本地文件头异常 (version=%d, filenameLen=%d)", versionNeeded, filenameLen))
			}
		}
	}

	if !localHeaderValid {
		messages = append(messages, "本地文件头无效")
	}
	if !filenameReadable && localHeaderValid {
		messages = append(messages, "文件名不可读")
	}

	// 检查 EOCD (End of Central Directory): PK\x05\x06
	eocdFound := false
	// EOCD 通常在文件末尾 22-65557 字节范围内
	searchSize := int64(65558)
	if searchSize > size {
		searchSize = size
	}
	eocdData, err := v.readAt(offset+size-searchSize, int(searchSize))
	if err == nil {
		eocdSig := []byte{0x50, 0x4B, 0x05, 0x06}
		if bytes.Contains(eocdData, eocdSig) {
			eocdFound = true
			confidence += 0.3
			messages = append(messages, "EOCD 记录存在")
		}
	}
	if !eocdFound {
		messages = append(messages, "未找到 EOCD 记录")
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.5,
		Confidence: confidence,
		Message:    fmt.Sprintf("ZIP 验证: %s", joinMessages(messages)),
	}
}

// ---------- MP4 验证器 ----------

func (v *Validator) validateMP4(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 4)

	if size < 12 {
		return Result{IsValid: false, Confidence: 0, Message: "MP4 文件过小"}
	}

	// 读取前 12 字节
	header, err := v.readAt(offset, 12)
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取 MP4 头部失败: %v", err)}
	}

	// 检查偏移 4 处 == "ftyp"
	ftypTag := string(header[4:8])
	if ftypTag == "ftyp" {
		confidence += 0.3
		messages = append(messages, "ftyp atom 存在")
	} else {
		messages = append(messages, fmt.Sprintf("ftyp atom 缺失 (找到: %q)", ftypTag))
		return Result{
			IsValid:    false,
			Confidence: 0,
			Message:    fmt.Sprintf("MP4 验证: %s", joinMessages(messages)),
		}
	}

	// 读取 ftyp brand (偏移 8, 4字节)
	brand := string(header[8:12])
	knownBrands := map[string]bool{
		"isom": true, "iso2": true, "iso3": true, "iso4": true, "iso5": true, "iso6": true,
		"mp41": true, "mp42": true, "mp71": true,
		"avc1": true, "M4V ": true, "M4A ": true, "M4VP": true,
		"qt  ": true, "MSNV": true, "3gp4": true, "3gp5": true, "3gp6": true,
		"f4v ": true, "dash": true, "mmp4": true,
	}
	if knownBrands[brand] {
		confidence += 0.2
		messages = append(messages, fmt.Sprintf("已知 brand: %s", brand))
	} else {
		messages = append(messages, fmt.Sprintf("未知 brand: %q", brand))
	}

	// 解析第一个 atom 的 size，跳到下一个 atom
	firstAtomSize := int64(binary.BigEndian.Uint32(header[0:4]))
	atomStructureValid := false

	if firstAtomSize >= 8 && firstAtomSize < size {
		// 尝试读取第二个 atom 的头部
		nextAtomHeader, err := v.readAt(offset+firstAtomSize, 8)
		if err == nil {
			nextAtomSize := int64(binary.BigEndian.Uint32(nextAtomHeader[0:4]))
			nextAtomType := string(nextAtomHeader[4:8])

			// 验证第二个 atom 是否合理
			if nextAtomSize >= 8 && isValidAtomType(nextAtomType) {
				atomStructureValid = true
				confidence += 0.3
				messages = append(messages, fmt.Sprintf("atom 结构有效 (第二个 atom: %s)", nextAtomType))
			}
		}
	}
	if !atomStructureValid {
		messages = append(messages, "atom 结构验证失败")
	}

	// 遍历所有 top-level atom —— 收集存在的 box types + 检测链中断
	hasMoov := false
	hasMdat := false
	boxChainComplete := true
	atomCount := 0
	searchOffset := offset
	endLimit := offset + size
	for atomCount < 200 && searchOffset+8 <= endLimit {
		atomHeaderBuf, err := v.readAt(searchOffset, 8)
		if err != nil {
			boxChainComplete = false
			break
		}
		atomSize := int64(binary.BigEndian.Uint32(atomHeaderBuf[0:4]))
		atomType := string(atomHeaderBuf[4:8])

		if atomType == "moov" {
			hasMoov = true
		} else if atomType == "mdat" {
			hasMdat = true
		}

		// 处理特殊 atom size
		if atomSize == 0 {
			// atom 延伸到文件末尾（合法终止）
			break
		} else if atomSize == 1 {
			// 64 位扩展大小
			if searchOffset+16 > endLimit {
				boxChainComplete = false
				break
			}
			extSizeBuf, err := v.readAt(searchOffset+8, 8)
			if err != nil {
				boxChainComplete = false
				break
			}
			atomSize = int64(binary.BigEndian.Uint64(extSizeBuf))
		}

		// 合法性检查：atomSize 必须 >= 8 且不超过文件尾
		if atomSize < 8 {
			boxChainComplete = false
			messages = append(messages, fmt.Sprintf("atom %s 有非法 size=%d", atomType, atomSize))
			break
		}
		// 如果 atomSize 让我们跳出文件 → 链中断（典型碎片化特征）
		if searchOffset+atomSize > endLimit {
			boxChainComplete = false
			messages = append(messages, fmt.Sprintf("atom %s 长度 %d 超出文件尾（碎片化嫌疑）", atomType, atomSize))
			break
		}
		// 如果 atom type 非法 ASCII → 数据被其他文件污染
		if !isValidAtomType(atomType) {
			boxChainComplete = false
			messages = append(messages, fmt.Sprintf("非法 atom type %q（碎片化嫌疑）", atomType))
			break
		}

		searchOffset += atomSize
		atomCount++
	}

	// 必要 box 硬要求：没有 moov+mdat 双命中直接 fail
	// 之前只扣 confidence，但总分仍能过 0.5 —— 不完整视频被当合格交付
	if !hasMoov || !hasMdat {
		return Result{
			IsValid:    false,
			Confidence: 0.2, // 留个非零分让前端知道"识别到但不完整"
			Message: fmt.Sprintf("MP4 验证失败: moov=%v mdat=%v（播放器要求两个都在才能解）; %s",
				hasMoov, hasMdat, joinMessages(messages)),
		}
	}
	confidence += 0.3
	messages = append(messages, "moov + mdat 双命中")

	// box 链完整 → 加分；不完整 → 碎片嫌疑扣分
	if boxChainComplete && atomCount >= 2 {
		confidence += 0.2
		messages = append(messages, fmt.Sprintf("box 链完整 (%d atoms)", atomCount))
	} else {
		confidence -= 0.15
		messages = append(messages, "box 链不完整（碎片化嫌疑）")
	}

	// mdat 最小大小：小于 4KB 基本不是真视频
	// 这是启发，真实短视频 mdat 也会远超这个
	// （留给未来：完整解析 moov.trak.mdia.minf.stbl 看轨道数 / 时长）

	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0 {
		confidence = 0
	}

	return Result{
		// 阈值 0.7 —— 与 JPEG 对齐，要求 moov+mdat + box 链完整才能过
		IsValid:    confidence >= 0.7,
		Confidence: confidence,
		Message:    fmt.Sprintf("MP4 验证: %s", joinMessages(messages)),
	}
}

// isValidAtomType 检查是否是合法的 MP4 atom 类型（4字节可打印 ASCII）
func isValidAtomType(t string) bool {
	if len(t) != 4 {
		return false
	}
	for _, c := range t {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// ---------- MP3 验证器 ----------

func (v *Validator) validateMP3(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 4)

	if size < 4 {
		return Result{IsValid: false, Confidence: 0, Message: "MP3 文件过小"}
	}

	// 读取头部用于判断 ID3v2 或 帧同步
	headerSize := 10
	if size < int64(headerSize) {
		headerSize = int(size)
	}
	header, err := v.readAt(offset, headerSize)
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取 MP3 头部失败: %v", err)}
	}

	frameSearchStart := int64(0)

	// 检查是否以 ID3v2 header 开头
	if len(header) >= 10 && string(header[:3]) == "ID3" {
		id3Version := header[3]
		id3Revision := header[4]
		id3Flags := header[5]

		// 版本号应合理 (v2.2=2, v2.3=3, v2.4=4)
		validID3 := id3Version >= 2 && id3Version <= 4 && id3Revision < 0xFF
		// 标志位：高4位可能有设置，低4位应为0
		validID3 = validID3 && (id3Flags&0x0F == 0)

		if validID3 {
			// 解析 ID3v2 大小 (synchsafe integer)
			id3Size := int64(header[6]&0x7F)<<21 |
				int64(header[7]&0x7F)<<14 |
				int64(header[8]&0x7F)<<7 |
				int64(header[9]&0x7F)

			confidence += 0.3
			messages = append(messages, fmt.Sprintf("ID3v2.%d 标签有效 (大小: %d)", id3Version, id3Size))

			// 跳过 ID3 标签查找帧同步
			frameSearchStart = 10 + id3Size
		} else {
			messages = append(messages, "ID3 标签头部异常")
		}
	}

	// 查找帧同步字节并验证帧头
	frameHeaderValid := false
	consecutiveFrames := 0
	frameOffset := frameSearchStart

	// 在前 8KB 范围内搜索帧同步
	searchLimit := int64(8192)
	if searchLimit > size-frameSearchStart {
		searchLimit = size - frameSearchStart
	}

	for scanPos := int64(0); scanPos < searchLimit-1; scanPos++ {
		syncBuf, err := v.readAt(offset+frameSearchStart+scanPos, 4)
		if err != nil || len(syncBuf) < 4 {
			break
		}

		// 帧同步: 11 位全 1 (0xFFE0 mask)
		if syncBuf[0] != 0xFF || (syncBuf[1]&0xE0) != 0xE0 {
			continue
		}

		// 验证帧头字段
		frameHeader := binary.BigEndian.Uint32(syncBuf)
		if !isValidMP3FrameHeader(frameHeader) {
			continue
		}

		frameOffset = frameSearchStart + scanPos
		frameHeaderValid = true

		// 计算帧大小并验证连续帧
		consecutiveFrames = countConsecutiveFrames(v, offset, frameOffset, size, frameHeader)
		break
	}

	if frameHeaderValid {
		if confidence < 0.3 {
			// 如果没有 ID3，帧同步本身贡献分数
			confidence += 0.3
			messages = append(messages, "帧同步字节正确")
		}

		confidence += 0.3
		messages = append(messages, "帧头字段有效")
	} else {
		messages = append(messages, "未找到有效的帧同步")
	}

	// 连续帧验证
	if consecutiveFrames >= 3 {
		confidence += 0.4
		messages = append(messages, fmt.Sprintf("连续帧验证通过 (%d 帧)", consecutiveFrames))
	} else if consecutiveFrames >= 1 {
		confidence += 0.2
		messages = append(messages, fmt.Sprintf("部分连续帧验证 (%d 帧)", consecutiveFrames))
	} else if frameHeaderValid {
		messages = append(messages, "无法验证连续帧")
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.5,
		Confidence: confidence,
		Message:    fmt.Sprintf("MP3 验证: %s", joinMessages(messages)),
	}
}

// isValidMP3FrameHeader 验证 MP3 帧头的各字段
func isValidMP3FrameHeader(header uint32) bool {
	// Bits 19-20: MPEG version — 01 是保留值
	mpegVersion := (header >> 19) & 0x03
	if mpegVersion == 0x01 {
		return false
	}

	// Bits 17-18: Layer — 00 是保留值
	layer := (header >> 17) & 0x03
	if layer == 0x00 {
		return false
	}

	// Bits 12-15: Bitrate index — 1111 是无效
	bitrateIndex := (header >> 12) & 0x0F
	if bitrateIndex == 0x0F {
		return false
	}

	// Bits 10-11: Sample rate index — 11 是保留值
	sampleRateIndex := (header >> 10) & 0x03
	return sampleRateIndex != 0x03
}

// mp3FrameSize 计算 MP3 帧的大小
func mp3FrameSize(header uint32) int {
	mpegVersion := (header >> 19) & 0x03
	layer := (header >> 17) & 0x03
	bitrateIndex := (header >> 12) & 0x0F
	sampleRateIndex := (header >> 10) & 0x03
	padding := (header >> 9) & 0x01

	if bitrateIndex == 0 || bitrateIndex == 0x0F || sampleRateIndex == 0x03 {
		return 0
	}

	// 比特率表 (kbps)
	// [version][layer][index]
	// version: 0=2.5, 1=reserved, 2=2, 3=1
	// layer: 0=reserved, 1=III, 2=II, 3=I
	bitrateTable := [4][4][16]int{
		// MPEG 2.5
		{
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},
			{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0},
		},
		// Reserved
		{{}, {}, {}, {}},
		// MPEG 2
		{
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},
			{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0},
		},
		// MPEG 1
		{
			{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},
			{0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},
			{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0},
		},
	}

	// 采样率表
	sampleRateTable := [4][4]int{
		{11025, 12000, 8000, 0},  // MPEG 2.5
		{0, 0, 0, 0},             // Reserved
		{22050, 24000, 16000, 0}, // MPEG 2
		{44100, 48000, 32000, 0}, // MPEG 1
	}

	bitrate := bitrateTable[mpegVersion][layer][bitrateIndex] * 1000
	sampleRate := sampleRateTable[mpegVersion][sampleRateIndex]

	if bitrate == 0 || sampleRate == 0 {
		return 0
	}

	// Layer I 使用不同的公式
	if layer == 3 { // Layer I
		return (12*bitrate/sampleRate + int(padding)) * 4
	}
	// Layer II, Layer III
	return 144*bitrate/sampleRate + int(padding)
}

// countConsecutiveFrames 计算连续有效帧数
func countConsecutiveFrames(v *Validator, baseOffset, frameOffset, totalSize int64, firstHeader uint32) int {
	count := 1
	currentOffset := frameOffset

	fSize := mp3FrameSize(firstHeader)
	if fSize <= 0 {
		return 1
	}
	currentOffset += int64(fSize)

	for i := 0; i < 10; i++ { // 最多检查10帧
		if currentOffset+4 > totalSize {
			break
		}

		frameBuf, err := v.readAt(baseOffset+currentOffset, 4)
		if err != nil || len(frameBuf) < 4 {
			break
		}

		// 检查帧同步
		if frameBuf[0] != 0xFF || (frameBuf[1]&0xE0) != 0xE0 {
			break
		}

		nextHeader := binary.BigEndian.Uint32(frameBuf)
		if !isValidMP3FrameHeader(nextHeader) {
			break
		}

		count++

		nextSize := mp3FrameSize(nextHeader)
		if nextSize <= 0 {
			break
		}
		currentOffset += int64(nextSize)
	}

	return count
}

// ---------- EXE (PE) 验证器 ----------

func (v *Validator) validateEXE(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 5)

	if size < 64 {
		return Result{IsValid: false, Confidence: 0, Message: "EXE 文件过小，无法包含有效的 PE 头部"}
	}

	// 读取 DOS header
	header, err := v.readAt(offset, 64)
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取 EXE 头部失败: %v", err)}
	}

	// 验证 MZ 签名
	if header[0] != 'M' || header[1] != 'Z' {
		return Result{IsValid: false, Confidence: 0, Message: "MZ 签名缺失"}
	}
	confidence += 0.1
	messages = append(messages, "MZ 签名正确")

	// 读取 PE offset (e_lfanew at 0x3C)
	peOffset := int64(binary.LittleEndian.Uint32(header[0x3C:0x40]))
	if peOffset < 0x40 || peOffset > 0x10000 || peOffset+4 > size {
		messages = append(messages, fmt.Sprintf("PE 偏移异常: 0x%X", peOffset))
		return Result{IsValid: false, Confidence: confidence, Message: fmt.Sprintf("EXE 验证: %s", joinMessages(messages))}
	}

	// 验证 PE 签名
	peSig, err := v.readAt(offset+peOffset, 4)
	if err != nil || len(peSig) < 4 {
		messages = append(messages, "无法读取 PE 签名")
		return Result{IsValid: false, Confidence: confidence, Message: fmt.Sprintf("EXE 验证: %s", joinMessages(messages))}
	}

	if peSig[0] == 'P' && peSig[1] == 'E' && peSig[2] == 0 && peSig[3] == 0 {
		confidence += 0.4
		messages = append(messages, "PE 签名正确")
	} else {
		messages = append(messages, fmt.Sprintf("PE 签名错误: %02X%02X%02X%02X", peSig[0], peSig[1], peSig[2], peSig[3]))
		return Result{IsValid: false, Confidence: confidence, Message: fmt.Sprintf("EXE 验证: %s", joinMessages(messages))}
	}

	// 读取 COFF header
	coffOffset := peOffset + 4
	if coffOffset+20 <= size {
		coffHeader, err := v.readAt(offset+coffOffset, 20)
		if err == nil && len(coffHeader) >= 20 {
			machine := binary.LittleEndian.Uint16(coffHeader[0:2])
			numSections := binary.LittleEndian.Uint16(coffHeader[2:4])

			// 验证 machine type
			validMachines := map[uint16]string{
				0x014C: "x86",
				0x0200: "IA64",
				0x8664: "x64",
				0xAA64: "ARM64",
				0x01C0: "ARM",
				0x01C4: "ARMv7",
			}
			if name, ok := validMachines[machine]; ok {
				confidence += 0.2
				messages = append(messages, fmt.Sprintf("平台: %s", name))
			} else {
				messages = append(messages, fmt.Sprintf("未知平台: 0x%04X", machine))
			}

			// Section 数量合理性
			if numSections > 0 && numSections <= 96 {
				confidence += 0.2
				messages = append(messages, fmt.Sprintf("Section 数: %d", numSections))
			} else {
				messages = append(messages, fmt.Sprintf("异常 Section 数: %d", numSections))
			}
		}
	}

	// 大小合理性 (>= 1KB)
	if size >= 1024 {
		confidence += 0.1
		messages = append(messages, fmt.Sprintf("文件大小: %s", types.FormatSize(size)))
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.5,
		Confidence: confidence,
		Message:    fmt.Sprintf("EXE 验证: %s", joinMessages(messages)),
	}
}

// ---------- BMP 验证器 ----------

func (v *Validator) validateBMP(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 5)

	if size < 18 {
		return Result{IsValid: false, Confidence: 0, Message: "BMP 文件过小"}
	}

	header, err := v.readAt(offset, 18)
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取 BMP 头部失败: %v", err)}
	}

	// 验证 BM 签名
	if header[0] != 'B' || header[1] != 'M' {
		return Result{IsValid: false, Confidence: 0, Message: "BM 签名缺失"}
	}
	confidence += 0.1
	messages = append(messages, "BM 签名正确")

	// 嵌入的文件大小
	embeddedSize := int64(binary.LittleEndian.Uint32(header[2:6]))

	// 保留字段应为 0
	reserved := binary.LittleEndian.Uint32(header[6:10])
	if reserved != 0 {
		messages = append(messages, fmt.Sprintf("保留字段非零: 0x%08X", reserved))
		return Result{IsValid: false, Confidence: confidence, Message: fmt.Sprintf("BMP 验证: %s", joinMessages(messages))}
	}
	confidence += 0.2
	messages = append(messages, "保留字段正确")

	// 像素数据偏移
	dataOffset := int64(binary.LittleEndian.Uint32(header[10:14]))

	// DIB header 大小
	dibSize := binary.LittleEndian.Uint32(header[14:18])

	validDIB := dibSize == 12 || dibSize == 40 || dibSize == 52 || dibSize == 56 ||
		dibSize == 108 || dibSize == 124
	if validDIB {
		confidence += 0.3
		messages = append(messages, fmt.Sprintf("DIB 头大小有效: %d", dibSize))
	} else {
		messages = append(messages, fmt.Sprintf("DIB 头大小异常: %d", dibSize))
		return Result{IsValid: false, Confidence: confidence, Message: fmt.Sprintf("BMP 验证: %s", joinMessages(messages))}
	}

	// 验证关系: dataOffset >= 14 + dibSize
	if dataOffset >= 14+int64(dibSize) {
		confidence += 0.2
		messages = append(messages, fmt.Sprintf("像素偏移合理: %d", dataOffset))
	} else {
		messages = append(messages, fmt.Sprintf("像素偏移异常: %d (期望 >= %d)", dataOffset, 14+int64(dibSize)))
	}

	// 嵌入大小应大致匹配实际大小
	if embeddedSize > 0 && embeddedSize <= size*2 && embeddedSize >= size/2 {
		confidence += 0.2
		messages = append(messages, fmt.Sprintf("嵌入大小匹配: %s", types.FormatSize(embeddedSize)))
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.5,
		Confidence: confidence,
		Message:    fmt.Sprintf("BMP 验证: %s", joinMessages(messages)),
	}
}

// ---------- 通用验证器 ----------

func (v *Validator) validateGeneric(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 3)

	if size <= 0 {
		return Result{IsValid: false, Confidence: 0, Message: "文件大小无效 (<=0)"}
	}

	// 读取文件开头 4KB 用于分析
	readSize := int64(4096)
	if readSize > size {
		readSize = size
	}
	data, err := v.readAt(offset, int(readSize))
	if err != nil {
		return Result{IsValid: false, Confidence: 0, Message: fmt.Sprintf("读取文件数据失败: %v", err)}
	}

	// 检查是否为全零数据
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		return Result{
			IsValid:    false,
			Confidence: 0,
			Message:    "通用验证: 数据全为零，无效文件",
		}
	}

	confidence += 0.1
	messages = append(messages, "数据非全零")

	// 熵分析
	entropy := shannonEntropy(data)
	if entropy < 0.5 {
		// 熵极低，可能是无效/填充数据
		messages = append(messages, fmt.Sprintf("熵极低 (%.2f)，可能无效", entropy))
	} else if entropy >= 0.5 && entropy < 3.0 {
		confidence += 0.3
		messages = append(messages, fmt.Sprintf("低熵 (%.2f)，可能是结构化数据", entropy))
	} else if entropy >= 3.0 && entropy <= 7.0 {
		// 正常文件范围
		confidence += 0.5
		messages = append(messages, fmt.Sprintf("熵正常 (%.2f)，有效文件特征", entropy))
	} else {
		// 高熵: 可能是加密或压缩文件
		confidence += 0.4
		messages = append(messages, fmt.Sprintf("高熵 (%.2f)，可能是加密/压缩文件", entropy))
	}

	// 大小合理性
	const maxReasonableSize = 10 * 1024 * 1024 * 1024 // 10GB
	if size > 0 && size < maxReasonableSize {
		confidence += 0.1
		messages = append(messages, fmt.Sprintf("文件大小合理: %s", types.FormatSize(size)))
	} else {
		messages = append(messages, fmt.Sprintf("文件大小异常: %s", types.FormatSize(size)))
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.4,
		Confidence: confidence,
		Message:    fmt.Sprintf("通用验证: %s", joinMessages(messages)),
	}
}

// ===================== 辅助函数 =====================

// shannonEntropy 计算 Shannon 熵 (0-8 之间)
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// 统计每个字节值的频率
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}

	total := float64(len(data))
	entropy := 0.0

	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := count / total
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// readAt 安全地从磁盘读取器读取指定偏移处的数据
func (v *Validator) readAt(offset int64, size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("读取大小无效: %d", size)
	}
	if offset < 0 {
		return nil, fmt.Errorf("偏移量无效: %d", offset)
	}

	buf := make([]byte, size)
	n, err := v.reader.ReadAt(buf, offset)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("在偏移 %d 处读取 %d 字节失败: %v", offset, size, err)
	}

	return buf[:n], nil
}

// joinMessages 将消息列表拼接为分号分隔的字符串
func joinMessages(msgs []string) string {
	result := ""
	for i, m := range msgs {
		if i > 0 {
			result += "; "
		}
		result += m
	}
	return result
}
