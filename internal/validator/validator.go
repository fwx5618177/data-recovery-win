package validator

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
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

// Validator 文件验证器
type Validator struct {
	reader disk.DiskReader
}

// NewValidator 创建文件验证器
func NewValidator(reader disk.DiskReader) *Validator {
	return &Validator{reader: reader}
}

// Validate 验证恢复的文件，根据扩展名选择对应的专用验证器
func (v *Validator) Validate(file *types.RecoveredFile) Result {
	if file == nil {
		return Result{IsValid: false, Confidence: 0, Message: "文件信息为空"}
	}

	var result Result

	switch file.Extension {
	case "jpg", "jpeg":
		result = v.validateJPEG(file.Offset, file.Size)
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

func (v *Validator) validateJPEG(offset, size int64) Result {
	confidence := 0.0
	messages := make([]string, 0, 4)

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
		confidence += 0.3
		messages = append(messages, "SOI 标记正确")
	} else {
		messages = append(messages, fmt.Sprintf("SOI 标记错误: %02X%02X (期望 FFD8)", header[0], header[1]))
	}

	// 检查 EOI (End Of Image): FF D9
	tail, err := v.readAt(offset+size-2, 2)
	if err == nil && tail[0] == 0xFF && tail[1] == 0xD9 {
		confidence += 0.3
		messages = append(messages, "EOI 标记正确")
	} else {
		messages = append(messages, "EOI 标记缺失或错误")
	}

	// 检查第3-4字节是否为有效的 JPEG marker
	if header[2] == 0xFF {
		marker := header[3]
		// 有效 marker: FFE0-FFEF (APP markers), FFDB (DQT), FFC0-FFCF (SOF markers) 等
		validMarker := (marker >= 0xE0 && marker <= 0xEF) || // APPn
			marker == 0xDB || // DQT
			(marker >= 0xC0 && marker <= 0xCF) || // SOF
			marker == 0xC4 || // DHT
			marker == 0xDA || // SOS
			marker == 0xDD || // DRI
			marker == 0xFE // COM
		if validMarker {
			confidence += 0.2
			messages = append(messages, fmt.Sprintf("有效 JPEG marker: FF%02X", marker))
		} else {
			messages = append(messages, fmt.Sprintf("未知 JPEG marker: FF%02X", marker))
		}
	} else {
		messages = append(messages, "缺少有效的 JPEG marker 结构")
	}

	// 大小合理性 (1KB - 50MB)
	if size >= 1024 && size <= 50*1024*1024 {
		confidence += 0.2
		messages = append(messages, fmt.Sprintf("文件大小合理: %s", types.FormatSize(size)))
	} else {
		messages = append(messages, fmt.Sprintf("文件大小异常: %s", types.FormatSize(size)))
	}

	// 限制最大置信度为 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.5,
		Confidence: confidence,
		Message:    fmt.Sprintf("JPEG 验证: %s", joinMessages(messages)),
	}
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

	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.5,
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

	// 检查 xref 或 startxref 关键字
	// 在文件尾部区域搜索
	xrefFound := false
	if tail != nil {
		if bytes.Contains(tail, []byte("startxref")) || bytes.Contains(tail, []byte("xref")) {
			xrefFound = true
		}
	}
	// 也在文件中间搜索 xref（大文件只采样前 64KB 和后 64KB）
	if !xrefFound {
		sampleSize := int64(65536)
		if sampleSize > size {
			sampleSize = size
		}
		sample, err := v.readAt(offset, int(sampleSize))
		if err == nil {
			if bytes.Contains(sample, []byte("xref")) || bytes.Contains(sample, []byte("startxref")) {
				xrefFound = true
			}
		}
	}
	if xrefFound {
		confidence += 0.3
		messages = append(messages, "xref/startxref 存在")
	} else {
		messages = append(messages, "未找到 xref/startxref")
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.5,
		Confidence: confidence,
		Message:    fmt.Sprintf("PDF 验证: %s", joinMessages(messages)),
	}
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

	// 检查是否有 moov 或 mdat atom（在前几个 atom 中搜索）
	moovMdatFound := false
	searchOffset := offset
	for i := 0; i < 20 && searchOffset < offset+size-8; i++ {
		atomHeaderBuf, err := v.readAt(searchOffset, 8)
		if err != nil {
			break
		}
		atomSize := int64(binary.BigEndian.Uint32(atomHeaderBuf[0:4]))
		atomType := string(atomHeaderBuf[4:8])

		if atomType == "moov" || atomType == "mdat" {
			moovMdatFound = true
			confidence += 0.2
			messages = append(messages, fmt.Sprintf("%s atom 存在", atomType))
			break
		}

		// 处理特殊 atom size
		if atomSize == 0 {
			// atom 延伸到文件末尾
			break
		} else if atomSize == 1 {
			// 64位扩展大小
			if searchOffset+16 > offset+size {
				break
			}
			extSizeBuf, err := v.readAt(searchOffset+8, 8)
			if err != nil {
				break
			}
			atomSize = int64(binary.BigEndian.Uint64(extSizeBuf))
		}

		if atomSize < 8 {
			break
		}
		searchOffset += atomSize
	}

	if !moovMdatFound {
		messages = append(messages, "未找到 moov/mdat atom")
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return Result{
		IsValid:    confidence >= 0.5,
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
	if sampleRateIndex == 0x03 {
		return false
	}

	return true
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
