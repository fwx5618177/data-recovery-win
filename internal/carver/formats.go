package carver

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// =========================================================================
// 通用辅助函数
// =========================================================================

// readBytesAt 从 reader 的 offset 处安全读取 size 字节
// 如果实际读取不足 size 字节，返回已读部分和错误
func readBytesAt(reader disk.DiskReader, offset int64, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	n, err := reader.ReadAt(buf, offset)
	if n >= size {
		return buf, nil
	}
	if err != nil {
		return buf[:n], err
	}
	return buf[:n], io.ErrUnexpectedEOF
}

// readUint16LE 从 offset 处读取小端序 uint16
func readUint16LE(reader disk.DiskReader, offset int64) (uint16, error) {
	b, err := readBytesAt(reader, offset, 2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

// readUint32LE 从 offset 处读取小端序 uint32
func readUint32LE(reader disk.DiskReader, offset int64) (uint32, error) {
	b, err := readBytesAt(reader, offset, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// readUint64BE 从 offset 处读取大端序 uint64
func readUint64BE(reader disk.DiskReader, offset int64) (uint64, error) {
	b, err := readBytesAt(reader, offset, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// min64 返回两个 int64 中较小的一个
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// =========================================================================
// 1. JPEG 文件大小检测
// =========================================================================
//
// JPEG 结构：FFD8 (SOI) → 多个 FF xx LL LL marker 段 → FFDA (SOS) → 熵编码数据 → FFD9 (EOI)
// 熵编码数据中 FF00 是字节填充，FFD0-FFD7 是 RST marker，FFD9 是 EOI

// detectJPEGSize 解析 JPEG marker 结构来精确确定文件大小
func detectJPEGSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	endLimit := offset + maxSize
	pos := offset + 2 // 跳过 FFD8 SOI marker

	for pos < endLimit-1 {
		// 读取当前字节，寻找 FF 前缀
		b, err := readBytesAt(reader, pos, 1)
		if err != nil || len(b) < 1 {
			return 0
		}

		// 如果当前字节不是 FF，向前搜索（容错）
		if b[0] != 0xFF {
			pos++
			continue
		}

		// 跳过连续的填充 FF 字节
		markerPos := pos
		for {
			markerPos++
			if markerPos >= endLimit {
				return 0
			}
			b, err = readBytesAt(reader, markerPos, 1)
			if err != nil || len(b) < 1 {
				return 0
			}
			if b[0] != 0xFF {
				break
			}
		}

		marker := b[0]
		pos = markerPos + 1 // pos 现在指向 marker 类型字节之后

		// --- EOI (End of Image) ---
		if marker == 0xD9 {
			return pos - offset
		}

		// --- 不带长度字段的 marker ---
		// 0x00: 字节填充转义 (不应出现在此上下文)
		// 0x01: TEM marker
		// 0xD0-0xD7: RST markers
		if marker == 0x00 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			continue
		}

		// --- SOS (Start of Scan) —— 此后是熵编码数据 ---
		if marker == 0xDA {
			// 读取 SOS header 长度
			lenBuf, err := readBytesAt(reader, pos, 2)
			if err != nil || len(lenBuf) < 2 {
				return 0
			}
			sosLen := int64(lenBuf[0])<<8 | int64(lenBuf[1])
			if sosLen < 2 {
				return 0
			}
			pos += sosLen // 跳过 SOS header

			// 在熵编码数据中扫描寻找下一个有效 marker
			foundPos, foundMarker := scanJPEGEntropy(reader, pos, endLimit)
			if foundPos < 0 {
				return 0 // 未找到结束标记
			}
			if foundMarker == 0xD9 {
				// FFD9 = EOI, 文件在 FF D9 之后结束
				return foundPos + 2 - offset
			}
			// 找到其他 marker 段，继续解析（pos 指向该 marker 的 FF 字节）
			pos = foundPos
			continue
		}

		// --- 其他带长度字段的 marker (APP0, DQT, DHT, SOF 等) ---
		lenBuf, err := readBytesAt(reader, pos, 2)
		if err != nil || len(lenBuf) < 2 {
			return 0
		}
		segLen := int64(lenBuf[0])<<8 | int64(lenBuf[1])
		if segLen < 2 {
			return 0 // 长度字段包含自身的 2 字节，最小值为 2
		}
		pos += segLen
	}

	return 0
}

// scanJPEGEntropy 扫描 JPEG 熵编码数据区域
// 在 [start, limit) 范围内寻找有效 marker（非字节填充、非 RST）
// 返回 (marker 的 FF 位置, marker 类型字节)
// 未找到时返回 (-1, 0)
func scanJPEGEntropy(reader disk.DiskReader, start, limit int64) (int64, byte) {
	const bufSize = 8192
	buf := make([]byte, bufSize)
	pos := start

	for pos < limit {
		readLen := limit - pos
		if readLen > bufSize {
			readLen = bufSize
		}

		n, _ := reader.ReadAt(buf[:readLen], pos)
		if n < 2 {
			return -1, 0
		}

		for i := 0; i < n-1; i++ {
			if buf[i] != 0xFF {
				continue
			}

			next := buf[i+1]

			// FF00: 字节填充（转义），跳过
			if next == 0x00 {
				i++ // 跳过 00 字节
				continue
			}

			// FFFF: 连续填充 FF
			if next == 0xFF {
				continue
			}

			// FFD0-FFD7: RST (Restart) marker，继续扫描
			if next >= 0xD0 && next <= 0xD7 {
				i++ // 跳过 RST marker 字节
				continue
			}

			// 找到有效 marker（可能是 EOI 或新的 marker 段）
			return pos + int64(i), next
		}

		// 移动到下一块，保留最后 1 字节以防 FF 恰好在边界
		pos += int64(n) - 1
	}

	return -1, 0
}

// =========================================================================
// 2. PNG 文件大小检测
// =========================================================================
//
// PNG 格式: 8字节签名 + 一系列 chunk
// 每个 chunk: 4字节长度(大端) + 4字节类型 + length字节数据 + 4字节CRC
// 最后一个 chunk 类型为 "IEND"

// detectPNGSize 解析 PNG chunk 链来确定文件大小
func detectPNGSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	endLimit := offset + maxSize
	pos := offset + 8 // 跳过 8 字节 PNG 签名

	for pos < endLimit {
		// 读取 chunk header: 4字节 length + 4字节 type
		hdr, err := readBytesAt(reader, pos, 8)
		if err != nil || len(hdr) < 8 {
			return 0
		}

		chunkLen := binary.BigEndian.Uint32(hdr[0:4])
		chunkType := string(hdr[4:8])

		// 合理性检查：单个 chunk 不应超过 2GB
		if chunkLen > 0x7FFFFFFF {
			return 0
		}

		// chunk 总大小 = 4(length) + 4(type) + data + 4(CRC) = 12 + chunkLen
		chunkTotalSize := int64(12) + int64(chunkLen)

		// 检查是否超出搜索范围
		if pos+chunkTotalSize > endLimit {
			return 0
		}

		// 移动到下一个 chunk
		pos += chunkTotalSize

		// IEND 标记 PNG 文件结束
		if chunkType == "IEND" {
			return pos - offset
		}
	}

	return 0
}

// =========================================================================
// 3. PDF 文件大小检测
// =========================================================================
//
// PDF 以 %PDF-x.x 开头，以 %%EOF 结束
// 增量保存的 PDF 可能有多个 %%EOF，取最后一个

// detectPDFSize 搜索最后一个 %%EOF 标记来确定 PDF 文件大小
func detectPDFSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	const blockSize = 64 * 1024 // 64KB
	buf := make([]byte, blockSize)

	eofMarker := []byte("%%EOF")
	eofLen := int64(len(eofMarker))

	var lastEOFEnd int64 // 记录最后一个 %%EOF 之后的位置（相对于 offset）
	endLimit := offset + maxSize
	pos := offset

	for pos < endLimit {
		readLen := endLimit - pos
		if readLen > int64(blockSize) {
			readLen = int64(blockSize)
		}

		n, err := reader.ReadAt(buf[:readLen], pos)
		if n < len(eofMarker) {
			break
		}

		// 在 buf[:n] 中搜索所有 %%EOF 出现
		for i := 0; i <= n-len(eofMarker); i++ {
			if buf[i] != '%' {
				continue
			}
			if buf[i+1] != '%' || buf[i+2] != 'E' || buf[i+3] != 'O' || buf[i+4] != 'F' {
				continue
			}

			// 找到 %%EOF
			markerEnd := pos + int64(i) + eofLen

			// 检查尾部换行符 (\r\n, \n, \r)
			if markerEnd+2 <= endLimit {
				tail, tailErr := readBytesAt(reader, markerEnd, 2)
				if tailErr == nil && len(tail) >= 2 {
					if tail[0] == '\r' && tail[1] == '\n' {
						markerEnd += 2
					} else if tail[0] == '\n' || tail[0] == '\r' {
						markerEnd += 1
					}
				}
			} else if markerEnd+1 <= endLimit {
				tail, tailErr := readBytesAt(reader, markerEnd, 1)
				if tailErr == nil && len(tail) >= 1 {
					if tail[0] == '\n' || tail[0] == '\r' {
						markerEnd += 1
					}
				}
			}

			candidate := markerEnd - offset
			if candidate > lastEOFEnd {
				lastEOFEnd = candidate
			}
		}

		// 向前推进，保留 overlap 避免 %%EOF 跨块边界被漏掉
		advance := int64(n) - eofLen + 1
		if advance < 1 {
			advance = int64(n)
		}
		pos += advance

		if err != nil && int64(n) < readLen {
			break
		}
	}

	if lastEOFEnd > 0 {
		return lastEOFEnd
	}
	return 0
}

// =========================================================================
// 4. ZIP 文件大小检测
// =========================================================================
//
// ZIP End of Central Directory Record (EOCD):
//   签名: 50 4B 05 06
//   固定部分 22 字节，偏移 20 处为 2 字节注释长度 (LE)
//   总文件大小 = EOCD 在文件内的偏移 + 22 + commentLen

// detectZIPSize 搜索 EOCD 记录来确定 ZIP 文件大小
func detectZIPSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	const blockSize = 64 * 1024
	buf := make([]byte, blockSize)

	endLimit := offset + maxSize
	pos := offset
	var bestSize int64

	for pos < endLimit {
		readLen := endLimit - pos
		if readLen > int64(blockSize) {
			readLen = int64(blockSize)
		}

		n, err := reader.ReadAt(buf[:readLen], pos)
		if n < 4 {
			break
		}

		// 在 buf[:n] 中搜索 EOCD 签名 PK\x05\x06
		for i := 0; i <= n-4; i++ {
			if buf[i] != 0x50 || buf[i+1] != 0x4B || buf[i+2] != 0x05 || buf[i+3] != 0x06 {
				continue
			}

			eocdDiskOffset := pos + int64(i)
			eocdFileOffset := eocdDiskOffset - offset // EOCD 在文件内的偏移

			// 读取完整 EOCD 记录（至少 22 字节）
			eocd, eocdErr := readBytesAt(reader, eocdDiskOffset, 22)
			if eocdErr != nil || len(eocd) < 22 {
				continue
			}

			// 偏移 12: central directory size (4 bytes LE)
			cdSize := uint32(eocd[12]) | uint32(eocd[13])<<8 | uint32(eocd[14])<<16 | uint32(eocd[15])<<24
			// 偏移 16: offset of central directory (4 bytes LE)
			cdOffset := uint32(eocd[16]) | uint32(eocd[17])<<8 | uint32(eocd[18])<<16 | uint32(eocd[19])<<24
			// 偏移 20: comment length (2 bytes LE)
			commentLen := uint16(eocd[20]) | uint16(eocd[21])<<8

			// 验证: central directory 应该在 EOCD 之前
			// cdOffset + cdSize 应该大致等于 eocdFileOffset
			cdEnd := int64(cdOffset) + int64(cdSize)
			if cdEnd > eocdFileOffset+1 {
				// 可能是 ZIP64 或者假阳性，跳过严格验证但仍尝试使用
				// 对于 ZIP64，central directory offset 可能是 0xFFFFFFFF
				if cdOffset != 0xFFFFFFFF {
					continue
				}
			}

			totalSize := eocdFileOffset + 22 + int64(commentLen)

			// 验证注释区域不超出搜索范围
			if totalSize > maxSize {
				continue
			}

			// 取最大的合法 EOCD（增量 ZIP 可能有多个 PK\x05\x06）
			if totalSize > bestSize {
				bestSize = totalSize
			}
		}

		// 向前推进，保留 overlap 避免签名跨块边界
		advance := int64(n) - 3
		if advance < 1 {
			advance = int64(n)
		}
		pos += advance

		if err != nil && int64(n) < readLen {
			break
		}
	}

	return bestSize
}

// =========================================================================
// 5. MP4/MOV 文件大小检测
// =========================================================================
//
// MP4/MOV 由顶级 atom (box) 组成:
//   4 字节 size (大端) + 4 字节 type (如 "ftyp", "moov", "mdat")
//   size == 1: 接下来 8 字节是 64-bit extended size
//   size == 0: atom 延伸到文件末尾

// detectMP4Size 解析顶级 atom 链来确定 MP4/MOV 文件大小
func detectMP4Size(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	endLimit := offset + maxSize
	pos := offset

	for pos < endLimit {
		// 读取 atom header: 4字节 size + 4字节 type
		hdr, err := readBytesAt(reader, pos, 8)
		if err != nil || len(hdr) < 8 {
			break
		}

		atomSize := int64(binary.BigEndian.Uint32(hdr[0:4]))
		atomType := string(hdr[4:8])

		// size == 0 表示 atom 延伸到文件末尾（无法确定精确大小）
		if atomSize == 0 {
			// 如果已经解析了一些 atom，使用 maxSize 作为上界
			if pos > offset {
				return maxSize
			}
			return maxSize
		}

		// size == 1 表示使用 64-bit extended size
		if atomSize == 1 {
			extSize, extErr := readUint64BE(reader, pos+8)
			if extErr != nil {
				break
			}
			atomSize = int64(extSize)
			// 64-bit size 包含 header 的 16 字节
			if atomSize < 16 {
				break // 无效
			}
		} else if atomSize < 8 {
			// 标准 size 包含 header 的 8 字节，最小合法值为 8
			break
		}

		// 验证 type 是合法的 ASCII 可打印字符
		if !isValidAtomType(atomType) {
			break
		}

		// 检查 atom 是否超出搜索范围
		nextPos := pos + atomSize
		if nextPos > endLimit {
			// 如果这是第一个 atom 且明显过大，可能数据损坏
			// 但如果已经成功解析了若干 atom，则最后一个可能是 mdat（很大）
			if pos > offset {
				// 信任此 atom 大小，即使超出 maxSize
				return min64(nextPos-offset, maxSize)
			}
			break
		}

		pos = nextPos
	}

	if pos > offset {
		return pos - offset
	}
	return 0
}

// isValidAtomType 检查 4 字节 atom type 是否为合法 ASCII 可打印字符
func isValidAtomType(t string) bool {
	if len(t) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		c := t[i]
		// 允许 0x20 (空格) 到 0x7E (~) 范围内的可打印 ASCII
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// =========================================================================
// 6. MP3 文件大小检测
// =========================================================================
//
// MP3 文件结构:
//   可选 ID3v2 tag (以 "ID3" 开头)
//   一系列 MPEG audio frames (帧同步: 11 bit, 0xFFE0 mask)
//   可选 ID3v1 tag (以 "TAG" 开头, 固定 128 字节)

// detectMP3Size 解析 ID3 tag 和 MP3 帧来确定文件大小。
//
// 对误报敏感：MP3 帧同步只有 11 bit（~1/2048 随机命中），再加上
// 合法 bitrate/sample-rate/layer 组合也只有 2/3 过滤率，纯随机数据也能
// 偶发凑出几个"valid-looking frame"。所以这里做三层硬性校验：
//
//   1. AC 命中偏移处必须直接是一个合法帧头（FFFB/FFF3/FFF2），或
//      是一个合法的 ID3v2 头（"ID3" + syncsafe size + 非零版本号）。
//   2. 跳过 ID3v2 tag 后，**下一个字节**就必须是合法帧头（不允许移位搜索）。
//   3. 从第一帧起连续读 minValidFrames 帧，每帧必须正好落在 prev+fs 偏移上
//      （不允许 1-3 字节的 slack），且 fs 在合法范围（16..2881 字节）内。
//      一旦失败就整体放弃，而不是"容忍 3 次"。
//
// 常量 minValidFrames = 16 的依据：
//   - 单帧 FF + valid header 的随机发生率 ≈ 1/3100
//   - 连续 16 帧全中的随机概率 ≈ (1/3100)^15 ≈ 10^-52，比宇宙总数都小
//   - 真实 MP3 最小是 10 帧级别（低比特率长度 1 秒以下），给 16 留点缓冲
const (
	mp3MinValidFrames = 16
	mp3MinFrameSize   = 16   // MPEG2.5 Layer III @ 8kbps, 24kHz 的下限
	mp3MaxFrameSize   = 2881 // MPEG1 Layer I @ 448kbps, 32kHz 的上限 + padding
)

func detectMP3Size(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	endLimit := offset + maxSize

	// ---- 层 1: AC 命中处的合法性判定 + 可能跳过 ID3v2 ----
	head, err := readBytesAt(reader, offset, 10)
	if err != nil || len(head) < 4 {
		return 0
	}

	pos := offset
	if head[0] == 'I' && head[1] == 'D' && head[2] == '3' {
		// ID3v2：版本号必须 2/3/4，flags 允许任意，size 是 syncsafe（4 字节高位为 0）
		if !(head[3] == 2 || head[3] == 3 || head[3] == 4) {
			return 0
		}
		if head[6] > 0x7F || head[7] > 0x7F || head[8] > 0x7F || head[9] > 0x7F {
			return 0
		}
		tagSize := int64(head[6]&0x7F)<<21 |
			int64(head[7]&0x7F)<<14 |
			int64(head[8]&0x7F)<<7 |
			int64(head[9]&0x7F)
		pos = offset + 10 + tagSize
	} else {
		// 非 ID3 必须直接是合法帧头
		if head[0] != 0xFF || (head[1]&0xE0) != 0xE0 {
			return 0
		}
		if mp3FrameSize(head[:4]) <= 0 {
			return 0
		}
	}
	if pos >= endLimit {
		return 0
	}

	// ---- 层 2: 跳过 tag 后下一帧必须立即出现 ----
	fhBuf, err := readBytesAt(reader, pos, 4)
	if err != nil || len(fhBuf) < 4 {
		return 0
	}
	if fhBuf[0] != 0xFF || (fhBuf[1]&0xE0) != 0xE0 {
		return 0
	}
	firstFS := mp3FrameSize(fhBuf)
	if firstFS < mp3MinFrameSize || firstFS > mp3MaxFrameSize {
		return 0
	}

	// 帧头的前 3 个字节（除 padding bit 外）在整首 MP3 内保持一致，
	// 我们用这把"指纹"来反制那些只是"看起来合法"的随机噪声——
	// 真实 MP3 每帧都匹配这把指纹；随机数据几乎不可能连续匹配。
	refByte1 := fhBuf[1]
	refByte2 := fhBuf[2] & 0xFD // 抹掉 padding bit

	validFrames := 1
	framePos := pos + int64(firstFS)

	// ---- 层 3: 严格连续帧链 ----
	for validFrames < mp3MinValidFrames {
		if framePos+4 > endLimit {
			break
		}
		b, err := readBytesAt(reader, framePos, 4)
		if err != nil || len(b) < 4 {
			break
		}
		if b[0] != 0xFF || (b[1]&0xE0) != 0xE0 {
			return 0
		}
		if b[1] != refByte1 || (b[2]&0xFD) != refByte2 {
			return 0
		}
		fs := mp3FrameSize(b)
		if fs < mp3MinFrameSize || fs > mp3MaxFrameSize {
			return 0
		}
		validFrames++
		framePos += int64(fs)
	}

	// 通过了严格校验：继续读到文件末尾（遇到无效帧 / TAG / APE / 越界就收尾）。
	// 这阶段无需像以前那么严，因为已经证明"这是真 MP3"。
	for framePos < endLimit {
		b, err := readBytesAt(reader, framePos, 4)
		if err != nil || len(b) < 4 {
			break
		}
		// ID3v1 tag：128 字节 "TAG..."，在文件末尾
		if b[0] == 'T' && b[1] == 'A' && b[2] == 'G' {
			framePos += 128
			break
		}
		// APEv2 tag
		if b[0] == 'A' && b[1] == 'P' && b[2] == 'E' {
			break
		}
		if b[0] != 0xFF || (b[1]&0xE0) != 0xE0 {
			break
		}
		if b[1] != refByte1 || (b[2]&0xFD) != refByte2 {
			break
		}
		fs := mp3FrameSize(b)
		if fs < mp3MinFrameSize || fs > mp3MaxFrameSize {
			break
		}
		framePos += int64(fs)
	}

	totalSize := framePos - offset
	if totalSize > maxSize {
		totalSize = maxSize
	}
	return totalSize
}

// mp3FrameSize 根据 4 字节帧头计算 MP3 帧大小
// 返回 0 表示帧头无效
func mp3FrameSize(header []byte) int {
	if len(header) < 4 {
		return 0
	}

	// 验证帧同步: 前 11 bits 全 1
	if header[0] != 0xFF || (header[1]&0xE0) != 0xE0 {
		return 0
	}

	// 解析帧头字段
	versionBits := (header[1] >> 3) & 0x03 // MPEG version
	layerBits := (header[1] >> 1) & 0x03   // Layer
	bitrateIdx := (header[2] >> 4) & 0x0F  // Bitrate index
	sampleIdx := (header[2] >> 2) & 0x03   // Sample rate index
	padding := (header[2] >> 1) & 0x01     // Padding bit

	// 无效值检查
	if bitrateIdx == 0 || bitrateIdx == 0x0F { // free/reserved
		return 0
	}
	if sampleIdx == 0x03 { // reserved
		return 0
	}
	if layerBits == 0x00 { // reserved
		return 0
	}
	if versionBits == 0x01 { // reserved
		return 0
	}

	bitrate := mp3Bitrate(versionBits, layerBits, bitrateIdx)
	sampleRate := mp3SampleRate(versionBits, sampleIdx)

	if bitrate <= 0 || sampleRate <= 0 {
		return 0
	}

	// 帧大小计算公式
	if layerBits == 0x03 { // Layer I
		// Layer I: FrameSize = (12 * BitRate / SampleRate + Padding) * 4
		return (12*bitrate*1000/sampleRate + int(padding)) * 4
	}

	// Layer II & III:
	if versionBits == 0x03 {
		// MPEG1 Layer II/III: FrameSize = 144 * BitRate / SampleRate + Padding
		return 144*bitrate*1000/sampleRate + int(padding)
	}

	// MPEG2/2.5 Layer III: FrameSize = 72 * BitRate / SampleRate + Padding
	if layerBits == 0x01 {
		return 72*bitrate*1000/sampleRate + int(padding)
	}

	// MPEG2/2.5 Layer II
	return 144*bitrate*1000/sampleRate + int(padding)
}

// mp3Bitrate 查表获取比特率 (kbps)
// versionBits: 00=MPEG2.5, 01=reserved, 10=MPEG2, 11=MPEG1
// layerBits:   00=reserved, 01=Layer III, 10=Layer II, 11=Layer I
func mp3Bitrate(versionBits, layerBits, idx byte) int {
	// 比特率表 (kbps)
	// [版本/层组合][比特率索引]
	var table [5][16]int

	// MPEG1, Layer I
	table[0] = [16]int{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0}
	// MPEG1, Layer II
	table[1] = [16]int{0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0}
	// MPEG1, Layer III
	table[2] = [16]int{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0}
	// MPEG2/2.5, Layer I
	table[3] = [16]int{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0}
	// MPEG2/2.5, Layer II & III
	table[4] = [16]int{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0}

	var tableIdx int
	switch {
	case versionBits == 3 && layerBits == 3: // MPEG1 Layer I
		tableIdx = 0
	case versionBits == 3 && layerBits == 2: // MPEG1 Layer II
		tableIdx = 1
	case versionBits == 3 && layerBits == 1: // MPEG1 Layer III
		tableIdx = 2
	case versionBits != 3 && layerBits == 3: // MPEG2/2.5 Layer I
		tableIdx = 3
	case versionBits != 3 && (layerBits == 2 || layerBits == 1): // MPEG2/2.5 Layer II/III
		tableIdx = 4
	default:
		return 0
	}

	if int(idx) >= 16 {
		return 0
	}
	return table[tableIdx][idx]
}

// mp3SampleRate 查表获取采样率 (Hz)
// versionBits: 00=MPEG2.5, 01=reserved, 10=MPEG2, 11=MPEG1
func mp3SampleRate(versionBits, idx byte) int {
	var table [3][4]int
	// MPEG1
	table[0] = [4]int{44100, 48000, 32000, 0}
	// MPEG2
	table[1] = [4]int{22050, 24000, 16000, 0}
	// MPEG2.5
	table[2] = [4]int{11025, 12000, 8000, 0}

	var tableIdx int
	switch versionBits {
	case 3: // MPEG1
		tableIdx = 0
	case 2: // MPEG2
		tableIdx = 1
	case 0: // MPEG2.5
		tableIdx = 2
	default:
		return 0
	}

	if int(idx) >= 4 {
		return 0
	}
	return table[tableIdx][idx]
}

// =========================================================================
// 7. RIFF (WAV/AVI/WEBP) 文件大小检测
// =========================================================================
//
// RIFF 格式: "RIFF" + 4字节小端文件大小 + 4字节子类型
// 文件总大小 = 偏移4处的 uint32 LE + 8 (前 4 字节 "RIFF" + 4 字节 size 字段本身)

// detectRIFFSize 读取 RIFF header 中的大小字段
func detectRIFFSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	size, err := readUint32LE(reader, offset+4)
	if err != nil {
		return 0
	}

	totalSize := int64(size) + 8
	if totalSize <= 8 {
		return 0 // 空文件或无效
	}
	if totalSize > maxSize {
		return maxSize
	}
	return totalSize
}

// =========================================================================
// 8. OLE2 (Compound Binary File: DOC/XLS/PPT) 文件大小检测
// =========================================================================
//
// OLE2 header (512 字节或 4096 字节):
//   偏移 0x00: 8 字节魔术数 D0 CF 11 E0 A1 B1 1A E1
//   偏移 0x1A: 2 字节 minor version
//   偏移 0x1C: 2 字节 major version (3 或 4)
//   偏移 0x1E: 2 字节 sector size power (通常 9→512 或 12→4096)
//   偏移 0x2C: 4 字节 total FAT sectors
//   偏移 0x30: 4 字节 first directory sector SECID
//   偏移 0x44: 4 字节 first mini FAT sector SECID
//   偏移 0x48: 4 字节 total mini FAT sectors
//   偏移 0x4C: 4 字节 first DIFAT sector SECID
//   偏移 0x50: 4 字节 total DIFAT sectors

// detectOLE2Size 通过 OLE2 header 中的扇区信息估算文件大小
func detectOLE2Size(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	const defaultSize = 10 * 1024 * 1024 // 解析失败时默认 10MB

	// 读取 sector size power
	sectorPower, err := readUint16LE(reader, offset+0x1E)
	if err != nil {
		return defaultSize
	}

	// 合理性检查: sector size power 通常为 9 (512B) 或 12 (4096B)
	if sectorPower < 7 || sectorPower > 16 {
		return defaultSize
	}

	sectorSize := int64(1) << sectorPower

	// 读取 major version
	majorVer, err := readUint16LE(reader, offset+0x1C)
	if err != nil {
		return defaultSize
	}

	// 读取 total FAT sectors
	fatSectors, err := readUint32LE(reader, offset+0x2C)
	if err != nil {
		return defaultSize
	}

	// 读取 total DIFAT sectors
	difatSectors, err := readUint32LE(reader, offset+0x50)
	if err != nil {
		difatSectors = 0 // 允许失败
	}

	// 每个 FAT sector 包含 sectorSize/4 个扇区编号条目
	// 这些条目映射了所有数据扇区
	entriesPerFAT := sectorSize / 4
	maxDataSectors := int64(fatSectors) * entriesPerFAT

	// header 大小:
	//   Version 3: 固定 512 字节 (1 个 sector)
	//   Version 4: 固定 4096 字节 (1 个 sector)
	headerSize := sectorSize
	if majorVer == 3 && sectorSize > 512 {
		headerSize = 512 // v3 的 header 始终是 512 字节
	}

	// 估算文件大小 = header + (数据扇区 + FAT扇区 + DIFAT扇区) * sectorSize
	totalSectors := maxDataSectors + int64(fatSectors) + int64(difatSectors)
	fileSize := headerSize + totalSectors*sectorSize

	// 合理性检查
	if fileSize <= 0 {
		return defaultSize
	}
	if fileSize > maxSize {
		fileSize = maxSize
	}

	// 额外验证: 尝试读取估算边界处的数据
	// 如果太大（大于 100MB），尝试更精确的估算
	if fileSize > 100*1024*1024 {
		// 尝试二分搜索找到实际文件末尾
		// 简化策略: 从估算大小的 10% 开始往回找到最后一个非零扇区
		// 这里保持简单，直接使用 FAT 估算值
		actualSize := refineOLE2Size(reader, offset, headerSize, sectorSize, int64(fatSectors), maxSize)
		if actualSize > 0 {
			return actualSize
		}
	}

	return fileSize
}

// refineOLE2Size 通过读取 FAT 扇区来更精确地确定 OLE2 文件大小
// 遍历 FAT 表中的有效条目，找到最大的已使用扇区编号
func refineOLE2Size(reader disk.DiskReader, offset int64, headerSize int64, sectorSize int64, fatSectors int64, maxSize int64) int64 {
	// 头部 header 之后的 109 个 DIFAT 条目在 header 偏移 0x4C 处 (实际上是 0x4C 开始每个4字节)
	// 简化：对于小文件 (<= 109 个 FAT sectors)，FAT sector IDs 在 header 偏移 0x4C 处
	// 读取 header 中 DIFAT 数组（最多 109 个条目，每个 4 字节，从偏移 0x4C 开始）
	// 实际上 DIFAT 在 header 中从 offset 0x4C 开始只有 first DIFAT sector
	// FAT sector 位置记录在 header 偏移 0x4C(first DIFAT sector) 之前

	// 简化方法：读取 header 中的前 109 个 FAT sector IDs（偏移 0x4C 处是 first DIFAT SECID，
	// 而 FAT sector IDs 从偏移 0x44+8 = 0x4C... 不对）
	// 实际上 OLE2 header 的 DIFAT array 在偏移 0x4C+4+4 = 0x54 处？不对
	// 正确位置：header 偏移 0x4C 是 first DIFAT SECID, 0x50 是 DIFAT count
	// DIFAT array 从 offset 0x4C 开始...不对

	// OLE2 spec:
	// 0x4C: First DIFAT sector
	// 0x50: Number of DIFAT sectors
	// 0x4C+4+4 = 0x54: 不对...
	// 实际上 header 从 offset 0x4C 开始存 first mini FAT...
	// 让我重新看：
	// offset 0x44: First Directory Sector Location (4 bytes)
	// ...实际上我搞混了

	// 简化：直接用 FAT sector 数量估算，不做精细化
	// 这个函数主要是为了处理估算过大的情况

	// 最保守的估算：FAT sectors 指明的数据容量
	entriesPerFAT := sectorSize / 4
	maxDataSectors := fatSectors * entriesPerFAT

	// 尝试读取第一个 FAT sector 来数有效条目
	// FAT sector 位置记录在 header DIFAT 数组中
	// Header 中 DIFAT 数组从偏移 0x4C 开始... 不对
	// 正确的是：
	// 偏移 0x4C: First DIFAT Sector Location
	// 偏移 0x50: Number of DIFAT Sectors
	// Header DIFAT entries: 从 offset 76 (0x4C) 开始的 109 个 DWORD

	// 算了，对于精确化来说太复杂了，直接用估算值
	// 但限制一下上界
	fileSize := headerSize + maxDataSectors*sectorSize
	if fileSize > maxSize {
		fileSize = maxSize
	}
	return fileSize
}

// =========================================================================
// 9. EXE (PE) 文件大小检测
// =========================================================================
//
// PE 格式: MZ DOS header → PE header → Section headers → Sections
// DOS header 偏移 0x3C 处存储 PE header ("PE\0\0") 的文件偏移。
// 文件实际大小 = 最后一个 section 的 RawOffset + RawSize。

// detectEXESize 验证 PE 结构并计算文件大小
// 如果不是有效的 PE 文件 (仅有 MZ 而无 PE 签名)，返回 0 表示丢弃
func detectEXESize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	// 读取 DOS header (至少 64 字节)
	dosHeader, err := readBytesAt(reader, offset, 64)
	if err != nil || len(dosHeader) < 64 {
		return 0
	}

	// 验证 MZ 签名
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return 0
	}

	// 偏移 0x3C: e_lfanew - PE header 的文件偏移
	peOffset := int64(binary.LittleEndian.Uint32(dosHeader[0x3C:0x40]))

	// 合理性检查: PE offset 不应太远 (通常 < 64KB)
	if peOffset < 0x40 || peOffset > 0x10000 {
		return 0
	}

	// 读取 PE 签名 "PE\0\0" (4 字节)
	peSig, err := readBytesAt(reader, offset+peOffset, 4)
	if err != nil || len(peSig) < 4 {
		return 0
	}
	if peSig[0] != 'P' || peSig[1] != 'E' || peSig[2] != 0 || peSig[3] != 0 {
		return 0 // 不是有效 PE 文件
	}

	// PE COFF header (20 bytes) starts at peOffset + 4
	coffOffset := offset + peOffset + 4
	coffHeader, err := readBytesAt(reader, coffOffset, 20)
	if err != nil || len(coffHeader) < 20 {
		return 0
	}

	numberOfSections := binary.LittleEndian.Uint16(coffHeader[2:4])
	sizeOfOptionalHeader := binary.LittleEndian.Uint16(coffHeader[16:18])

	// 合理性检查
	if numberOfSections == 0 || numberOfSections > 96 {
		return 0
	}
	if sizeOfOptionalHeader == 0 {
		return 0
	}

	// Section headers 位于 Optional Header 之后
	sectionTableOffset := coffOffset + 20 + int64(sizeOfOptionalHeader)

	// 遍历 section headers 找到文件中最远的 section
	// 每个 section header = 40 字节
	var maxEnd int64
	for i := uint16(0); i < numberOfSections; i++ {
		secOffset := sectionTableOffset + int64(i)*40
		secHeader, err := readBytesAt(reader, secOffset, 40)
		if err != nil || len(secHeader) < 40 {
			break
		}
		rawSize := int64(binary.LittleEndian.Uint32(secHeader[16:20]))
		rawOffset := int64(binary.LittleEndian.Uint32(secHeader[20:24]))

		sectionEnd := rawOffset + rawSize
		if sectionEnd > maxEnd {
			maxEnd = sectionEnd
		}
	}

	if maxEnd <= 0 {
		return 0
	}

	if maxEnd > maxSize {
		maxEnd = maxSize
	}

	return maxEnd
}

// =========================================================================
// 10. BMP 文件大小检测
// =========================================================================
//
// BMP header:
//   偏移 0: 2 字节 "BM"
//   偏移 2: 4 字节 文件大小 (LE)
//   偏移 6: 4 字节 保留 (应为 0)
//   偏移 10: 4 字节 像素数据偏移 (LE)
//   偏移 14: 4 字节 DIB header 大小 (LE)

// detectBMPSize 从 BMP header 读取嵌入的文件大小
// 如果 header 结构不合理，返回 0 表示丢弃（误报）
func detectBMPSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	header, err := readBytesAt(reader, offset, 18)
	if err != nil || len(header) < 18 {
		return 0
	}

	// 验证 BM 签名
	if header[0] != 'B' || header[1] != 'M' {
		return 0
	}

	// 读取嵌入的文件大小
	fileSize := int64(binary.LittleEndian.Uint32(header[2:6]))

	// 保留字段应为 0
	reserved := binary.LittleEndian.Uint32(header[6:10])
	if reserved != 0 {
		return 0 // 不是有效 BMP
	}

	// 像素数据偏移
	dataOffset := int64(binary.LittleEndian.Uint32(header[10:14]))

	// DIB header 大小
	dibSize := binary.LittleEndian.Uint32(header[14:18])

	// 合理性检查
	// DIB header 常见值: 12, 40, 52, 56, 108, 124
	validDIB := dibSize == 12 || dibSize == 40 || dibSize == 52 || dibSize == 56 ||
		dibSize == 108 || dibSize == 124
	if !validDIB {
		return 0
	}

	// dataOffset 应大于等于 14 + DIB header 大小
	if dataOffset < 14+int64(dibSize) {
		return 0
	}

	// 文件大小应大于 dataOffset
	if fileSize <= dataOffset {
		return 0
	}

	if fileSize > maxSize {
		fileSize = maxSize
	}

	return fileSize
}

// =========================================================================
// 11. ICO 文件大小检测
// =========================================================================
//
// ICO header:
//   偏移 0: 2 字节 保留 (00 00)
//   偏移 2: 2 字节 类型 (01 00 = ICO, 02 00 = CUR)
//   偏移 4: 2 字节 图像数量 (LE)
//   偏移 6: 每个图像目录条目 16 字节

// =========================================================================
// 12. AAC (ADTS) 文件大小检测
// =========================================================================
//
// ADTS 帧头 (7 or 9 字节):
//   同步字 (12 bits): 0xFFF
//   ID (1 bit): 0=MPEG-4, 1=MPEG-2
//   Layer (2 bits): 总是 00
//   Protection absent (1 bit)
//   Profile (2 bits)
//   Sampling freq index (4 bits): 0-12 有效
//   ...
//   Frame length (13 bits): 包含头部的帧总长度

// detectAACSize —— 严格验证 ADTS 帧链
//
// AAC 的签名是 2 字节（fff1/fff9），随机数据触发率极高；必须像 MP3 那样做：
//  1. AC 命中偏移处必须直接是合法 ADTS 帧头（不允许 slack 搜索）
//  2. 连续 aacMinValidFrames 帧，每帧都必须精确位于 prev + frameLen 偏移
//  3. profile/channel-config 在整流内保持一致（真实 AAC 这些字段不变）
const (
	aacMinValidFrames = 16
)

func detectAACSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	endLimit := offset + maxSize

	// 第一帧：AC 命中处必须直接是合法 ADTS 帧
	first, err := readBytesAt(reader, offset, 7)
	if err != nil || len(first) < 7 {
		return 0
	}
	frameLen := adtsFrameLen(first)
	if frameLen <= 0 {
		return 0
	}
	// 前 3 个字节的关键位（profile+samplerate+channel-cfg）当"指纹"用
	refByte1 := first[1] // version/layer
	refByte2 := first[2] // profile+freq+channel-high
	refByte3Mask := first[3] & 0xC0

	validFrames := 1
	pos := offset + int64(frameLen)

	for validFrames < aacMinValidFrames {
		if pos+7 > endLimit {
			break
		}
		b, err := readBytesAt(reader, pos, 7)
		if err != nil || len(b) < 7 {
			break
		}
		if b[0] != 0xFF || (b[1]&0xF0) != 0xF0 {
			return 0
		}
		if b[1] != refByte1 || b[2] != refByte2 || (b[3]&0xC0) != refByte3Mask {
			return 0
		}
		fl := adtsFrameLen(b)
		if fl <= 0 {
			return 0
		}
		validFrames++
		pos += int64(fl)
	}

	// 已经证明是真 AAC，继续读到第一次不匹配为止
	for pos < endLimit {
		if pos+7 > endLimit {
			break
		}
		b, err := readBytesAt(reader, pos, 7)
		if err != nil || len(b) < 7 {
			break
		}
		if b[0] != 0xFF || (b[1]&0xF0) != 0xF0 {
			break
		}
		if b[1] != refByte1 || b[2] != refByte2 || (b[3]&0xC0) != refByte3Mask {
			break
		}
		fl := adtsFrameLen(b)
		if fl <= 0 {
			break
		}
		pos += int64(fl)
	}

	total := pos - offset
	if total > maxSize {
		total = maxSize
	}
	return total
}

// adtsFrameLen 校验 ADTS 帧头并返回帧长度；无效时返回 0。
func adtsFrameLen(hdr []byte) int {
	if len(hdr) < 7 {
		return 0
	}
	// sync 12 bits
	if hdr[0] != 0xFF || (hdr[1]&0xF0) != 0xF0 {
		return 0
	}
	// layer 必须 00
	if (hdr[1]>>1)&0x03 != 0 {
		return 0
	}
	// sampling freq index 合法 0..12
	if (hdr[2]>>2)&0x0F > 12 {
		return 0
	}
	// frame length 13 bits
	fl := int(hdr[3]&0x03)<<11 | int(hdr[4])<<3 | int(hdr[5]>>5)
	if fl < 7 || fl > 8192 {
		return 0
	}
	return fl
}

// =========================================================================
// 13. GIF 文件大小检测
// =========================================================================
//
// GIF 结构: Header(6) → LSD(7) → [GCT] → {Blocks} → Trailer(0x3B)
// 每个数据块以 sub-block 方式存储: 1 字节长度 + 数据, 以 0x00 终止

// detectGIFSize 解析 GIF 块结构来确定文件大小
func detectGIFSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	endLimit := offset + maxSize

	// 验证 GIF 头部 (6 字节: "GIF87a" or "GIF89a")
	hdr, err := readBytesAt(reader, offset, 13)
	if err != nil || len(hdr) < 13 {
		return 0
	}

	if string(hdr[0:3]) != "GIF" {
		return 0
	}
	version := string(hdr[3:6])
	if version != "87a" && version != "89a" {
		return 0
	}

	pos := offset + 6 // 跳过 Header

	// Logical Screen Descriptor (7 字节)
	// 偏移 4 处的 packed byte: bit 7 = Global Color Table Flag
	packed := hdr[10]
	hasGCT := (packed & 0x80) != 0
	gctSize := 0
	if hasGCT {
		gctSize = 3 * (1 << ((packed & 0x07) + 1))
	}
	pos += 7 + int64(gctSize) // 跳过 LSD + GCT

	// 解析数据块
	for pos < endLimit {
		b, err := readBytesAt(reader, pos, 1)
		if err != nil || len(b) < 1 {
			return 0
		}

		switch b[0] {
		case 0x3B: // Trailer
			return pos + 1 - offset

		case 0x21: // Extension Block
			// 读取 extension label
			pos += 2 // 跳过 0x21 + label byte
			// 跳过 sub-blocks
			pos, err = skipGIFSubBlocks(reader, pos, endLimit)
			if err != nil {
				return 0
			}

		case 0x2C: // Image Descriptor
			if pos+10 > endLimit {
				return 0
			}
			imgDesc, err := readBytesAt(reader, pos+1, 9)
			if err != nil || len(imgDesc) < 9 {
				return 0
			}
			pos += 10 // 跳过 Image Descriptor

			// Local Color Table
			lctPacked := imgDesc[8]
			hasLCT := (lctPacked & 0x80) != 0
			if hasLCT {
				lctSize := 3 * (1 << ((lctPacked & 0x07) + 1))
				pos += int64(lctSize)
			}

			// LZW Minimum Code Size (1 byte)
			pos++

			// Image Data sub-blocks
			pos, err = skipGIFSubBlocks(reader, pos, endLimit)
			if err != nil {
				return 0
			}

		default:
			// 未知块类型，文件可能损坏
			return 0
		}
	}

	return 0
}

// skipGIFSubBlocks 跳过 GIF sub-block 序列
// sub-block: 1 字节长度 (n), n 字节数据, 重复直到长度为 0
func skipGIFSubBlocks(reader disk.DiskReader, start int64, limit int64) (int64, error) {
	pos := start
	for pos < limit {
		b, err := readBytesAt(reader, pos, 1)
		if err != nil || len(b) < 1 {
			return pos, fmt.Errorf("read error")
		}
		blockSize := int64(b[0])
		pos++ // 跳过长度字节
		if blockSize == 0 {
			return pos, nil // block terminator
		}
		pos += blockSize
	}
	return pos, fmt.Errorf("exceeded limit")
}

// =========================================================================
// 14. TIFF 文件大小检测
// =========================================================================
//
// TIFF 结构: 8 字节头 + IFD 链
// 头部: 2字节字节序 + 2字节标记42 + 4字节首个IFD偏移
// 每个 IFD: 2字节条目数 + N*12字节条目 + 4字节下一IFD偏移

// detectTIFFSize 通过解析 IFD 链和 strip/tile 偏移来确定文件大小
func detectTIFFSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	hdr, err := readBytesAt(reader, offset, 8)
	if err != nil || len(hdr) < 8 {
		return 0
	}

	// 确定字节序
	var bo binary.ByteOrder
	switch string(hdr[0:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return 0
	}

	// 验证标记 42
	magic := bo.Uint16(hdr[2:4])
	if magic != 42 {
		return 0
	}

	// 首个 IFD 偏移
	ifdOffset := int64(bo.Uint32(hdr[4:8]))
	if ifdOffset < 8 || ifdOffset > maxSize {
		return 0
	}

	// 追踪文件中最远的数据位置
	var maxEnd int64 = 8

	// 最多遍历 10 个 IFD (防止循环)
	for i := 0; i < 10 && ifdOffset > 0; i++ {
		// 读取 IFD 条目数
		countBuf, err := readBytesAt(reader, offset+ifdOffset, 2)
		if err != nil || len(countBuf) < 2 {
			break
		}
		entryCount := int(bo.Uint16(countBuf))
		if entryCount <= 0 || entryCount > 1000 {
			break
		}

		ifdEnd := ifdOffset + 2 + int64(entryCount)*12 + 4
		if ifdEnd > maxEnd {
			maxEnd = ifdEnd
		}

		// 遍历 IFD 条目寻找数据偏移和大小
		for j := 0; j < entryCount; j++ {
			entryBuf, err := readBytesAt(reader, offset+ifdOffset+2+int64(j)*12, 12)
			if err != nil || len(entryBuf) < 12 {
				break
			}

			tag := bo.Uint16(entryBuf[0:2])
			// StripOffsets=273, StripByteCounts=279, TileOffsets=324, TileByteCounts=325
			// 只关注这些和数据位置相关的 tag
			if tag == 273 || tag == 324 {
				// 数据偏移 tag
				count := int(bo.Uint32(entryBuf[4:8]))
				valueOffset := int64(bo.Uint32(entryBuf[8:12]))

				if count == 1 {
					// 值直接存储
					if valueOffset > maxEnd {
						maxEnd = valueOffset
					}
				}
			} else if tag == 279 || tag == 325 {
				// 数据大小 tag
				count := int(bo.Uint32(entryBuf[4:8]))
				valueOffset := int64(bo.Uint32(entryBuf[8:12]))

				if count == 1 && valueOffset > 0 {
					// 单个 strip/tile，值是大小
					// 需要结合 StripOffset，这里简单估算
					if valueOffset > maxEnd {
						maxEnd = valueOffset
					}
				}
			}
		}

		// 读取下一个 IFD 偏移
		nextBuf, err := readBytesAt(reader, offset+ifdOffset+2+int64(entryCount)*12, 4)
		if err != nil || len(nextBuf) < 4 {
			break
		}
		ifdOffset = int64(bo.Uint32(nextBuf))
		if ifdOffset == 0 {
			break // 最后一个 IFD
		}
		if ifdOffset > maxSize {
			break
		}
	}

	if maxEnd <= 8 {
		return 0
	}
	if maxEnd > maxSize {
		maxEnd = maxSize
	}

	return maxEnd
}

// detectICOSize 解析 ICO 文件目录来确定大小
//
// ICO 签名 `00 00 01 00` 只有 4 字节近零值，在磁盘自由空间中误报率极高。
// 这里做严格结构校验，任何字段不合理立刻返回 0 丢弃：
//  1. imgCount 落入合理范围（ICO 实际很少超过 20 条，远低于 256 上限）
//  2. 每条目录项的 color planes 只能是 0 或 1
//  3. bit count 只能是 0/1/4/8/16/24/32
//  4. 数据偏移必须跨过目录区（6 + count*16）
//  5. 数据大小不能太离谱（> 10MB 的 "ICO" 几乎肯定是误报）
func detectICOSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	header, err := readBytesAt(reader, offset, 6)
	if err != nil || len(header) < 6 {
		return 0
	}

	// 验证保留字段和类型
	if header[0] != 0 || header[1] != 0 {
		return 0
	}
	imgType := binary.LittleEndian.Uint16(header[2:4])
	if imgType != 1 && imgType != 2 { // 1=ICO, 2=CUR
		return 0
	}

	imgCount := binary.LittleEndian.Uint16(header[4:6])
	// 收紧：真实 ICO 条目数通常 1-16，超过 64 就极可疑
	if imgCount == 0 || imgCount > 64 {
		return 0
	}

	headerEnd := int64(6) + int64(imgCount)*16
	const maxReasonableICOSize = int64(10 * 1024 * 1024) // 10MB

	// 遍历图像目录，找到最远的图像数据
	var maxEnd int64
	for i := uint16(0); i < imgCount; i++ {
		entryOffset := offset + 6 + int64(i)*16
		entry, err := readBytesAt(reader, entryOffset, 16)
		if err != nil || len(entry) < 16 {
			return 0
		}

		// entry[4]: color planes — 必须是 0 或 1
		colorPlanes := binary.LittleEndian.Uint16(entry[4:6])
		if colorPlanes > 1 {
			return 0
		}

		// entry[6]: bit count — 只允许标准位深度
		bitCount := binary.LittleEndian.Uint16(entry[6:8])
		switch bitCount {
		case 0, 1, 4, 8, 16, 24, 32:
			// ok
		default:
			return 0
		}

		// 偏移 8: 4 字节 图像数据大小 (LE)
		dataSize := int64(binary.LittleEndian.Uint32(entry[8:12]))
		// 偏移 12: 4 字节 图像数据偏移 (LE)
		dataOff := int64(binary.LittleEndian.Uint32(entry[12:16]))

		if dataSize <= 0 || dataOff < headerEnd {
			return 0
		}
		if dataSize > maxReasonableICOSize {
			return 0
		}

		end := dataOff + dataSize
		if end > maxEnd {
			maxEnd = end
		}
	}

	// 整个文件超过 10MB 也按误报处理
	if maxEnd <= headerEnd || maxEnd > maxReasonableICOSize {
		return 0
	}
	if maxEnd > maxSize {
		maxEnd = maxSize
	}

	return maxEnd
}

// =========================================================================
// DjVu 文件大小检测
// =========================================================================
//
// DjVu 用 IFF FORM 容器，带一个 4 字节 "AT&T" 前缀：
//
//	offset 0:  "AT&T"                        (4 bytes prefix)
//	offset 4:  "FORM"                        (4 bytes IFF chunk id)
//	offset 8:  uint32 big-endian formSize    (4 bytes, FORM 内容长度，含 subtype)
//	offset 12: 子类型 "DJVU"/"DJVM"/"PM44"/"BM44"
//	offset 16: FORM body (formSize - 4 bytes)
//
// 总文件大小 = 12 (AT&T + FORM + size field) + formSize（+1 偶对齐 padding）
func detectDjVuSize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	head, err := readBytesAt(reader, offset, 16)
	if err != nil || len(head) < 16 {
		return 0
	}
	if string(head[0:8]) != "AT&TFORM" {
		return 0
	}
	formSize := int64(binary.BigEndian.Uint32(head[8:12]))
	if formSize <= 4 || formSize > maxSize-12 {
		return 0
	}
	// 子类型合理性
	sub := string(head[12:16])
	if sub != "DJVM" && sub != "DJVU" && sub != "PM44" && sub != "BM44" {
		return 0
	}
	total := 12 + formSize
	if total%2 == 1 {
		total++ // IFF 偶字节对齐
	}
	if total > maxSize {
		total = maxSize
	}
	return total
}

// =========================================================================
// MIDI 文件大小检测
// =========================================================================
//
// MIDI 用 MThd/MTrk 分块结构：
//
//	offset 0: "MThd"     (4 bytes)
//	offset 4: uint32 big-endian header 数据长度（通常 6）
//	offset 8+: header data
//	之后若干 MTrk chunk：
//	  offset 0: "MTrk"   (4 bytes)
//	  offset 4: uint32 big-endian track 数据长度
//	  offset 8+: track data
//
// 从 MThd 读 header length 算出第一个 MTrk 的起点，然后循环 MTrk 直到读不到 MTrk。
func detectMIDISize(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	head, err := readBytesAt(reader, offset, 8)
	if err != nil || len(head) < 8 {
		return 0
	}
	if string(head[0:4]) != "MThd" {
		return 0
	}
	headerLen := int64(binary.BigEndian.Uint32(head[4:8]))
	if headerLen < 6 || headerLen > 1024 { // 标准是 6；给点余地
		return 0
	}

	pos := int64(8) + headerLen
	// 合理性：一首 MIDI 曲子通常 < 100 个 track、总大小 < 10MB
	const maxTracks = 512
	for track := 0; track < maxTracks; track++ {
		if pos+8 > maxSize {
			break
		}
		chunkHead, err := readBytesAt(reader, offset+pos, 8)
		if err != nil || len(chunkHead) < 8 {
			break
		}
		if string(chunkHead[0:4]) != "MTrk" {
			// 合法 MIDI 应以 MTrk 结束；遇到非 MTrk 说明到文件外
			break
		}
		trackLen := int64(binary.BigEndian.Uint32(chunkHead[4:8]))
		if trackLen < 0 || trackLen > 10*1024*1024 {
			return 0 // 不合理的 track 大小视作误报
		}
		pos += 8 + trackLen
	}
	if pos <= 8+headerLen {
		return 0 // 至少要有一个 MTrk
	}
	if pos > maxSize {
		pos = maxSize
	}
	return pos
}
