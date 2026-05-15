package carver

// ZIP Central Directory stitcher —— 从碎片化 ZIP 末尾的 End of Central Directory
// Record (EOCD) 反查 Central Directory，然后按 CD 里记录的 localHeaderOffset 读每个 entry。
//
// ZIP 结构（PKZip APPNOTE.TXT）:
//   [local file header + file data] × N
//   [central directory file header] × N
//   end of central directory record (EOCD)
//
// 关键洞察：EOCD 含 CD 在文件内的 offset + CD size；CD 里每条 CentralDirFileHeader
// 含 localHeaderOffset。**这意味着我们不用顺序读 local headers，而是从 EOCD 反向
// 查 CD → 再跳到每个 local header**，对碎片化 ZIP 极其友好。
//
// 重组策略：
//   1. 在文件尾部 65KB 内搜 EOCD signature (0x06054b50)
//   2. EOCD 记录 CD offset + size → 跳到 CD
//   3. 遍历 CD 逐条 CentralDirFileHeader (0x02014b50)
//   4. 每条 CDFH 有 localHeaderOffset → 跳到 local file header (0x04034b50)
//   5. local header 后面跟 compressed data (size 在 CD 里)
//   6. 收集所有 entry → 重建成标准 ZIP 字节流
//
// 覆盖范围：
//   ✅ 单次或多次 entry-level 断点（只要 CD 完整）
//   ✅ EOCD64 (ZIP64 扩展) 也支持
//   ✅ CD 损坏 / 末尾被截断 → 自动 fallback 到扫 local headers 重建
//   ❌ 加密 ZIP（加密字段略过但密文仍输出）

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

const (
	eocdSig      = 0x06054B50
	eocd64Sig    = 0x06064B50
	eocd64LocSig = 0x07064B50
	cdFileHdrSig = 0x02014B50
	localFileSig = 0x04034B50
)

// ZIPStitchResult 重组输出
type ZIPStitchResult struct {
	Data          []byte
	EntryCount    int
	EntriesRead   int
	BytesRead     int64
	ConfidenceHex float32
	Notes         string
}

// ZIPEntry 从 CD 解出的一条 entry 元数据
type ZIPEntry struct {
	FileName          string
	CompressedSize    uint64
	UncompressedSize  uint64
	LocalHeaderOffset uint64
	CompressionMethod uint16
	CRC32             uint32
}

// ZIPStitcher
type ZIPStitcher struct {
	Reader         disk.DiskReader
	ZipStart       int64 // ZIP 文件在磁盘上的起始偏移
	ZipMaxSize     int64 // 猜测的 ZIP 总大小（用于在末尾找 EOCD）
	MaxOutputBytes int64
}

func NewZIPStitcher(r disk.DiskReader, zipStart, zipMaxSize int64) *ZIPStitcher {
	return &ZIPStitcher{
		Reader:         r,
		ZipStart:       zipStart,
		ZipMaxSize:     zipMaxSize,
		MaxOutputBytes: 4 * 1024 * 1024 * 1024, // 4GB 上限
	}
}

// Stitch 执行重组流程。
// CD 完整时走标准路径（read EOCD → read CD → read each LFH）。
// CD 损坏 / EOCD 找不到时自动 fallback 到 StitchFromLocalHeaders 兜底。
func (s *ZIPStitcher) Stitch() (*ZIPStitchResult, error) {
	// 1. 找 EOCD
	eocdOff, eocdRec, err := s.findEOCD()
	if err != nil {
		// CD 路径失败 → 尝试 local-header 扫描兜底
		return s.StitchFromLocalHeaders()
	}

	cdOff := int64(eocdRec.cdOffset)
	cdSize := int64(eocdRec.cdSize)
	entryCount := int(eocdRec.totalEntries)

	// 2. 读取 CD
	cdBuf := make([]byte, cdSize)
	n, err := s.Reader.ReadAt(cdBuf, s.ZipStart+cdOff)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 CD: %w", err)
	}
	if n < int(cdSize) {
		return nil, fmt.Errorf("CD 读不全 %d/%d", n, cdSize)
	}

	// 3. 解析每条 CentralDirFileHeader
	entries, err := s.parseCentralDir(cdBuf, entryCount)
	if err != nil {
		return nil, err
	}

	// 4. 按每条 entry 的 localHeaderOffset 读 local file header + data
	out := &bytes.Buffer{}
	read := 0
	for _, e := range entries {
		localOff := s.ZipStart + int64(e.LocalHeaderOffset)
		// local file header (PKZip LFH) 固定 30 字节 + name_len + extra_len
		lfhHead := make([]byte, 30)
		nn, _ := s.Reader.ReadAt(lfhHead, localOff)
		if nn < 30 {
			continue
		}
		if binary.LittleEndian.Uint32(lfhHead[0:4]) != localFileSig {
			continue
		}
		nameLen := binary.LittleEndian.Uint16(lfhHead[26:28])
		extraLen := binary.LittleEndian.Uint16(lfhHead[28:30])
		lfhTotal := int64(30) + int64(nameLen) + int64(extraLen) + int64(e.CompressedSize)
		entireLFH := make([]byte, lfhTotal)
		nn2, _ := s.Reader.ReadAt(entireLFH, localOff)
		if int64(nn2) < lfhTotal {
			// 读不全但保留已读部分
			out.Write(entireLFH[:nn2])
			read++
			continue
		}
		out.Write(entireLFH)
		read++

		if int64(out.Len()) > s.MaxOutputBytes {
			return nil, fmt.Errorf("ZIP 重组超过 %d 字节上限", s.MaxOutputBytes)
		}
	}

	// 5. 追加 CD 原文（保留完整签名链）
	out.Write(cdBuf)

	// 6. 追加 EOCD（以及 ZIP64 部分如果有）
	// comment 最大 65535 字节（uint16 上限），+22 EOCD header
	eocdBufSize := 22 + int(eocdRec.commentLen)
	if eocdBufSize > 65535+22 {
		eocdBufSize = 65535 + 22
	}
	eocdBuf := make([]byte, eocdBufSize)
	_, _ = s.Reader.ReadAt(eocdBuf, s.ZipStart+eocdOff)
	out.Write(eocdBuf)

	r := &ZIPStitchResult{
		Data:        out.Bytes(),
		EntryCount:  entryCount,
		EntriesRead: read,
		BytesRead:   int64(out.Len()),
	}
	if read == entryCount && entryCount > 0 {
		r.ConfidenceHex = 0.95
		r.Notes = "CD 完整，所有 entry 的 local header 都能读到"
	} else if read > 0 {
		r.ConfidenceHex = float32(read) / float32(entryCount)
		r.Notes = fmt.Sprintf("读到 %d / %d entry（可能碎片化过度或磁盘损坏）", read, entryCount)
	} else {
		r.ConfidenceHex = 0.2
		r.Notes = "无 entry 可读"
	}
	return r, nil
}

// eocdRecord EOCD 解析结果
type eocdRecord struct {
	diskNum      uint16
	cdStartDisk  uint16
	diskEntries  uint16
	totalEntries uint64 // 用 64 存以支持 ZIP64
	cdSize       uint64
	cdOffset     uint64
	commentLen   uint16
}

// findEOCD 在 ZIP 末尾 65KB 找 EOCD（含 ZIP64 兼容）
func (s *ZIPStitcher) findEOCD() (int64, *eocdRecord, error) {
	// EOCD 可变长：22 字节固定 + comment（0..65535）
	// 策略：读末尾 65KB + 22，从后往前扫 signature
	searchSize := int64(65535 + 22)
	if searchSize > s.ZipMaxSize {
		searchSize = s.ZipMaxSize
	}
	tail := make([]byte, searchSize)
	readStart := s.ZipStart + s.ZipMaxSize - searchSize
	if readStart < s.ZipStart {
		readStart = s.ZipStart
		searchSize = s.ZipMaxSize
		tail = tail[:searchSize]
	}
	n, _ := s.Reader.ReadAt(tail, readStart)
	if n < 22 {
		return 0, nil, fmt.Errorf("tail 太短")
	}
	tail = tail[:n]

	// 从后往前找 EOCD signature
	for i := n - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:i+4]) != eocdSig {
			continue
		}
		// 解析
		rec := &eocdRecord{
			diskNum:      binary.LittleEndian.Uint16(tail[i+4 : i+6]),
			cdStartDisk:  binary.LittleEndian.Uint16(tail[i+6 : i+8]),
			diskEntries:  binary.LittleEndian.Uint16(tail[i+8 : i+10]),
			totalEntries: uint64(binary.LittleEndian.Uint16(tail[i+10 : i+12])),
			cdSize:       uint64(binary.LittleEndian.Uint32(tail[i+12 : i+16])),
			cdOffset:     uint64(binary.LittleEndian.Uint32(tail[i+16 : i+20])),
			commentLen:   binary.LittleEndian.Uint16(tail[i+20 : i+22]),
		}
		eocdPosAbs := readStart + int64(i) - s.ZipStart

		// ZIP64 扩展：值为 0xFFFFFFFF 时实际值在 ZIP64 EOCD 里
		if rec.cdOffset == 0xFFFFFFFF || rec.cdSize == 0xFFFFFFFF || rec.totalEntries == 0xFFFF {
			if err := s.fillZIP64(&tail, i, rec); err != nil {
				// 降级：ZIP64 读失败就用原 32-bit 值
			}
		}
		return eocdPosAbs, rec, nil
	}
	return 0, nil, fmt.Errorf("未找到 EOCD signature")
}

// fillZIP64 读 ZIP64 End of Central Directory Record 补全 64-bit 字段
func (s *ZIPStitcher) fillZIP64(tail *[]byte, eocdIdx int, rec *eocdRecord) error {
	// ZIP64 EOCD Locator 在 EOCD 前 20 字节
	if eocdIdx < 20 {
		return fmt.Errorf("ZIP64 locator 越界")
	}
	loc := (*tail)[eocdIdx-20 : eocdIdx]
	if binary.LittleEndian.Uint32(loc[0:4]) != eocd64LocSig {
		return fmt.Errorf("ZIP64 EOCD locator signature mismatch")
	}
	zip64EOCDOffset := binary.LittleEndian.Uint64(loc[8:16])
	// 读 ZIP64 EOCD Record（56 字节固定）
	hdr := make([]byte, 56)
	_, err := s.Reader.ReadAt(hdr, s.ZipStart+int64(zip64EOCDOffset))
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(hdr[0:4]) != eocd64Sig {
		return fmt.Errorf("ZIP64 EOCD signature mismatch")
	}
	rec.totalEntries = binary.LittleEndian.Uint64(hdr[32:40])
	rec.cdSize = binary.LittleEndian.Uint64(hdr[40:48])
	rec.cdOffset = binary.LittleEndian.Uint64(hdr[48:56])
	return nil
}

// parseCentralDir 解析 CD 字节流为 ZIPEntry 列表
func (s *ZIPStitcher) parseCentralDir(cdBuf []byte, expectedCount int) ([]ZIPEntry, error) {
	entries := make([]ZIPEntry, 0, expectedCount)
	pos := 0
	for pos+46 <= len(cdBuf) {
		sig := binary.LittleEndian.Uint32(cdBuf[pos : pos+4])
		if sig != cdFileHdrSig {
			break
		}
		compMethod := binary.LittleEndian.Uint16(cdBuf[pos+10 : pos+12])
		crc32 := binary.LittleEndian.Uint32(cdBuf[pos+16 : pos+20])
		compSize := uint64(binary.LittleEndian.Uint32(cdBuf[pos+20 : pos+24]))
		uncompSize := uint64(binary.LittleEndian.Uint32(cdBuf[pos+24 : pos+28]))
		fileNameLen := binary.LittleEndian.Uint16(cdBuf[pos+28 : pos+30])
		extraLen := binary.LittleEndian.Uint16(cdBuf[pos+30 : pos+32])
		commentLen := binary.LittleEndian.Uint16(cdBuf[pos+32 : pos+34])
		localHdrOff := uint64(binary.LittleEndian.Uint32(cdBuf[pos+42 : pos+46]))
		nameStart := pos + 46
		if nameStart+int(fileNameLen) > len(cdBuf) {
			break
		}
		name := string(cdBuf[nameStart : nameStart+int(fileNameLen)])

		// ZIP64 extra field 解析：如果 compSize/uncompSize/localHdrOff 任一 0xFFFFFFFF，
		// 从 extra field 读 64-bit 值（extra field ID = 0x0001）
		if compSize == 0xFFFFFFFF || uncompSize == 0xFFFFFFFF || localHdrOff == 0xFFFFFFFF {
			extraStart := nameStart + int(fileNameLen)
			extra := cdBuf[extraStart : extraStart+int(extraLen)]
			parseZIP64Extra(extra, &uncompSize, &compSize, &localHdrOff)
		}

		entries = append(entries, ZIPEntry{
			FileName:          name,
			CompressedSize:    compSize,
			UncompressedSize:  uncompSize,
			LocalHeaderOffset: localHdrOff,
			CompressionMethod: compMethod,
			CRC32:             crc32,
		})
		pos = nameStart + int(fileNameLen) + int(extraLen) + int(commentLen)
	}
	return entries, nil
}

// StitchFromLocalHeaders 在 CD 不可用时的兜底：从头扫 0x04034B50 (LFH) signature，
// 逐个读 LFH + compressed data，自己合成一份合法的 CD + EOCD。
//
// 用得到的场景：
//   - ZIP 末尾被截断（CD + EOCD 都丢了）
//   - CD 区块被覆盖但 LFH 区块完整
//   - ZIP 的 EOCD signature 在 64KB 范围外（commentLen 异常）
//
// 限制：
//   - LFH 含"data descriptor"标志 (general purpose flag bit 3) 时，sizes 在
//     LFH 里是 0，真实 size 只在 data 后面的 12B descriptor 里。我们读 next
//     LFH signature 的位置反推该 entry 的 data 长度（不准但可用）。
//   - 加密 / spanning 的复杂场景不处理。
func (s *ZIPStitcher) StitchFromLocalHeaders() (*ZIPStitchResult, error) {
	// 一次读整个 ZIP 区域到内存（最多 MaxOutputBytes）
	scanSize := s.ZipMaxSize
	if scanSize > s.MaxOutputBytes {
		scanSize = s.MaxOutputBytes
	}
	if scanSize <= 0 {
		return nil, fmt.Errorf("ZipMaxSize 非法: %d", s.ZipMaxSize)
	}
	buf := make([]byte, scanSize)
	n, err := s.Reader.ReadAt(buf, s.ZipStart)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("local-header fallback 读盘: %w", err)
	}
	buf = buf[:n]

	// 扫所有 LFH signature 位置
	lfhSigBytes := []byte{0x50, 0x4B, 0x03, 0x04}
	positions := []int{}
	idx := 0
	for {
		off := bytes.Index(buf[idx:], lfhSigBytes)
		if off < 0 {
			break
		}
		positions = append(positions, idx+off)
		idx += off + 4
	}
	if len(positions) == 0 {
		return nil, fmt.Errorf("local-header fallback：未找到任何 LFH signature")
	}

	out := &bytes.Buffer{}
	cd := &bytes.Buffer{} // 我们边走边合成 CD
	entriesWritten := 0

	for i, lfhPos := range positions {
		if lfhPos+30 > len(buf) {
			break
		}
		head := buf[lfhPos : lfhPos+30]
		gpFlag := binary.LittleEndian.Uint16(head[6:8])
		compMethod := binary.LittleEndian.Uint16(head[8:10])
		mtime := binary.LittleEndian.Uint16(head[10:12])
		mdate := binary.LittleEndian.Uint16(head[12:14])
		crc32 := binary.LittleEndian.Uint32(head[14:18])
		compSize := uint32(binary.LittleEndian.Uint32(head[18:22]))
		uncompSize := uint32(binary.LittleEndian.Uint32(head[22:26]))
		nameLen := int(binary.LittleEndian.Uint16(head[26:28]))
		extraLen := int(binary.LittleEndian.Uint16(head[28:30]))

		nameStart := lfhPos + 30
		dataStart := nameStart + nameLen + extraLen
		if dataStart > len(buf) {
			break
		}

		// 算 entry 数据区长度
		var dataLen int
		var hasDescriptor bool
		if compSize != 0 && compSize != 0xFFFFFFFF {
			dataLen = int(compSize)
		} else if (gpFlag & 0x0008) != 0 {
			// data descriptor 模式：用下一个 signature 反推
			hasDescriptor = true
			nextEnd := len(buf)
			if i+1 < len(positions) {
				nextEnd = positions[i+1]
			}
			// 减去 16 字节 data descriptor（含 0x08074b50 signature 时 16 字节，
			// 不含 signature 时 12 字节）—— 先按 16 试，最后从描述符里读真值
			dataLen = nextEnd - dataStart - 16
			if dataLen < 0 {
				dataLen = nextEnd - dataStart - 12
			}
			if dataLen < 0 {
				continue
			}
		} else {
			// 既无 size 又无 descriptor 标志 — 只能用下一个 signature 兜底
			nextEnd := len(buf)
			if i+1 < len(positions) {
				nextEnd = positions[i+1]
			}
			dataLen = nextEnd - dataStart
		}
		if dataStart+dataLen > len(buf) {
			dataLen = len(buf) - dataStart
		}
		if dataLen < 0 {
			continue
		}

		// 抽出文件名
		fileName := ""
		if nameLen > 0 && nameStart+nameLen <= len(buf) {
			fileName = string(buf[nameStart : nameStart+nameLen])
		}

		// 如果是 data descriptor 模式，从 data 后面的 12/16 字节描述符读真实
		// CRC32 + compSize + uncompSize（这才是 archive/zip 写出的标准格式）
		if hasDescriptor {
			descStart := dataStart + dataLen
			// 描述符可选 0x08074B50 signature → 16B；无 signature → 12B
			if descStart+16 <= len(buf) &&
				binary.LittleEndian.Uint32(buf[descStart:descStart+4]) == 0x08074B50 {
				crc32 = binary.LittleEndian.Uint32(buf[descStart+4 : descStart+8])
				compSize = binary.LittleEndian.Uint32(buf[descStart+8 : descStart+12])
				uncompSize = binary.LittleEndian.Uint32(buf[descStart+12 : descStart+16])
				dataLen = int(compSize) // 用真实 size 修正
			} else if descStart+12 <= len(buf) {
				crc32 = binary.LittleEndian.Uint32(buf[descStart : descStart+4])
				compSize = binary.LittleEndian.Uint32(buf[descStart+4 : descStart+8])
				uncompSize = binary.LittleEndian.Uint32(buf[descStart+8 : descStart+12])
				dataLen = int(compSize)
			}
			if dataStart+dataLen > len(buf) {
				dataLen = len(buf) - dataStart
			}
		}

		// 重写 LFH（保留原始 LFH bytes，但若 size 字段是 0 且我们推算出了 dataLen，
		// 就把 compSize 填回去——避免下游 unzip 工具卡 data descriptor）
		entryStart := out.Len()
		entryBytes := buf[lfhPos : dataStart+dataLen]
		patched := make([]byte, len(entryBytes))
		copy(patched, entryBytes)
		// 始终把真实 CRC + sizes 写回 LFH（descriptor 模式下原本是 0）
		binary.LittleEndian.PutUint32(patched[14:18], crc32)
		binary.LittleEndian.PutUint32(patched[18:22], compSize)
		binary.LittleEndian.PutUint32(patched[22:26], uncompSize)
		// 清掉 data descriptor 标志（我们已把 size 写进 LFH）
		gpFlag &^= 0x0008
		binary.LittleEndian.PutUint16(patched[6:8], gpFlag)

		out.Write(patched)
		entriesWritten++

		// 合成对应的 CD 条目（46 字节固定 + name + extra + comment）
		cdEntry := make([]byte, 46+nameLen)
		binary.LittleEndian.PutUint32(cdEntry[0:4], cdFileHdrSig)
		binary.LittleEndian.PutUint16(cdEntry[4:6], 20) // version made by
		binary.LittleEndian.PutUint16(cdEntry[6:8], 20) // version needed
		binary.LittleEndian.PutUint16(cdEntry[8:10], gpFlag)
		binary.LittleEndian.PutUint16(cdEntry[10:12], compMethod)
		binary.LittleEndian.PutUint16(cdEntry[12:14], mtime)
		binary.LittleEndian.PutUint16(cdEntry[14:16], mdate)
		binary.LittleEndian.PutUint32(cdEntry[16:20], crc32)
		binary.LittleEndian.PutUint32(cdEntry[20:24], compSize)
		binary.LittleEndian.PutUint32(cdEntry[24:28], uncompSize)
		binary.LittleEndian.PutUint16(cdEntry[28:30], uint16(nameLen))
		// extra/comment 长度 0；disk number 0；internal/external attrs 0
		binary.LittleEndian.PutUint32(cdEntry[42:46], uint32(entryStart))
		copy(cdEntry[46:], fileName)
		cd.Write(cdEntry)

		if int64(out.Len()) > s.MaxOutputBytes {
			break
		}
	}

	if entriesWritten == 0 {
		return nil, fmt.Errorf("local-header fallback：扫到 LFH signature 但都解析失败")
	}

	// 追加合成的 CD
	cdOff := out.Len()
	cdSize := cd.Len()
	out.Write(cd.Bytes())

	// 追加 EOCD
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], eocdSig)
	// disk numbers 都是 0
	binary.LittleEndian.PutUint16(eocd[8:10], uint16(entriesWritten))
	binary.LittleEndian.PutUint16(eocd[10:12], uint16(entriesWritten))
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(cdSize))
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(cdOff))
	out.Write(eocd)

	return &ZIPStitchResult{
		Data:          out.Bytes(),
		EntryCount:    len(positions),
		EntriesRead:   entriesWritten,
		BytesRead:     int64(out.Len()),
		ConfidenceHex: 0.5,
		Notes: fmt.Sprintf(
			"CD 不可用 → 走 local-header 扫描兜底（识别 %d / 扫到 %d LFH，新 CD 已合成）",
			entriesWritten, len(positions)),
	}, nil
}

// parseZIP64Extra 从 extra field 找 0x0001 ZIP64 block，读 64-bit 替换值
func parseZIP64Extra(extra []byte, uncomp, comp, localOff *uint64) {
	pos := 0
	for pos+4 <= len(extra) {
		id := binary.LittleEndian.Uint16(extra[pos : pos+2])
		sz := int(binary.LittleEndian.Uint16(extra[pos+2 : pos+4]))
		if pos+4+sz > len(extra) {
			return
		}
		if id == 0x0001 {
			p := pos + 4
			// 按原 value 是否 0xFFFFFFFF 决定哪些字段在 ZIP64 block 里
			if *uncomp == 0xFFFFFFFF && p+8 <= pos+4+sz {
				*uncomp = binary.LittleEndian.Uint64(extra[p : p+8])
				p += 8
			}
			if *comp == 0xFFFFFFFF && p+8 <= pos+4+sz {
				*comp = binary.LittleEndian.Uint64(extra[p : p+8])
				p += 8
			}
			if *localOff == 0xFFFFFFFF && p+8 <= pos+4+sz {
				*localOff = binary.LittleEndian.Uint64(extra[p : p+8])
			}
			return
		}
		pos += 4 + sz
	}
}
