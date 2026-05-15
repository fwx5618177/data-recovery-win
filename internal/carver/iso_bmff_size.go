package carver

import (
	"encoding/binary"

	"data-recovery/internal/disk"
)

// =============================================================================
// ISO Base Media File Format (ISO/IEC 14496-12) — moov sample-table 精确大小计算
// =============================================================================
//
// 适用：MP4 / MOV / M4A / 3GP / HEIC / HEIF / AVIF / CR3（所有 ISO BMFF 衍生格式）
//
// 为什么需要这层：
//   atom-walk 只能加各 atom size 算个粗略和。但 mdat atom 经常 size=0（"延伸到文件末尾"
//   per spec 8.2），iPhone / Android / 各种相机录制视频都这样。遇到 size=0 mdat 时
//   atom-walk 不知道真实结束在哪，只能回退 maxSize（4GB）—— 这就是用户报的
//   "每个视频都 4GB" bug 的根因。
//
// 业界标准做法（ffprobe / QuickTime / 所有 demuxer）：
//   解析 moov.trak.mdia.minf.stbl 下的 sample tables，从 stsc/stsz/stco|co64 算出
//   每个 chunk 在文件里占的字节数 + 起始位置。
//   max(chunk_offset + chunk_total_size) = 文件真实结束位置。
//
// 关键 box（ISO/IEC 14496-12 §8）：
//   - stsd (Sample Description) — codec 信息（不影响大小，跳过）
//   - stsz (Sample Size, full box) — 每个 sample 的字节数
//   - stz2 (Compact Sample Size) — stsz 的压缩变体（罕见，先跳过 fall back）
//   - stsc (Sample-to-Chunk, full box) — 哪些 chunk 包含多少 sample
//   - stco (Chunk Offset 32-bit) / co64 (Chunk Offset 64-bit) — 每个 chunk 的文件偏移
//
// 不支持（fall back 到 atom-walk）：
//   - Fragmented MP4（moof boxes，需要解析 trun）
//   - stz2 (Compact Sample Size box)

const (
	maxReasonableSampleCount = 100 * 1000 * 1000 // 100M samples（30fps × 1000h 视频也才 1亿帧）
	maxReasonableChunkCount  = 10 * 1000 * 1000  // 10M chunks
	maxReasonableEntryCount  = 10 * 1000 * 1000  // 通用合理上限
)

// box 表示一个 ISO BMFF box 的位置 + 大小。
// startOffset 是 box header 的开始（含 size + type 字段）。
// dataOffset 是 box payload 的开始（跳过 header）。
// totalSize 是整个 box 的字节数（含 header）。
type box struct {
	boxType     string
	startOffset int64
	dataOffset  int64
	totalSize   int64
}

// detectISOBMFFSizeFromSampleTable 从 moov atom 的 sample tables 算出文件真实大小。
//
// offset 是文件起点（ftyp 的位置）。maxSize 是搜索上界。
// 返回 0 = 解析失败（caller 应回退到 atom-walk）。
//
// 算法：
//  1. 遍历 top-level atoms 找 moov
//  2. moov 内遍历找所有 trak
//  3. 每个 trak 走到 mdia/minf/stbl
//  4. stbl 下读 stsc + stsz + stco|co64
//  5. 算每个 chunk 的 (chunk_offset + chunk_size)
//  6. 全部 trak 的 max chunk_end - file_offset = 文件大小
func detectISOBMFFSizeFromSampleTable(reader disk.DiskReader, offset int64, maxSize int64) int64 {
	// ---- 1. 顶层找 moov ----
	moov, ok := findTopLevelBox(reader, offset, offset+maxSize, "moov")
	if !ok {
		return 0 // 没找到 moov（可能是 fragmented MP4 或损坏文件，走 fallback）
	}

	// ---- 2. moov 里找所有 trak ----
	traks := findChildBoxes(reader, moov, "trak", 32) // 单文件 trak 数量上限 32（音频+视频+字幕够了）
	if len(traks) == 0 {
		return 0
	}

	// ---- 3-5. 对每个 trak 算 max chunk end ----
	var maxEnd int64 = 0
	for _, trak := range traks {
		mdia, ok := findFirstChildBox(reader, trak, "mdia")
		if !ok {
			continue
		}
		minf, ok := findFirstChildBox(reader, mdia, "minf")
		if !ok {
			continue
		}
		stbl, ok := findFirstChildBox(reader, minf, "stbl")
		if !ok {
			continue
		}

		end, ok := computeTrackEndByte(reader, stbl)
		if !ok {
			// 这个 track 解析失败（损坏 / co64 / stz2）—— 跳过它继续别的 track
			// 如果所有 track 都失败，maxEnd 仍然 0，最终返回 0 触发 fallback
			continue
		}
		if end > maxEnd {
			maxEnd = end
		}
	}

	if maxEnd <= offset {
		return 0
	}

	// chunk offsets 是文件绝对偏移（从 ftyp 起），所以 maxEnd 已经是文件大小了
	// 但我们的 reader.ReadAt 是基于 disk-absolute offset，所以减回 file offset
	fileSize := maxEnd - offset
	if fileSize <= 0 || fileSize > maxSize {
		return 0
	}
	return fileSize
}

// findTopLevelBox 在 [searchStart, searchEnd) 范围内顺序遍历 box，找指定 type。
// 返回找到的 box + true / 失败时空 box + false。
func findTopLevelBox(reader disk.DiskReader, searchStart, searchEnd int64, wantType string) (box, bool) {
	pos := searchStart
	for pos < searchEnd {
		b, ok := readBoxHeader(reader, pos)
		if !ok {
			return box{}, false
		}
		if b.boxType == wantType {
			return b, true
		}
		// 防 size=0 / 损坏：size=0 表示延伸到文件末尾，对找特定 box 来说我们停下
		if b.totalSize <= 0 || b.totalSize > searchEnd-pos {
			return box{}, false
		}
		pos += b.totalSize
	}
	return box{}, false
}

// findChildBoxes 在 parent box 的 payload 内遍历找所有指定 type 的 child box。
// maxResults 上界保护异常输入不让我们扫到天荒地老。
func findChildBoxes(reader disk.DiskReader, parent box, wantType string, maxResults int) []box {
	var results []box
	pos := parent.dataOffset
	end := parent.startOffset + parent.totalSize
	for pos < end && len(results) < maxResults {
		b, ok := readBoxHeader(reader, pos)
		if !ok || b.totalSize <= 0 {
			break
		}
		if pos+b.totalSize > end {
			break // box 越界 → 损坏
		}
		if b.boxType == wantType {
			results = append(results, b)
		}
		pos += b.totalSize
	}
	return results
}

// findFirstChildBox 找 parent 下第一个指定 type 的 child（trak/mdia/minf/stbl 这种链）
func findFirstChildBox(reader disk.DiskReader, parent box, wantType string) (box, bool) {
	pos := parent.dataOffset
	end := parent.startOffset + parent.totalSize
	for pos < end {
		b, ok := readBoxHeader(reader, pos)
		if !ok || b.totalSize <= 0 {
			return box{}, false
		}
		if pos+b.totalSize > end {
			return box{}, false
		}
		if b.boxType == wantType {
			return b, true
		}
		pos += b.totalSize
	}
	return box{}, false
}

// readBoxHeader 解析 box header（4 bytes size + 4 bytes type，可能有 8 bytes 64-bit ext size）
func readBoxHeader(reader disk.DiskReader, offset int64) (box, bool) {
	hdr, err := readBytesAt(reader, offset, 8)
	if err != nil || len(hdr) < 8 {
		return box{}, false
	}
	size32 := binary.BigEndian.Uint32(hdr[0:4])
	boxType := string(hdr[4:8])
	if !isValidAtomType(boxType) {
		return box{}, false
	}

	totalSize := int64(size32)
	dataOff := offset + 8

	if size32 == 1 {
		// 64-bit extended size
		extBuf, err := readBytesAt(reader, offset+8, 8)
		if err != nil || len(extBuf) < 8 {
			return box{}, false
		}
		totalSize = int64(binary.BigEndian.Uint64(extBuf))
		dataOff = offset + 16
		if totalSize < 16 {
			return box{}, false
		}
	} else if size32 == 0 {
		// "延伸到文件末尾" —— 让 caller 决定怎么处理
		totalSize = 0
	} else if size32 < 8 {
		return box{}, false // 标准 size 必须 ≥ 8
	}

	return box{
		boxType:     boxType,
		startOffset: offset,
		dataOffset:  dataOff,
		totalSize:   totalSize,
	}, true
}

// computeTrackEndByte 从一个 stbl box 算出这个 track 数据的最后一个字节（文件绝对偏移）。
//
// 算法：
//  1. 读 stsz：得到每个 sample 的字节数
//  2. 读 stsc：得到 "chunk i 包含多少 samples" 的映射
//  3. 读 stco/co64：得到每个 chunk 的文件起始偏移
//  4. 对每个 chunk：累加它包含的 samples 大小 = chunk_size
//  5. chunk_end = chunk_offset + chunk_size，max chunk_end = track 结束位置
func computeTrackEndByte(reader disk.DiskReader, stbl box) (int64, bool) {
	stsz, defaultSampleSize, sampleCount, ok := readSTSZ(reader, stbl)
	if !ok {
		return 0, false
	}
	stscRuns, ok := readSTSC(reader, stbl)
	if !ok {
		return 0, false
	}
	chunkOffsets, ok := readChunkOffsets(reader, stbl)
	if !ok {
		return 0, false
	}

	if len(chunkOffsets) == 0 || sampleCount == 0 {
		return 0, false
	}

	var maxEnd int64 = 0
	var sampleIdx uint32 = 0 // 已处理 sample 数（0-indexed）

	// chunk index 在 ISO BMFF 是 1-indexed
	for chunkIdx := uint32(1); chunkIdx <= uint32(len(chunkOffsets)); chunkIdx++ {
		samplesHere := samplesInChunk(chunkIdx, stscRuns)
		if samplesHere == 0 {
			continue
		}
		if sampleIdx+samplesHere > sampleCount {
			samplesHere = sampleCount - sampleIdx
		}

		var chunkSize int64 = 0
		if defaultSampleSize > 0 {
			// stsz 默认大小模式：所有 sample 一样大
			chunkSize = int64(samplesHere) * int64(defaultSampleSize)
		} else {
			for s := uint32(0); s < samplesHere; s++ {
				idx := sampleIdx + s
				if idx >= uint32(len(stsz)) {
					break
				}
				chunkSize += int64(stsz[idx])
			}
		}

		chunkEnd := chunkOffsets[chunkIdx-1] + chunkSize
		if chunkEnd > maxEnd {
			maxEnd = chunkEnd
		}

		sampleIdx += samplesHere
		if sampleIdx >= sampleCount {
			break
		}
	}

	if maxEnd <= 0 {
		return 0, false
	}
	return maxEnd, true
}

// stscRun ISO BMFF stsc 的一行：从 firstChunk 开始，每个 chunk 包含 samplesPerChunk
// 个 sample，直到下一个 stscRun 改变规则。
type stscRun struct {
	firstChunk      uint32 // 1-indexed
	samplesPerChunk uint32
}

// samplesInChunk 在 stsc runs 表里查询第 chunkIdx 个 chunk 包含多少 sample。
// chunkIdx 是 1-indexed per ISO BMFF spec。
func samplesInChunk(chunkIdx uint32, runs []stscRun) uint32 {
	if len(runs) == 0 {
		return 0
	}
	current := uint32(0)
	for _, run := range runs {
		if run.firstChunk > chunkIdx {
			break
		}
		current = run.samplesPerChunk
	}
	return current
}

// readSTSZ 解析 stsz (Sample Size) full box。
//
// 返回：
//   - sizes: 每个 sample 的大小（仅当 defaultSampleSize == 0 时填）
//   - defaultSampleSize: 非 0 表示所有 sample 大小相同
//   - sampleCount: 总 sample 数
//   - ok: false = 解析失败 / 损坏 / 不是 stsz
//
// stsz body 布局（per ISO/IEC 14496-12 §8.7.3.2）：
//
//	[0]   1 byte  version (must be 0)
//	[1-3] 3 bytes flags
//	[4-7] 4 bytes default_sample_size (0 = 各 sample 大小不同)
//	[8-11] 4 bytes sample_count
//	if default_sample_size == 0:
//	  [12...] sample_count × 4 bytes per-sample size
func readSTSZ(reader disk.DiskReader, stbl box) ([]uint32, uint32, uint32, bool) {
	stsz, ok := findFirstChildBox(reader, stbl, "stsz")
	if !ok {
		// stz2 (Compact Sample Size) 是 stsz 的变体，本版本不支持 → fail
		return nil, 0, 0, false
	}
	bodyStart := stsz.dataOffset
	bodyEnd := stsz.startOffset + stsz.totalSize
	if bodyEnd-bodyStart < 12 {
		return nil, 0, 0, false
	}

	hdr, err := readBytesAt(reader, bodyStart, 12)
	if err != nil || len(hdr) < 12 {
		return nil, 0, 0, false
	}
	// hdr[0] version, hdr[1:4] flags
	defaultSize := binary.BigEndian.Uint32(hdr[4:8])
	sampleCount := binary.BigEndian.Uint32(hdr[8:12])

	if sampleCount > maxReasonableSampleCount {
		return nil, 0, 0, false // 损坏：sample count 异常大
	}

	if defaultSize > 0 {
		return nil, defaultSize, sampleCount, true
	}

	// 读 sample_count 个 4 字节 entry
	expectedBytes := int64(sampleCount) * 4
	if bodyStart+12+expectedBytes > bodyEnd {
		return nil, 0, 0, false
	}
	sizesBuf, err := readBytesAt(reader, bodyStart+12, int(expectedBytes))
	if err != nil || int64(len(sizesBuf)) < expectedBytes {
		return nil, 0, 0, false
	}
	sizes := make([]uint32, sampleCount)
	for i := uint32(0); i < sampleCount; i++ {
		sizes[i] = binary.BigEndian.Uint32(sizesBuf[i*4 : i*4+4])
	}
	return sizes, 0, sampleCount, true
}

// readSTSC 解析 stsc (Sample-to-Chunk) full box。
//
// stsc body 布局（per ISO/IEC 14496-12 §8.7.4.2）：
//
//	[0]   1 byte version
//	[1-3] 3 bytes flags
//	[4-7] 4 bytes entry_count
//	[8...] entry_count × 12 bytes:
//	  4 bytes first_chunk (1-indexed)
//	  4 bytes samples_per_chunk
//	  4 bytes sample_description_index
func readSTSC(reader disk.DiskReader, stbl box) ([]stscRun, bool) {
	stsc, ok := findFirstChildBox(reader, stbl, "stsc")
	if !ok {
		return nil, false
	}
	bodyStart := stsc.dataOffset
	bodyEnd := stsc.startOffset + stsc.totalSize
	if bodyEnd-bodyStart < 8 {
		return nil, false
	}
	hdr, err := readBytesAt(reader, bodyStart, 8)
	if err != nil || len(hdr) < 8 {
		return nil, false
	}
	entryCount := binary.BigEndian.Uint32(hdr[4:8])
	if entryCount == 0 || entryCount > maxReasonableEntryCount {
		return nil, false
	}

	expectedBytes := int64(entryCount) * 12
	if bodyStart+8+expectedBytes > bodyEnd {
		return nil, false
	}
	entriesBuf, err := readBytesAt(reader, bodyStart+8, int(expectedBytes))
	if err != nil || int64(len(entriesBuf)) < expectedBytes {
		return nil, false
	}

	runs := make([]stscRun, entryCount)
	for i := uint32(0); i < entryCount; i++ {
		off := i * 12
		runs[i] = stscRun{
			firstChunk:      binary.BigEndian.Uint32(entriesBuf[off : off+4]),
			samplesPerChunk: binary.BigEndian.Uint32(entriesBuf[off+4 : off+8]),
		}
	}
	// 合理性：第一个 entry 的 firstChunk 应当是 1
	if runs[0].firstChunk != 1 {
		return nil, false
	}
	return runs, true
}

// readChunkOffsets 解析 stco (32-bit) 或 co64 (64-bit) 任一个，返回 chunk offset 列表。
//
// stco body：4 bytes flags+ver, 4 bytes entry_count, entry_count × 4 bytes uint32 offset
// co64 body：4 bytes flags+ver, 4 bytes entry_count, entry_count × 8 bytes uint64 offset
//
// chunk offset 是文件绝对偏移（从 file start 起，per spec §8.7.5）。
func readChunkOffsets(reader disk.DiskReader, stbl box) ([]int64, bool) {
	// 优先 stco（32-bit，更常见），没有再试 co64（64-bit，> 4GB 文件）
	if stco, ok := findFirstChildBox(reader, stbl, "stco"); ok {
		return readSTCOEntries(reader, stco, 4)
	}
	if co64, ok := findFirstChildBox(reader, stbl, "co64"); ok {
		return readSTCOEntries(reader, co64, 8)
	}
	return nil, false
}

// readSTCOEntries 通用 stco/co64 reader。entrySize=4 (stco) or 8 (co64)。
func readSTCOEntries(reader disk.DiskReader, b box, entrySize int) ([]int64, bool) {
	bodyStart := b.dataOffset
	bodyEnd := b.startOffset + b.totalSize
	if bodyEnd-bodyStart < 8 {
		return nil, false
	}
	hdr, err := readBytesAt(reader, bodyStart, 8)
	if err != nil || len(hdr) < 8 {
		return nil, false
	}
	entryCount := binary.BigEndian.Uint32(hdr[4:8])
	if entryCount == 0 || entryCount > maxReasonableChunkCount {
		return nil, false
	}

	expectedBytes := int64(entryCount) * int64(entrySize)
	if bodyStart+8+expectedBytes > bodyEnd {
		return nil, false
	}
	buf, err := readBytesAt(reader, bodyStart+8, int(expectedBytes))
	if err != nil || int64(len(buf)) < expectedBytes {
		return nil, false
	}

	offsets := make([]int64, entryCount)
	for i := uint32(0); i < entryCount; i++ {
		off := int(i) * entrySize
		if entrySize == 4 {
			offsets[i] = int64(binary.BigEndian.Uint32(buf[off : off+4]))
		} else {
			offsets[i] = int64(binary.BigEndian.Uint64(buf[off : off+8]))
		}
		// 合理性：chunk offset 应该 > 0（0 通常是非法的，文件第一个 box 是 ftyp 不是 mdat）
		if offsets[i] <= 0 {
			return nil, false
		}
	}
	return offsets, true
}
