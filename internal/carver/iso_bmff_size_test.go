package carver

import (
	"bytes"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// =============================================================================
// 合成 MP4 构造器 —— 用于测试 detectISOBMFFSizeFromSampleTable
// =============================================================================
//
// 我们建一个最小合法 ISO BMFF 文件：
//   ftyp (32 字节)
//   moov
//     trak
//       mdia
//         minf
//           stbl
//             stsd (1 entry, 占位)
//             stsz (默认大小或 per-sample)
//             stsc (1 run: 第 1 chunk 起每 chunk N samples)
//             stco (chunk 的文件偏移)
//   mdat (size=0 / size=normal 都测)
//
// 关键：chunk_offset 必须是 mdat 数据的起始（即 mdat header 之后），
// chunk 的 sample 总和 = mdat data 大小。

// buildSTSZ 构造 stsz box payload —— defaultSize 模式 OR per-sample 模式。
// version=0 flags=0
func buildSTSZ(defaultSize uint32, sampleSizes []uint32) []byte {
	var p bytes.Buffer
	p.Write([]byte{0, 0, 0, 0}) // version + flags
	binary.Write(&p, binary.BigEndian, defaultSize)
	binary.Write(&p, binary.BigEndian, uint32(len(sampleSizes)))
	if defaultSize == 0 {
		for _, s := range sampleSizes {
			binary.Write(&p, binary.BigEndian, s)
		}
	}
	return p.Bytes()
}

// buildSTSC 构造 stsc box payload。每条目：first_chunk, samples_per_chunk, sample_desc_idx。
func buildSTSC(entries [][3]uint32) []byte {
	var p bytes.Buffer
	p.Write([]byte{0, 0, 0, 0}) // version + flags
	binary.Write(&p, binary.BigEndian, uint32(len(entries)))
	for _, e := range entries {
		binary.Write(&p, binary.BigEndian, e[0])
		binary.Write(&p, binary.BigEndian, e[1])
		binary.Write(&p, binary.BigEndian, e[2])
	}
	return p.Bytes()
}

// buildSTCO 构造 32-bit chunk offset table
func buildSTCO(offsets []uint32) []byte {
	var p bytes.Buffer
	p.Write([]byte{0, 0, 0, 0})
	binary.Write(&p, binary.BigEndian, uint32(len(offsets)))
	for _, o := range offsets {
		binary.Write(&p, binary.BigEndian, o)
	}
	return p.Bytes()
}

// buildCO64 构造 64-bit chunk offset table
func buildCO64(offsets []uint64) []byte {
	var p bytes.Buffer
	p.Write([]byte{0, 0, 0, 0})
	binary.Write(&p, binary.BigEndian, uint32(len(offsets)))
	for _, o := range offsets {
		binary.Write(&p, binary.BigEndian, o)
	}
	return p.Bytes()
}

// buildMinimalSTBL 构造 stbl box payload，含 stsd (placeholder) + stsz + stsc + stco|co64
func buildMinimalSTBL(stszPayload, stscPayload, stcoPayload []byte, stcoBoxType string) []byte {
	var p bytes.Buffer
	// stsd: 占位（实际用不到，本版本不解析）
	stsd := []byte{0, 0, 0, 0, 0, 0, 0, 0} // version+flags + entry_count=0
	writeBoxTo(&p, "stsd", stsd)
	writeBoxTo(&p, "stsz", stszPayload)
	writeBoxTo(&p, "stsc", stscPayload)
	writeBoxTo(&p, stcoBoxType, stcoPayload)
	return p.Bytes()
}

// writeBoxTo 把一个 box 写到 buffer
func writeBoxTo(out *bytes.Buffer, boxType string, payload []byte) {
	totalSize := uint32(8 + len(payload))
	var sz [4]byte
	binary.BigEndian.PutUint32(sz[:], totalSize)
	out.Write(sz[:])
	out.WriteString(boxType)
	out.Write(payload)
}

// buildTrak 用给定的 stbl 包成 trak/mdia/minf/stbl 的层级
func buildTrak(stblPayload []byte) []byte {
	var minf bytes.Buffer
	writeBoxTo(&minf, "stbl", stblPayload)

	var mdia bytes.Buffer
	writeBoxTo(&mdia, "minf", minf.Bytes())

	var trak bytes.Buffer
	writeBoxTo(&trak, "mdia", mdia.Bytes())

	return trak.Bytes()
}

// =============================================================================
// 测试
// =============================================================================

// TestDetectISOBMFFSize_SingleTrack_DefaultSampleSize 最简场景：
// 1 个 trak，1 个 chunk，10 个 sample 每个 100 字节 = 1000 bytes mdat data
func TestDetectISOBMFFSize_SingleTrack_DefaultSampleSize(t *testing.T) {
	// ---- 先算 layout ----
	// ftyp (32) + moov (...) + mdat (8 header + 1000 data = 1008)
	// chunk_offset = ftyp_end + moov_size + mdat_header (8) = 32 + moov_size + 8

	// 构造 stbl
	stsz := buildSTSZ(100, make([]uint32, 10)) // default size = 100, 10 samples
	stsc := buildSTSC([][3]uint32{{1, 10, 1}}) // 第 1 chunk 起每 chunk 10 samples
	// chunk_offset 暂用占位，等会算出 moov_size 再回填
	stco := buildSTCO([]uint32{0}) // placeholder
	stbl := buildMinimalSTBL(stsz, stsc, stco, "stco")
	trak := buildTrak(stbl)

	// 包 moov
	var moov bytes.Buffer
	writeBoxTo(&moov, "trak", trak)

	// 算文件 layout
	var ftyp bytes.Buffer
	ftyp.Write([]byte{0, 0, 0, 0x20, 'f', 't', 'y', 'p'}) // 32 字节 ftyp
	ftyp.Write(make([]byte, 32-8))                        // 填充

	moovSize := uint32(8 + moov.Len())
	mdatDataStart := uint32(ftyp.Len()) + moovSize + 8 // ftyp + moov + mdat_header

	// 重建 stbl with 正确 chunk offset
	stco = buildSTCO([]uint32{mdatDataStart})
	stbl = buildMinimalSTBL(stsz, stsc, stco, "stco")
	trak = buildTrak(stbl)
	moov.Reset()
	writeBoxTo(&moov, "trak", trak)

	// 校验 moovSize 没变（因为只改了 chunk_offset 数值，长度不变）
	if uint32(8+moov.Len()) != moovSize {
		t.Fatalf("moov size shifted: was %d now %d", moovSize, 8+moov.Len())
	}

	// 拼最终文件
	var img bytes.Buffer
	img.Write(ftyp.Bytes())
	writeBoxTo(&img, "moov", moov.Bytes())
	mdatData := make([]byte, 1000)
	for i := range mdatData {
		mdatData[i] = byte(i & 0xFF)
	}
	writeBoxTo(&img, "mdat", mdatData) // mdat 普通 size

	expectedSize := int64(img.Len())

	reader := testutil.NewMemReader(img.Bytes())
	got := detectISOBMFFSizeFromSampleTable(reader, 0, 100*1024*1024)
	if got != expectedSize {
		t.Errorf("size mismatch: got %d, want %d", got, expectedSize)
	}
}

// TestDetectISOBMFFSize_MdatWithSize0 关键 bug 复现：
// 用 size=0 mdat（"延伸到文件末尾"，iPhone/Android 常见）。
// 之前 detectMP4Size 这个场景返回 maxSize=4GB，现在应该从 sample table 算出准确大小。
func TestDetectISOBMFFSize_MdatWithSize0(t *testing.T) {
	stsz := buildSTSZ(0, []uint32{200, 300, 500}) // 3 samples per-sample sizes
	stsc := buildSTSC([][3]uint32{{1, 3, 1}})     // 1 chunk, 3 samples
	stco := buildSTCO([]uint32{0})                // placeholder
	stbl := buildMinimalSTBL(stsz, stsc, stco, "stco")
	trak := buildTrak(stbl)

	var moov bytes.Buffer
	writeBoxTo(&moov, "trak", trak)

	const ftypSize = 32
	moovSize := uint32(8 + moov.Len())
	// mdat with size=0 has only 8 byte header
	mdatDataStart := uint32(ftypSize) + moovSize + 8

	stco = buildSTCO([]uint32{mdatDataStart})
	stbl = buildMinimalSTBL(stsz, stsc, stco, "stco")
	trak = buildTrak(stbl)
	moov.Reset()
	writeBoxTo(&moov, "trak", trak)

	var img bytes.Buffer
	// ftyp (32 bytes)
	img.Write([]byte{0, 0, 0, 0x20, 'f', 't', 'y', 'p'})
	img.Write(make([]byte, 32-8))
	writeBoxTo(&img, "moov", moov.Bytes())

	// size=0 mdat
	mdatHeader := []byte{0, 0, 0, 0, 'm', 'd', 'a', 't'} // size=0
	img.Write(mdatHeader)

	// mdat data (sum of sample sizes = 200+300+500 = 1000)
	mdatData := make([]byte, 1000)
	img.Write(mdatData)

	// 多写 4MB 的"垃圾数据"模拟磁盘上 mdat 之后是别的内容
	garbage := make([]byte, 4*1024*1024)
	for i := range garbage {
		garbage[i] = byte(i & 0xFF)
	}
	img.Write(garbage)

	expectedSize := int64(ftypSize) + int64(moovSize) + 8 + 1000 // ftyp + moov + mdat_header + data

	reader := testutil.NewMemReader(img.Bytes())
	got := detectISOBMFFSizeFromSampleTable(reader, 0, 100*1024*1024)
	if got != expectedSize {
		t.Errorf("size=0 mdat 场景失败：got %d, want %d（差 %d 字节，本应该=ftyp+moov+mdat_hdr+data=%d）",
			got, expectedSize, got-expectedSize, expectedSize)
	}
	// 关键断言：不应该返回 4MB+ 的垃圾数据大小
	if got > expectedSize+1000 {
		t.Errorf("size=0 mdat 应该按 sample table 截断，实际多读了 %d 字节垃圾数据", got-expectedSize)
	}
}

// TestDetectISOBMFFSize_MultiTrack 多 track 场景（常见：视频+音频）。
// max chunk_end 跨所有 track 取最大 = 文件结束。
func TestDetectISOBMFFSize_MultiTrack(t *testing.T) {
	// 视频 track：在 mdat 前半段（offset X，1000 字节）
	// 音频 track：在 mdat 后半段（offset X+1000，500 字节）
	// 总 mdat data 1500 字节

	// trak 1 (video)
	stsz1 := buildSTSZ(0, []uint32{1000})
	stsc1 := buildSTSC([][3]uint32{{1, 1, 1}})
	stco1 := buildSTCO([]uint32{0}) // placeholder

	// trak 2 (audio)
	stsz2 := buildSTSZ(0, []uint32{500})
	stsc2 := buildSTSC([][3]uint32{{1, 1, 1}})
	stco2 := buildSTCO([]uint32{0}) // placeholder

	stbl1 := buildMinimalSTBL(stsz1, stsc1, stco1, "stco")
	stbl2 := buildMinimalSTBL(stsz2, stsc2, stco2, "stco")

	trak1 := buildTrak(stbl1)
	trak2 := buildTrak(stbl2)

	var moov bytes.Buffer
	writeBoxTo(&moov, "trak", trak1)
	writeBoxTo(&moov, "trak", trak2)

	const ftypSize = 32
	moovSize := uint32(8 + moov.Len())
	mdatStart := uint32(ftypSize) + moovSize + 8

	// 重建 with 正确 offset
	stco1 = buildSTCO([]uint32{mdatStart})        // 视频从 mdat 开头
	stco2 = buildSTCO([]uint32{mdatStart + 1000}) // 音频从 +1000 开始

	stbl1 = buildMinimalSTBL(stsz1, stsc1, stco1, "stco")
	stbl2 = buildMinimalSTBL(stsz2, stsc2, stco2, "stco")
	trak1 = buildTrak(stbl1)
	trak2 = buildTrak(stbl2)
	moov.Reset()
	writeBoxTo(&moov, "trak", trak1)
	writeBoxTo(&moov, "trak", trak2)

	var img bytes.Buffer
	img.Write([]byte{0, 0, 0, 0x20, 'f', 't', 'y', 'p'})
	img.Write(make([]byte, 32-8))
	writeBoxTo(&img, "moov", moov.Bytes())
	mdatData := make([]byte, 1500)
	writeBoxTo(&img, "mdat", mdatData)

	expectedSize := int64(img.Len())

	reader := testutil.NewMemReader(img.Bytes())
	got := detectISOBMFFSizeFromSampleTable(reader, 0, 100*1024*1024)
	if got != expectedSize {
		t.Errorf("multi-track: got %d, want %d", got, expectedSize)
	}
}

// TestDetectISOBMFFSize_CO64 64-bit chunk offset（>4GB 文件）。
// 我们不真造 4GB 镜像，只验证 co64 解析路径正确。
func TestDetectISOBMFFSize_CO64(t *testing.T) {
	stsz := buildSTSZ(0, []uint32{100})
	stsc := buildSTSC([][3]uint32{{1, 1, 1}})
	stco := buildCO64([]uint64{0}) // 用 co64 而不是 stco
	stbl := buildMinimalSTBL(stsz, stsc, stco, "co64")
	trak := buildTrak(stbl)

	var moov bytes.Buffer
	writeBoxTo(&moov, "trak", trak)

	const ftypSize = 32
	moovSize := uint32(8 + moov.Len())
	mdatStart := uint32(ftypSize) + moovSize + 8

	stco = buildCO64([]uint64{uint64(mdatStart)})
	stbl = buildMinimalSTBL(stsz, stsc, stco, "co64")
	trak = buildTrak(stbl)
	moov.Reset()
	writeBoxTo(&moov, "trak", trak)

	var img bytes.Buffer
	img.Write([]byte{0, 0, 0, 0x20, 'f', 't', 'y', 'p'})
	img.Write(make([]byte, 32-8))
	writeBoxTo(&img, "moov", moov.Bytes())
	writeBoxTo(&img, "mdat", make([]byte, 100))

	expectedSize := int64(img.Len())

	reader := testutil.NewMemReader(img.Bytes())
	got := detectISOBMFFSizeFromSampleTable(reader, 0, 100*1024*1024)
	if got != expectedSize {
		t.Errorf("co64: got %d, want %d", got, expectedSize)
	}
}

// TestDetectISOBMFFSize_MissingMoov 没有 moov（损坏文件）—— 应该返回 0 让 caller 走 fallback
func TestDetectISOBMFFSize_MissingMoov(t *testing.T) {
	var img bytes.Buffer
	img.Write([]byte{0, 0, 0, 0x20, 'f', 't', 'y', 'p'})
	img.Write(make([]byte, 32-8))
	writeBoxTo(&img, "mdat", make([]byte, 1000))
	// 没有 moov

	reader := testutil.NewMemReader(img.Bytes())
	got := detectISOBMFFSizeFromSampleTable(reader, 0, 100*1024*1024)
	if got != 0 {
		t.Errorf("无 moov 应返回 0 触发 fallback，实际 %d", got)
	}
}

// TestDetectISOBMFFSize_CorruptedSTSZ 损坏的 stsz（sample_count 异常大）—— 返回 0 走 fallback
func TestDetectISOBMFFSize_CorruptedSTSZ(t *testing.T) {
	// 故意造 sample_count = 0xFFFFFFFF 的 stsz（损坏）
	var corruptStsz bytes.Buffer
	corruptStsz.Write([]byte{0, 0, 0, 0})                            // version+flags
	binary.Write(&corruptStsz, binary.BigEndian, uint32(0))          // default size
	binary.Write(&corruptStsz, binary.BigEndian, uint32(0xFFFFFFFF)) // 损坏的 count

	stsc := buildSTSC([][3]uint32{{1, 1, 1}})
	stco := buildSTCO([]uint32{100})
	stbl := buildMinimalSTBL(corruptStsz.Bytes(), stsc, stco, "stco")
	trak := buildTrak(stbl)

	var moov bytes.Buffer
	writeBoxTo(&moov, "trak", trak)

	var img bytes.Buffer
	img.Write([]byte{0, 0, 0, 0x20, 'f', 't', 'y', 'p'})
	img.Write(make([]byte, 32-8))
	writeBoxTo(&img, "moov", moov.Bytes())
	writeBoxTo(&img, "mdat", make([]byte, 100))

	reader := testutil.NewMemReader(img.Bytes())
	got := detectISOBMFFSizeFromSampleTable(reader, 0, 100*1024*1024)
	if got != 0 {
		t.Errorf("损坏 stsz 应返回 0，实际 %d", got)
	}
}

// TestDetectISOBMFFSize_PerSampleSizes 真实视频常见：每个 sample 大小不同（VBR 编码）
func TestDetectISOBMFFSize_PerSampleSizes(t *testing.T) {
	sizes := []uint32{1000, 2000, 1500, 3000, 800} // 总 8300
	stsz := buildSTSZ(0, sizes)
	stsc := buildSTSC([][3]uint32{{1, 5, 1}}) // 1 chunk, 5 samples
	stco := buildSTCO([]uint32{0})            // placeholder
	stbl := buildMinimalSTBL(stsz, stsc, stco, "stco")
	trak := buildTrak(stbl)

	var moov bytes.Buffer
	writeBoxTo(&moov, "trak", trak)

	const ftypSize = 32
	moovSize := uint32(8 + moov.Len())
	mdatStart := uint32(ftypSize) + moovSize + 8

	stco = buildSTCO([]uint32{mdatStart})
	stbl = buildMinimalSTBL(stsz, stsc, stco, "stco")
	trak = buildTrak(stbl)
	moov.Reset()
	writeBoxTo(&moov, "trak", trak)

	var img bytes.Buffer
	img.Write([]byte{0, 0, 0, 0x20, 'f', 't', 'y', 'p'})
	img.Write(make([]byte, 32-8))
	writeBoxTo(&img, "moov", moov.Bytes())
	writeBoxTo(&img, "mdat", make([]byte, 8300))

	expectedSize := int64(img.Len())

	reader := testutil.NewMemReader(img.Bytes())
	got := detectISOBMFFSizeFromSampleTable(reader, 0, 100*1024*1024)
	if got != expectedSize {
		t.Errorf("per-sample sizes: got %d, want %d", got, expectedSize)
	}
}

// TestDetectMP4Size_Integration 集成测试：经过 detectMP4Size 入口（含 fallback 逻辑）。
// 验证 size=0 mdat 不再返回 4GB。
func TestDetectMP4Size_Integration_Size0Mdat(t *testing.T) {
	stsz := buildSTSZ(0, []uint32{500, 500}) // 1000 总
	stsc := buildSTSC([][3]uint32{{1, 2, 1}})
	stco := buildSTCO([]uint32{0})
	stbl := buildMinimalSTBL(stsz, stsc, stco, "stco")
	trak := buildTrak(stbl)

	var moov bytes.Buffer
	writeBoxTo(&moov, "trak", trak)

	const ftypSize = 32
	moovSize := uint32(8 + moov.Len())
	mdatStart := uint32(ftypSize) + moovSize + 8

	stco = buildSTCO([]uint32{mdatStart})
	stbl = buildMinimalSTBL(stsz, stsc, stco, "stco")
	trak = buildTrak(stbl)
	moov.Reset()
	writeBoxTo(&moov, "trak", trak)

	var img bytes.Buffer
	img.Write([]byte{0, 0, 0, 0x20, 'f', 't', 'y', 'p'})
	img.Write(make([]byte, 32-8))
	writeBoxTo(&img, "moov", moov.Bytes())
	img.Write([]byte{0, 0, 0, 0, 'm', 'd', 'a', 't'}) // size=0 mdat
	img.Write(make([]byte, 1000))                     // 真实 mdat data
	img.Write(make([]byte, 4*1024*1024))              // 4MB 垃圾数据（模拟磁盘后续区）

	expectedSize := int64(ftypSize) + int64(moovSize) + 8 + 1000

	reader := testutil.NewMemReader(img.Bytes())
	const maxSize = 4 * 1024 * 1024 * 1024 // 4 GB（模拟 signature.MaxSize）
	got := detectMP4Size(reader, 0, maxSize)
	if got != expectedSize {
		t.Errorf("detectMP4Size 集成测试 size=0 mdat 失败：got %d, want %d", got, expectedSize)
	}
	// 关键断言：以前 v2.8.13 之前会返回 4GB，现在不应该
	if got >= 4*1024*1024*1024 {
		t.Errorf("v2.8.14 应该从 sample table 算精确大小，不应该返回 maxSize=%d", got)
	}
}
