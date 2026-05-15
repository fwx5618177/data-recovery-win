package carver

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"data-recovery/internal/testutil"
)

// JPEG：最小可解析文件 = SOI(FFD8) + APP0(FFE0 + 16B) + SOS(FFDA + 12B + 熵数据) + EOI(FFD9)
func minimalJPEG() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI

	// APP0 段：FFE0 LL LL ...（LL 包含自身 2 字节）
	app0 := []byte{0xFF, 0xE0, 0x00, 0x10}
	app0 = append(app0, make([]byte, 14)...) // 凑满 16 字节
	buf.Write(app0)

	// SOS 段：FFDA LL LL ...
	sos := []byte{0xFF, 0xDA, 0x00, 0x0C}
	sos = append(sos, make([]byte, 10)...)
	buf.Write(sos)

	// 熵数据几个字节
	buf.Write([]byte{0x01, 0x02, 0x03})
	// FF00 字节填充（不应被识别为 marker）
	buf.Write([]byte{0xFF, 0x00})
	// RST0 marker（FFD0），应该跳过继续
	buf.Write([]byte{0xFF, 0xD0})
	buf.Write([]byte{0x04, 0x05})
	// EOI
	buf.Write([]byte{0xFF, 0xD9})

	return buf.Bytes()
}

func TestDetectJPEGSize(t *testing.T) {
	data := minimalJPEG()
	reader := testutil.NewMemReader(data)
	size := detectJPEGSize(reader, 0, int64(len(data)+100))
	if size != int64(len(data)) {
		t.Errorf("期望 %d, 实际 %d", len(data), size)
	}
}

func TestDetectJPEGSize_WithOffset(t *testing.T) {
	// 在前面填一些垃圾数据，检验偏移是否正确处理
	data := minimalJPEG()
	buffer := append(bytes.Repeat([]byte{0xAA}, 1024), data...)
	reader := testutil.NewMemReader(buffer)

	size := detectJPEGSize(reader, 1024, int64(len(data)+100))
	if size != int64(len(data)) {
		t.Errorf("带偏移的 JPEG 大小检测错：got %d, want %d", size, len(data))
	}
}

func TestDetectJPEGSize_NoEOI(t *testing.T) {
	// 破坏 EOI marker
	data := minimalJPEG()
	data[len(data)-1] = 0x00
	reader := testutil.NewMemReader(data)
	size := detectJPEGSize(reader, 0, int64(len(data)))
	if size != 0 {
		t.Errorf("缺少 EOI 应返回 0, 实际 %d", size)
	}
}

// PNG: 8 字节签名 + chunk 链，末尾为 IEND chunk
func minimalPNG() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) // 签名

	// IHDR chunk（长度 13）
	writeChunk(&buf, "IHDR", make([]byte, 13))
	// IDAT chunk（任意数据）
	writeChunk(&buf, "IDAT", []byte{0x01, 0x02, 0x03})
	// IEND chunk（长度 0）
	writeChunk(&buf, "IEND", nil)

	return buf.Bytes()
}

func writeChunk(buf *bytes.Buffer, name string, data []byte) {
	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(data)))
	buf.Write(sizeBuf[:])
	buf.WriteString(name)
	buf.Write(data)
	buf.Write([]byte{0, 0, 0, 0}) // 假 CRC
}

func TestDetectPNGSize(t *testing.T) {
	data := minimalPNG()
	reader := testutil.NewMemReader(data)
	size := detectPNGSize(reader, 0, int64(len(data)+100))
	if size != int64(len(data)) {
		t.Errorf("期望 %d, 实际 %d", len(data), size)
	}
}

func TestDetectPNGSize_NoIEND(t *testing.T) {
	// 去掉 IEND
	data := minimalPNG()
	data = data[:len(data)-16]
	reader := testutil.NewMemReader(data)
	size := detectPNGSize(reader, 0, int64(len(data)))
	if size != 0 {
		t.Errorf("缺少 IEND 应返回 0, 实际 %d", size)
	}
}

// PDF：只要 %PDF 头 + 最后一个 %%EOF 即可
func minimalPDF() []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	buf.WriteString("1 0 obj\n<<>>\nendobj\n")
	buf.WriteString("xref\n0 1\ntrailer <</Size 1>>\n")
	buf.WriteString("%%EOF\n")
	return buf.Bytes()
}

func TestDetectPDFSize(t *testing.T) {
	data := minimalPDF()
	reader := testutil.NewMemReader(data)
	size := detectPDFSize(reader, 0, int64(len(data)+1024))
	if size <= 0 {
		t.Fatalf("应返回正数大小，实际 %d", size)
	}
	// %%EOF 结束位置必然 <= 整个数据长度
	if size > int64(len(data)) {
		t.Errorf("返回大小 %d 超过数据长度 %d", size, len(data))
	}
	// 预期 size 覆盖到 %%EOF（至多到末尾）
	if size < int64(len(data))-2 {
		t.Errorf("返回大小 %d 不应小于 %d", size, len(data)-2)
	}
}

// ZIP：local file header + EOCD
func minimalZIP() []byte {
	var buf bytes.Buffer
	// Local file header: 504B0304 + 其他字段（简化，只需最小长度）
	buf.Write([]byte{0x50, 0x4B, 0x03, 0x04})
	buf.Write(make([]byte, 26))

	// 空文件内容

	// EOCD: 504B0506 + 18 字节字段（总 22 字节，comment length = 0）
	eocd := []byte{0x50, 0x4B, 0x05, 0x06}
	eocd = append(eocd, make([]byte, 16)...)
	eocd = append(eocd, 0x00, 0x00) // comment length
	buf.Write(eocd)
	return buf.Bytes()
}

func TestDetectZIPSize(t *testing.T) {
	data := minimalZIP()
	reader := testutil.NewMemReader(data)
	size := detectZIPSize(reader, 0, int64(len(data)+1024))
	if size == 0 {
		t.Fatal("应检测到 ZIP 大小")
	}
	if size != int64(len(data)) {
		t.Errorf("期望 %d, 实际 %d", len(data), size)
	}
}

// RIFF/WAV: RIFF + size + WAVE + ...
func minimalWAV() []byte {
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	// 小端 size = 文件总长度 - 8
	// 这里先占位，后面回填
	buf.Write([]byte{0, 0, 0, 0})
	buf.WriteString("WAVE")
	buf.WriteString("fmt ")
	buf.Write([]byte{16, 0, 0, 0}) // fmt chunk size = 16
	buf.Write(make([]byte, 16))    // fmt 数据
	buf.WriteString("data")
	buf.Write([]byte{4, 0, 0, 0}) // data chunk size = 4
	buf.Write([]byte{1, 2, 3, 4})

	data := buf.Bytes()
	size := uint32(len(data) - 8)
	binary.LittleEndian.PutUint32(data[4:8], size)
	return data
}

func TestDetectRIFFSize(t *testing.T) {
	data := minimalWAV()
	reader := testutil.NewMemReader(data)
	size := detectRIFFSize(reader, 0, int64(len(data)+100))
	if size != int64(len(data)) {
		t.Errorf("期望 %d, 实际 %d", len(data), size)
	}
}

func TestSizeDetectionReliable(t *testing.T) {
	// 保证关键常见格式处于"可靠检测"名单（提前发现回归）
	reliable := []string{"jpg", "png", "pdf", "zip", "mp4", "mp3", "avi", "wav"}
	for _, ext := range reliable {
		if !sizeDetectionReliable(ext) {
			t.Errorf("%s 应在可靠检测名单", ext)
		}
	}
	// 未登记格式应为 unreliable
	unreliable := []string{"rtf", "svg", "sqlite"}
	for _, ext := range unreliable {
		if sizeDetectionReliable(ext) {
			t.Errorf("%s 不应在可靠检测名单", ext)
		}
	}
}

// ===========================================================================
// MP3 / AAC 误报防御测试
//
// 背景：短签名（MP3 的 FFFB 2 字节、AAC 的 FFF1 2 字节）在随机磁盘数据上
// 平均每 2KB 就能碰上一次。必须保证：
//   1. 单帧看起来合法但后续无帧链 → 必然拒收
//   2. 纯随机 / 全零 / 全 FF 数据 → 必然拒收
//   3. 只有真实的、连续 ≥ mp3MinValidFrames 个同指纹帧才通过
// ===========================================================================

// buildMP3Frame 构造一个 MPEG1 Layer III @ 128kbps 44.1kHz 的 417 字节帧。
// 该组合是最常见的 MP3 编码参数，帧长度恒为 417（无 padding）。
func buildMP3Frame() []byte {
	b := make([]byte, 417)
	// 帧同步 FF FB 90 44：
	//   FF     sync 高 8
	//   FB     sync 低 3 + version(11,MPEG1) + layer(01,L3) + CRC(1,none)
	//   90     bitrate(1001,128kbps) + samplerate(00,44.1k) + padding(0) + private(0)
	//   44     channel(01,JointStereo) + mode_ext(00) + copyright(0) + original(1) + emph(00)
	b[0] = 0xFF
	b[1] = 0xFB
	b[2] = 0x90
	b[3] = 0x44
	return b
}

func TestDetectMP3_RealFileAccepted(t *testing.T) {
	// 20 个同指纹帧 = ~8KB，足以通过严格校验
	var buf bytes.Buffer
	for i := 0; i < 20; i++ {
		buf.Write(buildMP3Frame())
	}
	// 真实 MP3 后面跟 ID3v1
	buf.WriteString("TAG")
	buf.Write(make([]byte, 125))

	reader := testutil.NewMemReader(buf.Bytes())
	size := detectMP3Size(reader, 0, int64(len(buf.Bytes())+100))
	if size == 0 {
		t.Fatal("合法 20 帧 MP3 应被接受")
	}
	if size < int64(20*417) {
		t.Errorf("应读到 20 帧以上，实际 size=%d", size)
	}
}

func TestDetectMP3_OnlyOneFrameRejected(t *testing.T) {
	// 单帧之后就是随机数据 —— 过去允许 3 帧容差，现在要求 16 帧连续链，必须拒收
	buf := append(buildMP3Frame(), bytes.Repeat([]byte{0x12, 0x34, 0x56, 0x78}, 1024)...)
	reader := testutil.NewMemReader(buf)
	size := detectMP3Size(reader, 0, int64(len(buf)))
	if size != 0 {
		t.Errorf("孤立单帧应被拒收，实际 size=%d", size)
	}
}

func TestDetectMP3_RandomNoiseRejected(t *testing.T) {
	// 纯随机 64KB，即使里面偶有 FFE0 同步字也不该被识别为 MP3
	r := rand.New(rand.NewSource(42))
	noise := make([]byte, 64*1024)
	r.Read(noise)
	// 确保起始字节是 FFFB 以命中 AC；后续随机
	noise[0] = 0xFF
	noise[1] = 0xFB
	reader := testutil.NewMemReader(noise)
	size := detectMP3Size(reader, 0, int64(len(noise)))
	if size != 0 {
		t.Errorf("纯随机数据应被拒收，实际 size=%d", size)
	}
}

func TestDetectMP3_AllFFRejected(t *testing.T) {
	// 连续全 FF —— 过去易被误识为 MP3 流，严格版必须拒
	data := bytes.Repeat([]byte{0xFF}, 32*1024)
	reader := testutil.NewMemReader(data)
	size := detectMP3Size(reader, 0, int64(len(data)))
	if size != 0 {
		t.Errorf("全 FF 数据应被拒收，实际 size=%d", size)
	}
}

func TestDetectMP3_ID3v2ThenFrames(t *testing.T) {
	// ID3v2 header(10) + size=100 的假 tag + 20 帧
	tagData := make([]byte, 100)
	hdr := []byte{'I', 'D', '3', 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64} // size=100 (syncsafe)
	var buf bytes.Buffer
	buf.Write(hdr)
	buf.Write(tagData)
	for i := 0; i < 20; i++ {
		buf.Write(buildMP3Frame())
	}

	reader := testutil.NewMemReader(buf.Bytes())
	size := detectMP3Size(reader, 0, int64(len(buf.Bytes())+100))
	if size == 0 {
		t.Fatal("ID3v2 + 20 帧的 MP3 应被接受")
	}
}

func TestDetectMP3_ID3v2ButNoFramesRejected(t *testing.T) {
	// 随机数据凑出 "ID3" 三个字节，但 tag 之后不是合法帧头 → 拒收
	tagData := make([]byte, 100)
	hdr := []byte{'I', 'D', '3', 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}
	var buf bytes.Buffer
	buf.Write(hdr)
	buf.Write(tagData)
	buf.Write([]byte{0xAB, 0xCD, 0xEF, 0x01}) // 不是 FFE0 同步
	buf.Write(make([]byte, 1000))

	reader := testutil.NewMemReader(buf.Bytes())
	size := detectMP3Size(reader, 0, int64(len(buf.Bytes())))
	if size != 0 {
		t.Errorf("ID3 头后无合法帧应被拒收，实际 size=%d", size)
	}
}

// buildAACFrame 构造一个 ADTS AAC 帧（长度 frameLen，包含 7 字节头）。
func buildAACFrame(frameLen int) []byte {
	if frameLen < 7 {
		frameLen = 7
	}
	b := make([]byte, frameLen)
	// FF F1 50 80 00 [ll] FC
	// F1: sync12 + version(0) + layer(00) + protection_absent(1)
	// 50: profile(01,LC) + freq_idx(0100,44.1k) + private(0) + channel-high(0)
	// 80: channel-low(10,stereo) + origin(0) + home(0) + copy_id(0) + copy_start(0) + frame_length(high)
	// frame_length 13 bits 跨越 byte[3][4][5]
	b[0] = 0xFF
	b[1] = 0xF1
	b[2] = 0x50
	// 帧长占 3..5：b[3] 低 2 位 = fl bit12..11，b[4] = fl bit10..3，b[5] 高 3 位 = fl bit2..0
	b[3] = 0x80 | byte((frameLen>>11)&0x03)
	b[4] = byte((frameLen >> 3) & 0xFF)
	b[5] = byte((frameLen&0x07)<<5) | 0x1F
	b[6] = 0xFC
	return b
}

func TestDetectAAC_RealFileAccepted(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 20; i++ {
		buf.Write(buildAACFrame(256))
	}
	reader := testutil.NewMemReader(buf.Bytes())
	size := detectAACSize(reader, 0, int64(len(buf.Bytes())+100))
	if size == 0 {
		t.Fatal("合法 20 帧 AAC 应被接受")
	}
}

func TestDetectAAC_RandomNoiseRejected(t *testing.T) {
	r := rand.New(rand.NewSource(1337))
	noise := make([]byte, 64*1024)
	r.Read(noise)
	noise[0] = 0xFF
	noise[1] = 0xF1
	reader := testutil.NewMemReader(noise)
	size := detectAACSize(reader, 0, int64(len(noise)))
	if size != 0 {
		t.Errorf("随机数据不应被认成 AAC，实际 size=%d", size)
	}
}

func TestDetectAAC_OnlyOneFrameRejected(t *testing.T) {
	data := append(buildAACFrame(256), bytes.Repeat([]byte{0x00}, 8192)...)
	reader := testutil.NewMemReader(data)
	size := detectAACSize(reader, 0, int64(len(data)))
	if size != 0 {
		t.Errorf("孤立单帧 AAC 应被拒收，实际 size=%d", size)
	}
}
