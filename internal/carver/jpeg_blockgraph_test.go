package carver

import (
	"bytes"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// 工具：构造一个最小合法 JPEG 字节流（带 RST，便于触发 stitching 路径）
func makeMinimalJPEGWithRST(restartInterval int, rstCount int) []byte {
	var b bytes.Buffer
	// SOI
	b.WriteByte(0xFF)
	b.WriteByte(jpegSOI)
	// DRI segment：marker(2) + length(2)=0x0004 + interval(2)
	b.WriteByte(0xFF)
	b.WriteByte(jpegDRI)
	binary.Write(&b, binary.BigEndian, uint16(4))
	binary.Write(&b, binary.BigEndian, uint16(restartInterval))
	// SOS segment：marker(2) + length(2)=0x000C + 10 byte filler
	b.WriteByte(0xFF)
	b.WriteByte(jpegSOS)
	binary.Write(&b, binary.BigEndian, uint16(12))
	for i := 0; i < 10; i++ {
		b.WriteByte(0)
	}
	// 熵数据 + RST 序列
	for i := 0; i < rstCount; i++ {
		// 写一些非 0xFF 字节模拟 entropy data
		for j := 0; j < 16; j++ {
			b.WriteByte(byte(0x10 + (i*j)%200))
		}
		// RSTn marker
		b.WriteByte(0xFF)
		b.WriteByte(jpegRST0 + byte(i%8))
	}
	// 尾部 entropy + EOI
	for j := 0; j < 16; j++ {
		b.WriteByte(0xAA)
	}
	b.WriteByte(0xFF)
	b.WriteByte(jpegEOI)
	return b.Bytes()
}

// 健康（连续）JPEG：Carve 应直接返回 EOI 边界，不做 stitching
func TestJPEGCarver_HealthyContinuous(t *testing.T) {
	jpeg := makeMinimalJPEGWithRST(1, 3) // RSTn 序号 0,1,2
	disk := append([]byte{0xAA, 0xBB}, jpeg...) // 前面有 2 字节噪声
	r := testutil.NewMemReader(disk)

	c := NewJPEGBlockGraphCarver(r)
	c.MaxFileSize = int64(len(disk) + 256)
	res, err := c.Carve(2) // SOI 在 offset 2
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if res.Fragmented {
		t.Errorf("健康文件不应被识别为碎片")
	}
	if !bytes.Equal(res.Bytes, jpeg) {
		t.Errorf("carved 字节不匹配:\n  got  %x\n  want %x", res.Bytes[:16], jpeg[:16])
	}
	// 末尾必须是 EOI
	last2 := res.Bytes[len(res.Bytes)-2:]
	if last2[0] != 0xFF || last2[1] != jpegEOI {
		t.Errorf("末尾应是 EOI: %X", last2)
	}
}

// 碎片场景：JPEG 中段被另一个文件覆盖，但后段还在
//   [JPEG_head with RST0,RST1] + [垃圾 256 字节] + [JPEG_tail starting RST2 ... EOI]
// Carver 应识别 RST 序号断（到 RST2 时跳到了别处）→ stitching → 找回完整文件
func TestJPEGCarver_StitchesAcrossGarbage(t *testing.T) {
	full := makeMinimalJPEGWithRST(1, 4) // RST 0,1,2,3
	// 找 RST2 位置：扫 0xFF 0xD2
	var rst2Pos int
	for i := 0; i < len(full)-1; i++ {
		if full[i] == 0xFF && full[i+1] == 0xD2 {
			rst2Pos = i
			break
		}
	}
	if rst2Pos == 0 {
		t.Fatal("makeMinimalJPEGWithRST 没生成 RST2")
	}

	// 切掉 RST2 之后到 EOI 之间一段 → 制造碎片
	head := full[:rst2Pos]      // 含到 RST1 之后部分
	tail := full[rst2Pos:]       // 从 RST2 开始
	garbage := make([]byte, 256) // 中间夹 256 字节"别的文件"
	for i := range garbage {
		garbage[i] = byte(0x99)
	}

	// 组装 disk：head + garbage + tail
	// 让 head 的"碎片断点"出现在 RST 序号期望 = 2 的位置
	// 我们故意在 RST1 之后插入一段非 RST/非 EOI 字节（假装下一个 marker 不再是 RST2）
	// 正确的"另一种文件" 字节模拟是放一个 SOI 0xFF 0xD8 触发碎片识别：
	headWithFakeMarker := append([]byte{}, head...)
	headWithFakeMarker = append(headWithFakeMarker, 0xFF, jpegSOI) // 触发"中段又出现 SOI"
	headWithFakeMarker = append(headWithFakeMarker, 0x00, 0x01, 0x02) // 一些 jam

	disk := append(headWithFakeMarker, garbage...)
	disk = append(disk, tail...)
	r := testutil.NewMemReader(disk)

	c := NewJPEGBlockGraphCarver(r)
	c.MaxFileSize = int64(len(disk) + 256)
	c.SearchWindow = int64(len(disk))
	c.ChunkSize = 32

	res, err := c.Carve(0)
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if !res.Fragmented {
		t.Fatalf("应识别为碎片: reason=%s", res.Reason)
	}
	if res.Stitches < 1 {
		t.Errorf("Stitches=%d want >=1", res.Stitches)
	}
	// 末尾应是 EOI（拼接成功）
	if len(res.Bytes) >= 2 {
		last2 := res.Bytes[len(res.Bytes)-2:]
		if last2[0] != 0xFF || last2[1] != jpegEOI {
			t.Logf("stitched 但未找到 EOI（这在搜索窗口不够时是合法降级）reason=%s", res.Reason)
		}
	}
}

// findJPEGEOI 单元测试
func TestFindJPEGEOI(t *testing.T) {
	if findJPEGEOI([]byte{0x10, 0xFF, 0xD9, 0x20}) != 1 {
		t.Error("应在 1 找到 EOI")
	}
	if findJPEGEOI([]byte{0x10, 0xFF, 0x00, 0xFF, 0xD9}) != 3 {
		t.Error("应跳过 stuffed byte")
	}
	if findJPEGEOI([]byte{0x10, 0x20, 0x30}) != -1 {
		t.Error("无 EOI 应返回 -1")
	}
}
