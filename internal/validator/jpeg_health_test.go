package validator

import "testing"

// 正向：合法 JPEG 结构（SOI + 少量 RST + EOI）应得高分
func TestComputeJPEGHealth_Clean(t *testing.T) {
	// SOI + APP0 头 + SOS + 一段干净熵流（无非法 marker）+ RST × 2 + EOI
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, // APP0
		0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 0, 0, // SOS
		// 熵数据：普通字节 + 偶尔 FF00 stuffed + RST
		0x12, 0x34, 0xFF, 0x00, 0x56, 0xFF, 0xD0, 0x78, 0x9A, 0xFF, 0xD1, 0xBC,
		0xFF, 0xD9, // EOI
	}
	score := computeJPEGHealth(jpeg)
	if score < 0.9 {
		t.Errorf("clean JPEG 应高分，got %v", score)
	}
}

// 负向：熵流中间混入 APP marker（典型碎片化"半截图"）应低分
func TestComputeJPEGHealth_FragmentWithJunk(t *testing.T) {
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 0, 0, // SOS
		// 熵流中间混 APP0 / SOF / DHT 等"头部 marker"——碎片特征
		0x12, 0xFF, 0xE0, 0x00, 0x10, 'X', // 熵中混 APP0
		0xFF, 0xC0, 0x00, 0x11, // 熵中混 SOF0
		0xFF, 0xC4, 0x00, 0x1F, // 熵中混 DHT
		0xFF, 0xDB, 0x00, 0x43, // 熵中混 DQT
		0xFF, 0xD9, // EOI
	}
	score := computeJPEGHealth(jpeg)
	if score >= 0.7 {
		t.Errorf("fragmented JPEG 应得低分，got %v", score)
	}
}

// 缺 EOI（截断）分数应被 × 0.5
func TestComputeJPEGHealth_NoEOI(t *testing.T) {
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 0, 0, // SOS
		0xFF, 0xD0, 0xFF, 0xD1, // RST × 2
		0x12, 0x34, 0x56, // 尾部截断
	}
	score := computeJPEGHealth(jpeg)
	if score >= 0.5 {
		t.Errorf("截断 JPEG 最多 0.5, got %v", score)
	}
}

// 空文件 / 非 JPEG → 0
func TestComputeJPEGHealth_Invalid(t *testing.T) {
	if got := computeJPEGHealth(nil); got != 0 {
		t.Errorf("nil: %v", got)
	}
	if got := computeJPEGHealth([]byte{0x89, 0x50, 0x4E, 0x47}); got != 0 {
		t.Errorf("PNG 签名: %v", got)
	}
}
