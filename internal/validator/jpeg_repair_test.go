package validator

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
)

// makeValidJPEG 生成一张合法的小 JPEG，方便构造"本来能 Decode"的基线。
// 基线太小 Decode 会走标准库的 fast path，我们要的是能通过 image/jpeg.Decode。
func makeValidJPEG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{byte(x * 4), byte(y * 4), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatalf("jpeg.Encode: %v", err)
	}
	return buf.Bytes()
}

func TestRepairJPEG_NothingToDo(t *testing.T) {
	data := makeValidJPEG(t, 32, 32)
	repaired, info := RepairJPEG(data)
	if repaired != nil {
		t.Errorf("合法 JPEG 不应被'修复'，但 RepairJPEG 返回了修复版本；info=%q", info)
	}
}

func TestRepairJPEG_RefusesSOIMissing(t *testing.T) {
	data := []byte{0x00, 0x00, 0x01, 0x02, 0x03, 0x04}
	repaired, info := RepairJPEG(data)
	if repaired != nil {
		t.Errorf("无 SOI 的数据不应被修复；info=%q", info)
	}
}

func TestRepairJPEG_TruncatesOnIllegalMarker(t *testing.T) {
	// 取合法 JPEG → 找 SOS 段后面随机位置插入 FF E0（APP0 marker）制造"跨入别的数据"
	valid := makeValidJPEG(t, 64, 64)
	sosPos := findSOS(valid)
	if sosPos < 0 {
		t.Fatalf("测试基线 JPEG 里找不到 SOS")
	}
	sosLen := int(valid[sosPos+2])<<8 | int(valid[sosPos+3])
	corruptAt := sosPos + 2 + sosLen + 20 // 熵流起点之后 20 字节
	if corruptAt+4 >= len(valid) {
		t.Fatalf("测试基线 JPEG 太小，放不下 corruption")
	}

	damaged := make([]byte, len(valid))
	copy(damaged, valid)
	damaged[corruptAt] = 0xFF
	damaged[corruptAt+1] = 0xE0 // APP0：熵流里出现这种 marker = 非法

	repaired, info := RepairJPEG(damaged)
	if repaired == nil {
		t.Fatalf("应能做边界修复；info=%q", info)
	}
	// 修复版本必须以 FFD9 结尾
	if len(repaired) < 2 || repaired[len(repaired)-2] != 0xFF || repaired[len(repaired)-1] != 0xD9 {
		t.Errorf("修复版本必须以 FFD9 结尾")
	}
	// 修复版本长度必须 < 原损坏版本
	if len(repaired) >= len(damaged) {
		t.Errorf("修复应该截掉 corruption 点及其后数据，但 repaired=%d >= damaged=%d",
			len(repaired), len(damaged))
	}
}

func TestRepairJPEG_MidFileEOITruncation(t *testing.T) {
	// 模拟一种场景：文件后段拼接了一段无关数据，中段已有 EOI，应该只保留到中段 EOI
	valid := makeValidJPEG(t, 32, 32)
	// 在 valid 后面追加垃圾，让中段的 EOI 被"埋"在 valid 末尾
	junk := make([]byte, 512)
	for i := range junk {
		junk[i] = 0xAA
	}
	combined := append(append([]byte{}, valid...), junk...)

	repaired, info := RepairJPEG(combined)
	if repaired == nil {
		t.Fatalf("应能检测到中段 EOI 并截尾；info=%q", info)
	}
	if !bytes.Equal(repaired, valid) {
		t.Errorf("截尾结果应完全等于原始 valid JPEG；got %d bytes, want %d", len(repaired), len(valid))
	}
}

func TestRepairAndVerifyJPEG_ReturnsDecodable(t *testing.T) {
	// 构造一个"可修复"的场景：末尾缺 FFD9 + 熵流段尾部有些 corruption
	valid := makeValidJPEG(t, 48, 48)
	// 模拟被截断：去掉末尾 EOI 再加一些乱数据
	truncated := valid[:len(valid)-2]
	truncated = append(truncated, 0x12, 0x34) // junk 替代 EOI

	repaired, ok := RepairAndVerifyJPEG(truncated)
	// 这种情况不一定能修（看 decoder 宽容度），主要验证 API 不 panic 且返回一致
	if ok && repaired == nil {
		t.Errorf("ok=true 时 repaired 不应为 nil")
	}
	if !ok && repaired != nil {
		t.Errorf("ok=false 时 repaired 应为 nil")
	}
}
