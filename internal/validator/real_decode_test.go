package validator

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

// 回归测试：合法 JPEG 必须通过新的严格阈值（防误伤）
func TestValidateJPEG_RealValidImagePasses(t *testing.T) {
	// 生成一张 100x100 RGBA 图，encode 成 JPEG
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			img.Set(x, y, color.RGBA{byte(x * 2), byte(y * 2), 128, 255})
		}
	}
	buf := &bytes.Buffer{}
	if err := jpeg.Encode(buf, img, &jpeg.Options{Quality: 85}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	data := buf.Bytes()

	v := &Validator{reader: &mockReader{data: data}}
	res := v.validateJPEG(0, int64(len(data)))
	if !res.IsValid {
		t.Errorf("合法 JPEG 应通过 validator: %+v", res)
	}
	if res.Confidence < 0.9 {
		t.Errorf("合法 JPEG confidence 应 >= 0.9: %v\n%s", res.Confidence, res.Message)
	}
}

// 破损 JPEG（中间字节被覆写）应被拒
func TestValidateJPEG_CorruptedImageRejected(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	buf := &bytes.Buffer{}
	_ = jpeg.Encode(buf, img, &jpeg.Options{Quality: 85})
	data := buf.Bytes()

	// 把中间一段（熵数据区）替换成其他文件特征（模拟碎片）
	// SOS 之后是熵流；往里面塞 "BM" (BMP 签名) / "PDF" / 其他 magic
	mid := len(data) / 2
	corrupt := []byte{'%', 'P', 'D', 'F', '-', '1', '.', '4', 0x0A, 'B', 'M', 'P', 'Z'}
	copy(data[mid:mid+len(corrupt)], corrupt)

	v := &Validator{reader: &mockReader{data: data}}
	res := v.validateJPEG(0, int64(len(data)))
	if res.IsValid {
		t.Errorf("破损 JPEG 不应通过（confidence=%v, Message=%s）", res.Confidence, res.Message)
	}
}

// 合法 PNG 通过
func TestValidatePNG_RealValidImagePasses(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	buf := &bytes.Buffer{}
	if err := png.Encode(buf, img); err != nil {
		t.Fatalf("encode: %v", err)
	}
	data := buf.Bytes()
	v := &Validator{reader: &mockReader{data: data}}
	res := v.validatePNG(0, int64(len(data)))
	if !res.IsValid {
		t.Errorf("合法 PNG 应通过: %+v", res)
	}
}

// 破损 PNG —— IHDR CRC 对但 Decode 会失败
func TestValidatePNG_CorruptedImageRejected(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	buf := &bytes.Buffer{}
	_ = png.Encode(buf, img)
	data := buf.Bytes()

	// 把 IDAT 中间的字节替换 → zlib 解压会失败
	if len(data) > 100 {
		for i := 50; i < 80 && i < len(data); i++ {
			data[i] = 0xFF
		}
	}

	v := &Validator{reader: &mockReader{data: data}}
	res := v.validatePNG(0, int64(len(data)))
	if res.IsValid {
		t.Errorf("破损 PNG 不应通过: %+v", res)
	}
}
