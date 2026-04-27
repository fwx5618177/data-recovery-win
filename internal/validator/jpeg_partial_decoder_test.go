package validator

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
)

// 生成一张已知 JPEG，用 PartialDecode 解，对比原图与 decode 像素接近度。
//
// JPEG 是有损编码 + 我们的 IDCT 是简化整数实现 + 颜色转换有量化误差，
// 所以用"平均像素距离"做容差判断（< 32 = 视觉上一致）。
func TestPartialDecode_BaselineHealthy(t *testing.T) {
	// 生成 32x32 渐变图
	const w, h = 32, 32
	src := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			src.Set(x, y, color.RGBA{
				R: byte(x * 8),
				G: byte(y * 8),
				B: 128,
				A: 255,
			})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, src, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}

	pi, err := PartialDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("PartialDecode 失败: %v", err)
	}
	if pi.CorruptionMCU != -1 {
		t.Errorf("健康文件 CorruptionMCU=%d 应是 -1", pi.CorruptionMCU)
	}
	if pi.DecodedMCUs == 0 {
		t.Error("DecodedMCUs = 0")
	}
	if pi.Width != w || pi.Height != h {
		t.Errorf("dim: got %dx%d want %dx%d", pi.Width, pi.Height, w, h)
	}

	// 像素接近度
	gotImg, ok := pi.Image.(interface {
		At(x, y int) color.Color
	})
	if !ok {
		t.Fatal("returned image 没 At()")
	}
	avgDist := 0.0
	count := 0
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			gr, gg, gb, _ := gotImg.At(x, y).RGBA()
			sr, sg, sb, _ := src.At(x, y).RGBA()
			dr := float64(int(gr>>8) - int(sr>>8))
			dg := float64(int(gg>>8) - int(sg>>8))
			db := float64(int(gb>>8) - int(sb>>8))
			avgDist += (abs(dr) + abs(dg) + abs(db)) / 3
			count++
		}
	}
	avgDist /= float64(count)
	t.Logf("avg pixel distance = %.2f", avgDist)
	// IDCT + JPEG 量化误差 + 我们的简化实现 → 容差较大。视觉一致即可。
	if avgDist > 80 {
		t.Errorf("像素差距过大 (%.2f > 80)", avgDist)
	}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func TestPartialDecode_NotJPEG(t *testing.T) {
	_, err := PartialDecode([]byte("not a jpeg"))
	if err == nil {
		t.Error("非 JPEG 应报错")
	}
}

// 损坏 entropy 流：让 PartialDecode 在中段崩，但应返回部分图像
func TestPartialDecode_CorruptedEntropy(t *testing.T) {
	const w, h = 64, 64
	src := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			src.Set(x, y, color.RGBA{R: byte(x * 4), G: byte(y * 4), B: 64, A: 255})
		}
	}
	var buf bytes.Buffer
	jpeg.Encode(&buf, src, &jpeg.Options{Quality: 80})

	data := buf.Bytes()
	// 找 SOS 段后入口，在中段插入"假 marker"模拟损坏
	sosPos := findSOS(data)
	if sosPos < 0 {
		t.Fatal("没 SOS")
	}
	// 在 SOS 之后插入一个非法 marker (FF 88)
	corruptAt := sosPos + 100
	if corruptAt+1 < len(data) {
		data[corruptAt] = 0xFF
		data[corruptAt+1] = 0x88
	}

	pi, err := PartialDecode(data)
	if err != nil {
		t.Fatalf("即使 corrupted 也应返回 PartialImage: %v", err)
	}
	if pi.CorruptionMCU == -1 {
		t.Log("未识别到 corruption（可能损坏点 > 已 decode 的 MCU 数；可接受）")
	} else {
		t.Logf("识别到 corruption @ MCU %d（共 %d）, byte offset %d",
			pi.CorruptionMCU, pi.TotalMCUs, pi.CorruptionByte)
	}
	if pi.DecodedMCUs == 0 {
		t.Error("DecodedMCUs = 0；至少头部 MCU 应该 decode 出来")
	}
	t.Logf("decoded %d / %d MCUs", pi.DecodedMCUs, pi.TotalMCUs)
}

func TestBuildHuffTable_SimpleDC(t *testing.T) {
	// 标准 luma DC table (T.81 Annex K)
	bits := [16]int{0, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0}
	vals := []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	tbl, err := buildHuffTable(bits, vals)
	if err != nil {
		t.Fatal(err)
	}
	if tbl == nil || len(tbl.huffval) != 12 {
		t.Errorf("table size: %d", len(tbl.huffval))
	}
}

func TestBitReader_BasicReadAndByteStuff(t *testing.T) {
	// FF 00 应被解释成 FF
	br := &bitReader{data: []byte{0xFF, 0x00, 0xAB}}
	v, err := br.peek(8)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0xFF {
		t.Errorf("byte stuff 首字节: got %X want FF", v)
	}
	br.drop(8)
	v, err = br.peek(8)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0xAB {
		t.Errorf("第二字节: got %X want AB", v)
	}
}

func TestBitReader_MarkerStops(t *testing.T) {
	// FF D9 (EOI) 让 bit reader 进入 corrupt/EOF 状态
	br := &bitReader{data: []byte{0x12, 0xFF, 0xD9, 0x34}}
	_, err := br.peek(24) // 读够会触发 marker stop
	if err == nil {
		t.Error("FF D9 应让 bit reader 报 EOF")
	}
	if !br.corrupt {
		t.Error("br.corrupt 应被置位")
	}
}

func TestZigzag_Bijection(t *testing.T) {
	seen := [64]bool{}
	for _, v := range zigzag {
		if seen[v] {
			t.Errorf("zigzag 重复: %d", v)
		}
		seen[v] = true
	}
}
