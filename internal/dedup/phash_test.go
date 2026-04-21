package dedup

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

// 合成一张 16x16 的纯黑图 + 同样的图加 1 像素噪声，验证 aHash 接近
func TestComputeAverageHash_Similar(t *testing.T) {
	mk := func(noise bool) []byte {
		img := image.NewGray(image.Rect(0, 0, 16, 16))
		for y := 0; y < 16; y++ {
			for x := 0; x < 16; x++ {
				img.SetGray(x, y, color.Gray{Y: 0})
			}
		}
		if noise {
			img.SetGray(0, 0, color.Gray{Y: 255})
		}
		var buf bytes.Buffer
		png.Encode(&buf, img)
		return buf.Bytes()
	}

	h1, err := ComputeAverageHash(bytes.NewReader(mk(false)))
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	h2, err := ComputeAverageHash(bytes.NewReader(mk(true)))
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	d := HammingDistance(h1, h2)
	if d > 5 {
		t.Errorf("近似图 Hamming distance %d 太大", d)
	}
	if !IsSimilar(h1, h2, 5) {
		t.Error("应被识别为相似")
	}
}

// 完全不同的两张图（全黑 vs 全白）应有大 Hamming distance
func TestComputeAverageHash_Different(t *testing.T) {
	mkAll := func(v uint8) []byte {
		img := image.NewGray(image.Rect(0, 0, 16, 16))
		// 一半亮 + 一半暗，让 aHash 有"对比"
		for y := 0; y < 16; y++ {
			for x := 0; x < 16; x++ {
				if v == 0 {
					if x < 8 {
						img.SetGray(x, y, color.Gray{Y: 0})
					} else {
						img.SetGray(x, y, color.Gray{Y: 255})
					}
				} else {
					if x < 8 {
						img.SetGray(x, y, color.Gray{Y: 255})
					} else {
						img.SetGray(x, y, color.Gray{Y: 0})
					}
				}
			}
		}
		var buf bytes.Buffer
		png.Encode(&buf, img)
		return buf.Bytes()
	}
	h1, _ := ComputeAverageHash(bytes.NewReader(mkAll(0)))
	h2, _ := ComputeAverageHash(bytes.NewReader(mkAll(1)))
	if IsSimilar(h1, h2, 5) {
		t.Error("反相图不应被识别为相似")
	}
}

func TestSimilarityGroup_Basic(t *testing.T) {
	// 前两个相似，第三个不同
	hashes := []AverageHash{
		0xFFFFFFFFFFFFFFFF,
		0xFFFFFFFFFFFFFFFE, // 1 bit 差
		0x0000000000000000,
	}
	groups := SimilarityGroup(hashes, 5)
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Errorf("groups=%+v", groups)
	}
}
