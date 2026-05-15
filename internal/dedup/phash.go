// Package dedup 提供 perceptual hashing —— 找回 5 万张照片后用户最大需求是
// "近似查重"（同一张图被 carve 出多次但 SHA-256 不同 = 字节级差异，但视觉上一样）。
//
// **当前实现**：64-bit aHash (average hash) — 最简单但有效的 perceptual hash。
//  1. 解码图片为灰度
//  2. 缩放到 8x8
//  3. 算 64 个像素的平均亮度
//  4. 每个像素 > 平均 → bit=1，否则 0
//  5. 64 bit 拼成 uint64
//
// 比较：两个 hash 的 Hamming distance ≤ 5 = 视觉上很可能同一张图。
//
// pHash (DCT) 更准但 ~5x 慢；本工具暂用 aHash。
package dedup

import (
	"image"
	"image/color"
	_ "image/jpeg" // 注册 jpeg decoder
	_ "image/png"  // 注册 png decoder
	"io"
	"math/bits"
)

// AverageHash 64-bit perceptual hash
type AverageHash uint64

// ComputeAverageHash 从 image reader 算出 aHash。
// 解码失败返回 0 + error。
func ComputeAverageHash(r io.Reader) (AverageHash, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return 0, err
	}
	// 缩放到 8x8 + 灰度（不引第三方包，自己做最简 nearest-neighbor）
	const N = 8
	src := img.Bounds()
	srcW, srcH := src.Dx(), src.Dy()
	if srcW <= 0 || srcH <= 0 {
		return 0, nil
	}
	pixels := make([]uint16, N*N)
	var sum uint32
	for y := 0; y < N; y++ {
		for x := 0; x < N; x++ {
			sx := src.Min.X + x*srcW/N
			sy := src.Min.Y + y*srcH/N
			c := color.GrayModel.Convert(img.At(sx, sy)).(color.Gray)
			pixels[y*N+x] = uint16(c.Y)
			sum += uint32(c.Y)
		}
	}
	avg := uint16(sum / (N * N))
	var h AverageHash
	for i, p := range pixels {
		if p > avg {
			h |= 1 << uint(i)
		}
	}
	return h, nil
}

// HammingDistance 两个 hash 的不同 bit 数；0 = 完全相同；64 = 完全相反
func HammingDistance(a, b AverageHash) int {
	return bits.OnesCount64(uint64(a ^ b))
}

// IsSimilar Hamming distance ≤ 阈值 (默认 5)
func IsSimilar(a, b AverageHash, threshold int) bool {
	if threshold <= 0 {
		threshold = 5
	}
	return HammingDistance(a, b) <= threshold
}

// SimilarityGroup 把一组 hash 聚类成"近似相同"的组。
// 简单 O(n²) 实现 —— n 大时改用 BK-tree。
func SimilarityGroup(hashes []AverageHash, threshold int) [][]int {
	used := make([]bool, len(hashes))
	var groups [][]int
	for i := range hashes {
		if used[i] {
			continue
		}
		g := []int{i}
		used[i] = true
		for j := i + 1; j < len(hashes); j++ {
			if used[j] {
				continue
			}
			if IsSimilar(hashes[i], hashes[j], threshold) {
				g = append(g, j)
				used[j] = true
			}
		}
		if len(g) > 1 {
			groups = append(groups, g)
		}
	}
	return groups
}
