package validator

import (
	"math/rand"
	"testing"
)

// 三种典型 block 类型 benchmark：
//   - DC-only：自然图像高频被量化掉的常见场景（短路应触发）
//   - Sparse：少量非零 AC 系数（合成图像 / 文本截图）
//   - Dense：所有 64 系数非零（高质量真实摄影）
//
// 实测对比：自然图像里 DC-only 占 ~30-60% 的 block；优化它的成本与 dense 同等重要。

func BenchmarkIDCT_DCOnly(b *testing.B) {
	var src [64]int32
	src[0] = 100 // 仅 DC
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block := src
		idct8x8(&block)
	}
}

func BenchmarkIDCT_Sparse(b *testing.B) {
	var src [64]int32
	src[0] = 1024
	src[1] = 200
	src[8] = -150
	src[9] = 50
	src[16] = 80
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block := src
		idct8x8(&block)
	}
}

func BenchmarkIDCT_Dense(b *testing.B) {
	var src [64]int32
	r := rand.New(rand.NewSource(42))
	for i := range src {
		src[i] = int32(r.Intn(2048) - 1024)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		block := src
		idct8x8(&block)
	}
}
