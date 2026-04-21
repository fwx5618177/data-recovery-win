package carver

import (
	"crypto/rand"
	"testing"

	"data-recovery/internal/testutil"
)

// BenchmarkDetectFragmentationParanoid 给 paranoid v2 一个性能基准。
// 防回归：未来重构 byteEntropy / 多点采样实现时如果性能掉一半会被 CI 抓出来。
func BenchmarkDetectFragmentationParanoid(b *testing.B) {
	const size = 1 * 1024 * 1024 // 1 MB 文件
	disk := make([]byte, size)
	rand.Read(disk)
	r := testutil.NewMemReader(disk)

	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		_ = DetectFragmentationParanoid(r, 0, size, "unknown")
	}
}

func BenchmarkByteEntropy(b *testing.B) {
	buf := make([]byte, 32*1024)
	rand.Read(buf)
	b.ResetTimer()
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		_ = byteEntropy(buf)
	}
}
