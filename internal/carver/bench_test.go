package carver

import (
	"context"
	"crypto/rand"
	"testing"

	"data-recovery/internal/signature"
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

// BenchmarkScan_RandomDisk_64MB 给 carver 端到端扫描跑性能基准。
//
// 用 64MB 随机字节内存盘当模拟磁盘 —— 没有真实签名命中，纯测量"扫这么多字节
// 经过 AC 匹配 + 流水线开销的吞吐"。这是 carver 跑大盘时的瓶颈。
//
// v2.8.37 perf 改动（ChunkSize 8MB + chunkCh 缓冲 Workers*4）应该提高 throughput
// 在多核 + SSD/NVMe 上的"AC 搜索 + 流水线"组件成本。任何回归（搜索算法变慢 /
// 流水线 channel 变小 / chunk pool 失效）都会让这个基准报警。
//
// b.SetBytes 让 ns/op 转 MB/s 直观。运行：
//
//	go test -bench=BenchmarkScan_RandomDisk_64MB -benchmem ./internal/carver/
func BenchmarkScan_RandomDisk_64MB(b *testing.B) {
	const size = 64 * 1024 * 1024
	data := make([]byte, size)
	rand.Read(data)
	sigDB := signature.NewSignatureDB()

	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		r := testutil.NewMemReader(data)
		eng := NewEngine(r, sigDB, DefaultConfig())
		b.StartTimer()

		_ = eng.Scan(context.Background(), 0, size, nil, nil)
	}
}
