package carver

import (
	"context"
	"testing"

	"data-recovery/internal/signature"
	"data-recovery/internal/testutil"
	"data-recovery/internal/types"
)

// buildSparsePNGDisk 造一个磁盘：在多个偏移上各放一个完整可解析的最小 PNG，
// 用来让 carver 从池化缓冲里多次命中、多次释放，验证池没有破坏结果正确性。
//
// PNG 依赖 IEND chunk 收尾，否则 determineFileSize 会判定失败从而不产出文件，
// 这会让测试变成对"签名误报丢弃"的验证而非对 pool 的验证。这里直接复用
// formats_test.go 里同样风格，但不依赖其私有 helper。
func buildMinimalPNG() []byte {
	// PNG signature + IHDR (minimal) + IEND
	var b []byte
	b = append(b, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) // magic
	// IHDR 长度 13 + type "IHDR"
	b = append(b, 0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R')
	// 13 字节 IHDR 数据占位
	b = append(b, make([]byte, 13)...)
	// CRC 占位
	b = append(b, 0x00, 0x00, 0x00, 0x00)
	// IEND length=0 + "IEND" + CRC
	b = append(b, 0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D')
	b = append(b, 0xAE, 0x42, 0x60, 0x82)
	return b
}

// 回归测试：启用 sync.Pool 后，扫描多个块仍能正确命中所有签名。
// 这也是对 `Data[:Size]` 切片上界的间接测试——如果 Search 在 pool 缓冲越界读，
// 要么报错要么产生偏移错误的假命中。
func TestCarver_PoolReusePreservesMatches(t *testing.T) {
	png := buildMinimalPNG()

	// 造一个 3 * 4MB 的磁盘，在三个不同偏移各埋一个 PNG
	chunkSize := int64(4 * 1024 * 1024)
	disk := make([]byte, chunkSize*3)
	offsets := []int64{100, chunkSize + 5000, 2*chunkSize + 1024}
	for _, off := range offsets {
		copy(disk[off:], png)
	}

	reader := testutil.NewMemReader(disk)
	cfg := Config{
		ChunkSize:   chunkSize,
		Workers:     2,
		MaxFileSize: chunkSize * 3,
	}
	engine := NewEngine(reader, signature.NewSignatureDB(), cfg)

	var found []*types.RecoveredFile
	err := engine.Scan(context.Background(), 0, int64(len(disk)),
		nil,
		func(f *types.RecoveredFile) { found = append(found, f) },
	)
	if err != nil {
		t.Fatalf("Scan 失败: %v", err)
	}

	// 允许相同 PNG 被多次 overlap 命中后去重，只要我们埋的三个都被找到即可
	foundOffsets := make(map[int64]bool)
	for _, f := range found {
		foundOffsets[f.Offset] = true
	}
	for _, want := range offsets {
		if !foundOffsets[want] {
			t.Errorf("偏移 0x%X 处的 PNG 未被识别；总共找到 %d 个", want, len(found))
		}
	}
}

// 回归测试：大量命中不会让 seen map 超过 soft cap 的 2 倍——
// 若水位线裁剪逻辑失效，map 会被撑到上百万级。这里用大量分布于不同偏移的 PNG
// 模拟真实碎片盘，验证裁剪实际生效。
//
// 注：这是行为性测试，不直接访问 seen map，通过"Scan 能在合理内存下完成大量命中"
// 来间接验证。
func TestCarver_SeenMapDoesNotExplode(t *testing.T) {
	png := buildMinimalPNG()

	chunkSize := int64(1 * 1024 * 1024) // 1MB chunk 让命中更密集
	totalChunks := int64(20)
	disk := make([]byte, chunkSize*totalChunks)

	// 每 4KB 埋一个 PNG，模拟高密度命中场景
	step := int64(4096)
	planted := 0
	for off := int64(0); off+int64(len(png)) <= int64(len(disk)); off += step {
		copy(disk[off:], png)
		planted++
	}

	reader := testutil.NewMemReader(disk)
	cfg := Config{
		ChunkSize:   chunkSize,
		Workers:     2,
		MaxFileSize: chunkSize * totalChunks,
	}
	engine := NewEngine(reader, signature.NewSignatureDB(), cfg)

	// 仅验证扫描能完成、不卡住、产出数量合理（不应为 0，也不应远超埋入数）
	foundCount := 0
	err := engine.Scan(context.Background(), 0, int64(len(disk)), nil,
		func(f *types.RecoveredFile) { foundCount++ },
	)
	if err != nil {
		t.Fatalf("Scan 失败: %v", err)
	}

	if foundCount == 0 {
		t.Fatalf("埋入 %d 个 PNG，一个都没找到——去重/裁剪可能误删所有条目", planted)
	}
	// 不要求精确匹配 planted，只要数量级合理即可（去重可能因 chunk overlap 有少量波动）
	if foundCount > planted*2 {
		t.Errorf("找到数 %d 远超埋入数 %d，可能裁剪过早导致重复", foundCount, planted)
	}
}
