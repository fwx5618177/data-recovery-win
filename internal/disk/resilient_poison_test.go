package disk

import (
	"testing"
	"time"
)

// TestResilientReader_PoisonCacheSkipsRetry v2.8.44 核心契约：
// 第二次读同一坏扇区不再 retry + sleep，直接 0 填充。
//
// 用户场景：carver collector 对每个文件 detect + classify 反复读头部区域。
// 头部如果在坏扇区，每次都 retry 50ms × maxRetry → 100-200ms / 文件浪费。
// 1000 文件 = 100-200 秒。poison cache 让首次失败后所有后续读秒退（< 1ms）。
func TestResilientReader_PoisonCacheSkipsRetry(t *testing.T) {
	// 4KB 盘，扇区 1 (offset 512..1024) 永远坏
	disk := make([]byte, 4096)
	for i := range disk {
		disk[i] = byte(i)
	}
	mock := &unstableMock{
		data:      disk,
		badRanges: [][2]int64{{512, 1024}},
	}
	// maxRetry=3 让"如果没 cache，每次会重试 3 次"明显可见
	r := NewResilientReader(mock, 512, 3)

	// 第 1 次读坏扇区 —— 应有重试 + sleep
	buf := make([]byte, 512)
	start := time.Now()
	_, _ = r.ReadAt(buf, 512)
	firstReadTime := time.Since(start)

	if !r.isPoisoned(512) {
		t.Fatalf("第 1 次读失败后扇区 512 应已 poisoned")
	}

	// 第 2 次读同一坏扇区 —— 应秒退（< 1ms）
	start = time.Now()
	n, err := r.ReadAt(buf, 512)
	secondReadTime := time.Since(start)

	if err != nil {
		t.Errorf("poisoned 读不该返错（应 0 填充返 nil）: %v", err)
	}
	if n != 512 {
		t.Errorf("poisoned 读应返 512 字节（0 填充）: %d", n)
	}
	for i, b := range buf {
		if b != 0 {
			t.Errorf("poisoned 读应全 0 填充，buf[%d]=%d", i, b)
			break
		}
	}

	if secondReadTime > firstReadTime/3 {
		t.Errorf("poison cache 没生效：第 2 次 %v 接近第 1 次 %v（应 <1/3）",
			secondReadTime, firstReadTime)
	}
	t.Logf("第 1 次读 %v / 第 2 次读 %v (≥ %.0f× 加速)", firstReadTime, secondReadTime,
		float64(firstReadTime)/float64(secondReadTime+1))
}

// TestResilientReader_PoisonCacheSavesUnderlyingReads 验证底层 ReadAt 次数：
// 第 1 次 = maxRetry 次重试；第 N 次 = 0 次（全走 poison cache）。
func TestResilientReader_PoisonCacheSavesUnderlyingReads(t *testing.T) {
	disk := make([]byte, 4096)
	mock := &unstableMock{
		data:      disk,
		badRanges: [][2]int64{{1024, 1536}}, // 扇区 2 坏
	}
	r := NewResilientReader(mock, 512, 3) // maxRetry=3

	buf := make([]byte, 512)
	// 第 1 次：1 次失败 + 1 次进 retry 路径 = 3 次（每次 retry 调底层）
	mock.readCount.Store(0)
	_, _ = r.ReadAt(buf, 1024)
	firstCount := mock.readCount.Load()
	if firstCount < 2 {
		t.Errorf("第 1 次读应至少调底层 2 次（首读 + 1 次 retry），实得 %d", firstCount)
	}

	// 第 2 次：poison cache 命中 → 0 次底层调用
	mock.readCount.Store(0)
	_, _ = r.ReadAt(buf, 1024)
	secondCount := mock.readCount.Load()
	if secondCount != 0 {
		t.Errorf("poison cache 命中后底层调用应为 0，实得 %d", secondCount)
	}
}

// TestResilientReader_PoisonOnlyMarksFailedSectors 健康扇区不能误进 poison cache。
func TestResilientReader_PoisonOnlyMarksFailedSectors(t *testing.T) {
	disk := make([]byte, 4096)
	for i := range disk {
		disk[i] = byte(i)
	}
	mock := &unstableMock{
		data:      disk,
		badRanges: [][2]int64{{1024, 1536}}, // 扇区 2 坏
	}
	r := NewResilientReader(mock, 512, 1)

	buf := make([]byte, 4096)
	_, _ = r.ReadAt(buf, 0)

	// 扇区 0, 1, 3, 4, 5, 6, 7 健康，不该 poisoned
	for _, off := range []int64{0, 512, 1536, 2048, 2560, 3072, 3584} {
		if r.isPoisoned(off) {
			t.Errorf("健康扇区 %d 不该被 poisoned", off)
		}
	}
	// 扇区 2 (offset 1024) 该 poisoned
	if !r.isPoisoned(1024) {
		t.Errorf("坏扇区 1024 该 poisoned")
	}
}

// TestResilientReader_MarkPoisonedAlignsToSector 给个非对齐 offset，markPoisoned
// 必须把覆盖到的所有 sector 都标记（向下对齐到 sector 边界，上取整到 end）。
func TestResilientReader_MarkPoisonedAlignsToSector(t *testing.T) {
	r := &ResilientReader{sectorSize: 512, poisonCache: make(map[int64]bool)}
	// 标 [300, 1500) —— 跨扇区 0 (0..512), 1 (512..1024), 2 (1024..1536)
	r.markPoisoned(300, 1200)
	for _, expected := range []int64{0, 512, 1024} {
		if !r.poisonCache[expected] {
			t.Errorf("扇区 %d 该被标记 poisoned", expected)
		}
	}
	if r.poisonCache[1536] {
		t.Errorf("扇区 1536 不该被标记（范围 < 1500）")
	}
}
