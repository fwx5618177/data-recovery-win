package recovery

import (
	"sync"
	"testing"

	"data-recovery/internal/disk"
	"data-recovery/internal/types"
)

// 这一组测试守住 v2.8.12 引入的进度合并契约。
//
// 用户实测 v2.8.11 还是看到"已发现 114 / 0 B / 0 B / 速度 0 B/s"卡 12 小时。
// 根因：每个 FS dispatcher 创建新 ScanProgress 只设置自己关心的字段（Phase/Percent/
// CurrentFile），其他字段是 zero。app.go 的 `a.scanProgress = p` 是覆盖式赋值，
// 把已经从底层 reader 拿到的 TotalBytes 重置为 0，导致 UI 一直 "0 B / 0 B"。
// engine.go 启动时也没主动 emit 一个带 TotalBytes 的初始进度。
//
// v2.8.12 修复：
//   1. engine.go 扫描开始立刻 emit 一个 init 进度带 TotalBytes（disk size）
//   2. app.go OnProgress 用 mergeScanProgress 合并而不是覆盖，保留累计字段
//   3. exFAT/FAT 目录遍历期间 onFound 节流 emit progress 让 UI 看到活动

// TestScan_TotalBytes_PrefilledAtStart 锁住 v2.8.12 契约：扫描启动后**立刻**有
// 一个进度 emit 带正确的 TotalBytes（磁盘总字节数）。如果失败 = 用户会看到 "0 B / 0 B"。
func TestScan_TotalBytes_PrefilledAtStart(t *testing.T) {
	const imgSize = 8 * 1024 * 1024 // 8MB
	mock := &countingMock{data: make([]byte, imgSize)}
	reader := disk.NewResilientReader(mock, 512, 0)
	engine := NewEngine()

	var (
		mu              sync.Mutex
		firstTotalBytes int64 = -1 // -1 = 未设置
	)
	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			mu.Lock()
			defer mu.Unlock()
			if firstTotalBytes == -1 && p.TotalBytes > 0 {
				firstTotalBytes = p.TotalBytes
			}
		},
	}
	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, callbacks)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if firstTotalBytes != imgSize {
		t.Errorf("第一次带 TotalBytes 的进度应为磁盘大小 %d，实际 %d —— UI 会显示 \"0 B / 0 B\"",
			imgSize, firstTotalBytes)
	}
}

// TestMergeScanProgress_PreservesAccumulatedFields 锁住 mergeScanProgress 行为：
// dispatcher emit 不带 TotalBytes 时，前一帧的 TotalBytes 必须保留。
// 这条 fail = TotalBytes 被重置为 0，前端显示退化。
//
// 注意：mergeScanProgress 在 app.go 包，从这里测不到。改为对 mergeScanProgress 的语义
// 做契约测试 —— 通过一个集成测试模拟 dispatcher emit 序列。
func TestScan_TotalBytes_PreservedAcrossPhases(t *testing.T) {
	const imgSize = 8 * 1024 * 1024
	mock := &countingMock{data: make([]byte, imgSize)}
	reader := disk.NewResilientReader(mock, 512, 0)
	engine := NewEngine()

	var (
		mu                  sync.Mutex
		emitsWithTotalBytes int
		emitsWithZeroTotal  int
		totalEmits          int
	)

	// 我们模拟 app.go 的合并逻辑测试 dispatcher 出来的 emit 是否合理。
	prev := types.ScanProgress{}
	mergedHasTotal := func(p types.ScanProgress) bool {
		// 合并：incoming 0 时保留 prev
		if p.TotalBytes == 0 && prev.TotalBytes > 0 {
			p.TotalBytes = prev.TotalBytes
		}
		prev = p
		return p.TotalBytes > 0
	}

	callbacks := ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			mu.Lock()
			defer mu.Unlock()
			totalEmits++
			if p.TotalBytes > 0 {
				emitsWithTotalBytes++
			} else {
				emitsWithZeroTotal++
			}
			if !mergedHasTotal(p) {
				t.Errorf("合并后 TotalBytes 仍为 0（emit #%d, phase=%s）—— mergeScanProgress 没保留", totalEmits, p.Phase)
			}
		},
	}
	_, err := engine.ScanWithReaderOptions(reader, types.ScanOptions{Mode: types.ScanFull}, callbacks)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if totalEmits == 0 {
		t.Fatal("没有 emit 任何 progress")
	}
	t.Logf("emits with TotalBytes=%d, zero=%d, total=%d", emitsWithTotalBytes, emitsWithZeroTotal, totalEmits)
}
