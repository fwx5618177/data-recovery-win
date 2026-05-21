package scanevent_test

import (
	"testing"

	"data-recovery/internal/scanevent"
	"data-recovery/internal/types"
)

// TestMergeScanProgress 锁住 v2.8.12 关键契约：dispatcher emit 新 ScanProgress 时
// 不应清掉 TotalBytes / FilesFound / Speed / BytesScanned 等累计字段。
//
// 失败 = 用户 UI 显示 "0 B / 0 B / 速度 0"（v2.8.11 之前的 bug）。
// v2.8.46 测试从 root（package main）搬到 tests/scanevent 子目录，
// 配合 mergeScanProgress 抽到 internal/scanevent 包。
func TestMergeScanProgress_PreservesTotalBytes(t *testing.T) {
	prev := types.ScanProgress{
		Phase:      "ntfs",
		Percent:    1.0,
		TotalBytes: 128 * 1024 * 1024 * 1024, // 128GB（用户场景）
	}
	incoming := types.ScanProgress{
		Phase:       "exfat",
		Percent:     2.0,
		CurrentFile: "正在查找 exFAT 分区...",
		// TotalBytes 故意 0 —— dispatcher emit 时常如此
	}
	merged := scanevent.MergeProgress(prev, incoming)
	if merged.TotalBytes != prev.TotalBytes {
		t.Errorf("TotalBytes 没保留：got %d, want %d", merged.TotalBytes, prev.TotalBytes)
	}
	if merged.Phase != "exfat" {
		t.Errorf("Phase 应用 incoming 值：got %s", merged.Phase)
	}
	if merged.CurrentFile != "正在查找 exFAT 分区..." {
		t.Errorf("CurrentFile 应用 incoming 值：got %s", merged.CurrentFile)
	}
}

func TestMergeScanProgress_PreservesAccumulated(t *testing.T) {
	prev := types.ScanProgress{
		Phase:        "carving",
		BytesScanned: 50 * 1024 * 1024,
		FilesFound:   100,
		Speed:        1024 * 1024, // 1MB/s
	}
	// dispatcher 偶尔 emit 一个只带 phase/percent 的更新（比如阶段切换）
	incoming := types.ScanProgress{
		Phase:   "validating",
		Percent: 96.0,
	}
	merged := scanevent.MergeProgress(prev, incoming)

	if merged.BytesScanned != prev.BytesScanned {
		t.Errorf("BytesScanned 没保留：got %d, want %d", merged.BytesScanned, prev.BytesScanned)
	}
	if merged.FilesFound != prev.FilesFound {
		t.Errorf("FilesFound 没保留：got %d, want %d", merged.FilesFound, prev.FilesFound)
	}
	if merged.Speed != prev.Speed {
		t.Errorf("Speed 没保留：got %d, want %d", merged.Speed, prev.Speed)
	}
}

func TestMergeScanProgress_IncomingNonZeroWins(t *testing.T) {
	prev := types.ScanProgress{
		TotalBytes:   100,
		BytesScanned: 50,
		FilesFound:   10,
		Speed:        1000,
	}
	// incoming 设置了非零值（比如 carver 真在工作）—— 应用 incoming
	incoming := types.ScanProgress{
		Phase:        "carving",
		TotalBytes:   200, // 不同
		BytesScanned: 75,
		FilesFound:   20,
		Speed:        2000,
	}
	merged := scanevent.MergeProgress(prev, incoming)

	if merged.TotalBytes != incoming.TotalBytes {
		t.Errorf("TotalBytes 应用 incoming：got %d", merged.TotalBytes)
	}
	if merged.BytesScanned != incoming.BytesScanned {
		t.Errorf("BytesScanned 应用 incoming：got %d", merged.BytesScanned)
	}
	if merged.FilesFound != incoming.FilesFound {
		t.Errorf("FilesFound 应用 incoming：got %d", merged.FilesFound)
	}
	if merged.Speed != incoming.Speed {
		t.Errorf("Speed 应用 incoming：got %d", merged.Speed)
	}
}
