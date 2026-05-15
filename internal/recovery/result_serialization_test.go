package recovery

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestRecoveryResult_JSONShape 锁住 recovery:completed 事件 payload 的契约。
//
// v2.8.28 修复"恢复完成统计全 0、文件列表空"的 bug 根因之一：
// 前端用 `if (norm.records) ...` 检查记录是否存在 ——
//   - records=null（Go 里 nil slice）→ JS null → falsy → 走 GetLastRecoveryRecords 回退 ✓
//   - records=[]（Go 空 slice 但 non-nil）→ JS [] → **truthy** → 不回退、不取记录 ✗
//   - records=[{state:"success",...}] → 正常显示 ✓
//
// 本测试锁字段名 + 嵌套结构，保证：
//   - 顶层字段全部 lowerCamelCase（success/lowConfidence/partial/failed/records）
//   - records 数组里每个对象的 state 字段是字符串 "success"/"failed" 等
//   - 包含 1 条 success 记录时，records.length=1 + state=="success"
//
// 任何后续把字段名改大写、把 state 改成 enum int、或把 records 序列化丢掉的改动，
// 这个测试立刻 fail。
func TestRecoveryResult_JSONShape(t *testing.T) {
	res := &RecoveryResult{
		Succeeded:     1,
		LowConfidence: 0,
		Partial:       0,
		Failed:        0,
		Skipped:       0,
		Duplicates:    0,
		Total:         1,
		Records: []*FileRecoveryRecord{
			{
				FileID:      "carve_0x12345",
				FileName:    "photo_0x12345_000001.jpg",
				Category:    "image",
				Size:        1234567,
				SizeHuman:   "1.2 MB",
				State:       RecoveryStateSuccess,
				OutputPath:  `C:\recovered\photo.jpg`,
				DurationMs:  42,
				CompletedAt: time.Now(),
			},
		},
	}

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// 顶层字段名必须是 lowerCamelCase（Wails 默认序列化按 json tag 走）
	mustContain := []string{
		`"success":1`,
		`"lowConfidence":0`,
		`"partial":0`,
		`"failed":0`,
		`"skipped":0`,
		`"total":1`,
		`"records":[`,
	}
	for _, frag := range mustContain {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("JSON 缺字段或值不对，期望含 %q，实际：%s", frag, raw)
		}
	}

	// 反序列化回结构体，确认 round-trip 干净
	var back map[string]interface{}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	records, ok := back["records"].([]interface{})
	if !ok {
		t.Fatalf("records 不是数组：%T %v", back["records"], back["records"])
	}
	if len(records) != 1 {
		t.Fatalf("records 长度应该是 1，实际 %d", len(records))
	}

	rec, ok := records[0].(map[string]interface{})
	if !ok {
		t.Fatalf("records[0] 不是 object：%T", records[0])
	}
	if rec["state"] != "success" {
		t.Errorf("records[0].state 应该是 \"success\"，实际 %v", rec["state"])
	}
	if rec["fileName"] != "photo_0x12345_000001.jpg" {
		t.Errorf("records[0].fileName 不对：%v", rec["fileName"])
	}
}

// TestRecoveryResult_EmptyRecordsStillSerializesAsArray 锁住"空记录序列化"行为：
// 当 records 是 nil slice 或空 slice，JSON 中应该出现 records 字段（前端检查时
// 能 ?? 兜底），而不是消失或变成 undefined。
//
// 之前前端代码 `if (norm.records) ...` 把空数组当真，导致不去回退取记录。
// v2.8.28 前端改成 `if (norm.records && norm.records.length > 0)`，再加这个
// 测试在 backend 侧锁结构，让两端都稳。
func TestRecoveryResult_EmptyRecordsStillSerializesAsArray(t *testing.T) {
	// nil slice
	res1 := &RecoveryResult{Total: 0, Records: nil}
	raw1, _ := json.Marshal(res1)
	// nil slice 序列化为 null（Go 默认），这是前端 falsy 检查的正确触发点
	if !strings.Contains(string(raw1), `"records":null`) {
		t.Errorf("nil records 应序列化为 null，实际：%s", raw1)
	}

	// 空 slice
	res2 := &RecoveryResult{Total: 0, Records: []*FileRecoveryRecord{}}
	raw2, _ := json.Marshal(res2)
	// 空 slice 序列化为 [] —— 前端必须用 length > 0 检查
	if !strings.Contains(string(raw2), `"records":[]`) {
		t.Errorf("空 records 应序列化为 []，实际：%s", raw2)
	}
}
