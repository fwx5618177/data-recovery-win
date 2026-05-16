package parallel

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"data-recovery/internal/types"
)

// TestDiskJob_WireFormat_CamelCase 锁住 DiskJob 作为 Wails event payload 时
// 的 JSON 字段必须是 camelCase。
//
// 历史 bug（v2.8.38 修）：
// 前端 MultiDiskScanModal 里的 TS 接口写成 PascalCase（{ DrivePath, Mode }），
// 而 Go 侧 DiskJob 加了 `json:"drivePath"` / `json:"mode"`，导致 EventsEmit
// 序列化后前端读 j.DrivePath = undefined，再用 [undefined] 当 key 造出
// 「undefined / undefined」幽灵行。
//
// v2.8.34 的反射契约测试只验证了 "tag 是否存在"，没验证 "tag 实际值是否 camelCase"
// 也没验证序列化后的 wire 格式。这个测试补上这个缺口。
//
// 任何把 tag 改成 PascalCase / 去掉 tag / 加 omitempty 影响必填字段的改动都会
// 让这个测试报警。
func TestDiskJob_WireFormat_CamelCase(t *testing.T) {
	j := DiskJob{
		DrivePath: "\\\\.\\PhysicalDrive0",
		Mode:      types.ScanMode("auto"),
	}
	b, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("marshal DiskJob: %v", err)
	}
	wire := string(b)

	// 必须有 camelCase 字段
	for _, want := range []string{`"drivePath"`, `"mode"`} {
		if !strings.Contains(wire, want) {
			t.Errorf("DiskJob wire 缺 %s: %s", want, wire)
		}
	}
	// 不能有 PascalCase 字段（说明 tag 被删 / 写错）
	for _, bad := range []string{`"DrivePath"`, `"Mode"`} {
		if strings.Contains(wire, bad) {
			t.Errorf("DiskJob wire 出现 PascalCase 字段 %s（前端会读不到）: %s", bad, wire)
		}
	}

	// 反序列化也要 round-trip 成功（前端发回 backend 时走的也是 JSON）
	var got DiskJob
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal DiskJob: %v", err)
	}
	if got.DrivePath != j.DrivePath {
		t.Errorf("round-trip DrivePath: 期望 %q 得到 %q", j.DrivePath, got.DrivePath)
	}
	if got.Mode != j.Mode {
		t.Errorf("round-trip Mode: 期望 %q 得到 %q", j.Mode, got.Mode)
	}
}

// TestDiskJob_AcceptsPascalCaseInput Go 的 encoding/json 默认 case-insensitive，
// 前端发 PascalCase 也能 bind。这是个 "前向兼容" 测试 —— 老前端 / 第三方调用方
// 还发 PascalCase 不能让 backend 直接报错。
func TestDiskJob_AcceptsPascalCaseInput(t *testing.T) {
	in := `{"DrivePath":"\\\\.\\D:","Mode":"deep"}`
	var got DiskJob
	if err := json.Unmarshal([]byte(in), &got); err != nil {
		t.Fatalf("PascalCase 输入 unmarshal 失败（破坏向后兼容）: %v", err)
	}
	if got.DrivePath != `\\.\D:` || got.Mode != "deep" {
		t.Errorf("PascalCase 输入未正确 bind: %+v", got)
	}
}

// TestJobResult_WireFormat_CamelCase 同上，锁住 JobResult。
//
// 注意 Err 字段是 `json:"-"`（error 接口不可直接序列化），上层 emit 时必须显式
// 把它转成 "error" 字符串（见 app.go:2696 的 payload）。
func TestJobResult_WireFormat_CamelCase(t *testing.T) {
	res := JobResult{
		DrivePath: "\\\\.\\PhysicalDrive0",
		Result: &types.ScanResult{
			Duration:     1.5,
			TotalScanned: 1024,
			Stats:        map[string]int{"image": 10},
		},
		Err: errors.New("不该被序列化"),
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal JobResult: %v", err)
	}
	wire := string(b)

	for _, want := range []string{`"drivePath"`, `"result"`} {
		if !strings.Contains(wire, want) {
			t.Errorf("JobResult wire 缺 %s: %s", want, wire)
		}
	}
	for _, bad := range []string{`"DrivePath"`, `"Result"`, `"Err"`, `"err"`, "不该被序列化"} {
		if strings.Contains(wire, bad) {
			t.Errorf("JobResult wire 不该出现 %q: %s", bad, wire)
		}
	}
}
