package vss

import (
	"testing"
)

// 真实 Windows 10 英文系统的 vssadmin 输出样例（去敏化）
const sampleEnglishOutput = `
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {11111111-2222-3333-4444-555555555555}
   Contained 1 shadow copies at creation time: 4/19/2026 10:00:00 AM
   Shadow Copy ID: {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}
      Original Volume: (C:)\\?\Volume{f1f2f3f4-0000-0000-0000-000000000000}\
      Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
      Originating Machine: DESKTOP-ORIG
      Service Machine: DESKTOP-ORIG
      Provider: 'Microsoft Software Shadow Copy provider 1.0'
      Type: ClientAccessibleWriters
      Attributes: Persistent, Client-accessible, No auto release, Differential, Auto recovered

Contents of shadow copy set ID: {66666666-7777-8888-9999-000000000000}
   Contained 1 shadow copies at creation time: 4/18/2026 08:30:00 AM
   Shadow Copy ID: {12121212-3434-5656-7878-909090909090}
      Original Volume: (C:)\\?\Volume{f1f2f3f4-0000-0000-0000-000000000000}\
      Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4
      Originating Machine: DESKTOP-ORIG
      Service Machine: DESKTOP-ORIG
`

func TestParseVssadminOutput_MultipleShadows(t *testing.T) {
	shadows := parseVssadminOutput(sampleEnglishOutput)
	if len(shadows) != 2 {
		t.Fatalf("应解析出 2 个快照，实际 %d", len(shadows))
	}
	s1 := shadows[0]
	if s1.ID != "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}" {
		t.Errorf("Shadow[0] ID 错: %s", s1.ID)
	}
	if s1.DevicePath != `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3` {
		t.Errorf("Shadow[0] DevicePath 错: %s", s1.DevicePath)
	}
	if s1.OriginalVolume == "" {
		t.Error("Shadow[0] OriginalVolume 不应为空")
	}
	if s1.OriginatingMachine != "DESKTOP-ORIG" {
		t.Errorf("Shadow[0] OriginatingMachine 错: %s", s1.OriginatingMachine)
	}
	if s1.CreatedAt.IsZero() {
		t.Error("Shadow[0] CreatedAt 应被解析出来")
	} else if s1.CreatedAt.Year() != 2026 {
		t.Errorf("Shadow[0] CreatedAt.Year 错: %d", s1.CreatedAt.Year())
	}

	s2 := shadows[1]
	if s2.DevicePath != `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4` {
		t.Errorf("Shadow[1] DevicePath 错: %s", s2.DevicePath)
	}
}

func TestParseVssadminOutput_NoShadows(t *testing.T) {
	emptyOutput := `
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool

No items found that satisfy the query.
`
	shadows := parseVssadminOutput(emptyOutput)
	if len(shadows) != 0 {
		t.Errorf("无快照时应返回空，实际 %d", len(shadows))
	}
}

func TestParseVssadminOutput_BlockMissingDeviceDropped(t *testing.T) {
	// 这个 block 有 ID 但没有 Shadow Copy Volume —— 应被丢弃（没法读就没用）
	broken := `
Contents of shadow copy set ID: {xxx}
   Shadow Copy ID: {aaa-bbb-ccc}
      Original Volume: (C:)\\?\Volume{yyy}\
      Originating Machine: ABC
`
	shadows := parseVssadminOutput(broken)
	if len(shadows) != 0 {
		t.Errorf("缺 DevicePath 应被丢弃，实际解析出 %d", len(shadows))
	}
}

func TestParseCreationTime_MultipleLayouts(t *testing.T) {
	cases := []struct {
		block string
		year  int
	}{
		{"Contained 1 shadow copies at creation time: 4/19/2026 10:00:00 AM", 2026},
		{"Contained 1 shadow copies at creation time: 2026/4/19 10:00:00", 2026},
		{"Contained 1 shadow copies at creation time: 2026-04-19 10:00:00", 2026},
	}
	for _, c := range cases {
		got := parseCreationTime(c.block)
		if got.Year() != c.year {
			t.Errorf("layout %q 解析错: got %v", c.block, got)
		}
	}
}

func TestParseCreationTime_UnknownFormatReturnsZero(t *testing.T) {
	got := parseCreationTime("at creation time: totally-not-a-date")
	if !got.IsZero() {
		t.Errorf("未知格式应返回零值，实际 %v", got)
	}
}

// 中文 Windows 系统的 vssadmin 输出
const sampleChineseOutput = `
vssadmin 1.1 - 卷影复制服务管理命令行工具
(C) 版权所有 2001-2013 Microsoft Corp.

卷影复制集 ID: {12345678-1234-1234-1234-123456789ABC} 的内容
   在创建时间: 2026/4/19 14:30:00 包含 1 个卷影副本
   卷影复制 ID: {ABCDEF12-3456-7890-ABCD-EF1234567890}
      原始卷: (C:)\\?\Volume{99999999-9999-9999-9999-999999999999}\
      卷影复制 卷: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7
      原始计算机: DESKTOP-CN
      服务计算机: DESKTOP-CN
      提供程序: 'Microsoft Software Shadow Copy provider 1.0'
      类型: ClientAccessibleWriters
      属性: 持久, 客户端可访问, 无自动释放, 差异, 自动恢复
`

func TestParseVssadminOutput_Chinese(t *testing.T) {
	shadows := parseVssadminOutput(sampleChineseOutput)
	if len(shadows) != 1 {
		t.Fatalf("中文输出应解析出 1 个快照，实际 %d", len(shadows))
	}
	s := shadows[0]
	if s.ID != "{ABCDEF12-3456-7890-ABCD-EF1234567890}" {
		t.Errorf("ID 错: %s", s.ID)
	}
	if s.DevicePath != `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7` {
		t.Errorf("DevicePath 错: %s", s.DevicePath)
	}
	if s.OriginatingMachine != "DESKTOP-CN" {
		t.Errorf("OriginatingMachine 错: %s", s.OriginatingMachine)
	}
}

// 多个 ShadowCopySet 共享同一 CreatedAt 行的边界场景。
// GUID 必须是合法 hex 字符（regex 限制），不能用 SHADOW1 这种占位串。
const sampleMultipleSets = `
Contents of shadow copy set ID: {11111111-1111-1111-1111-111111111111}
   Contained 2 shadow copies at creation time: 4/19/2026 10:00:00 AM
   Shadow Copy ID: {aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}
      Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
   Shadow Copy ID: {bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}
      Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

Contents of shadow copy set ID: {22222222-2222-2222-2222-222222222222}
   Contained 1 shadow copies at creation time: 4/20/2026 11:00:00 AM
   Shadow Copy ID: {cccccccc-cccc-cccc-cccc-cccccccccccc}
      Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
`

func TestParseVssadminOutput_MultipleSetsMultipleShadows(t *testing.T) {
	shadows := parseVssadminOutput(sampleMultipleSets)
	if len(shadows) != 3 {
		t.Fatalf("应解析出 3 个快照（来自 2 个 set），实际 %d", len(shadows))
	}
	devices := make(map[string]bool)
	for _, s := range shadows {
		devices[s.DevicePath] = true
	}
	if !devices[`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3`] {
		t.Error("第二个 set 的快照应被解析到")
	}
}

// Windows 11 实测输出（真实采集，去敏化）
const sampleWindows11Output = `
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}
   Contained 1 shadow copies at creation time: 12/25/2025 8:15:42 AM
   Shadow Copy ID: {CAFEBABE-CAFE-BABE-CAFE-BABECAFEBABE}
      Original Volume: (C:)\\?\Volume{0123abcd-0000-0000-0000-000000000000}\
      Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42
      Originating Machine: WIN11-SAMPLE
      Service Machine: WIN11-SAMPLE
      Provider: 'Microsoft Software Shadow Copy provider 1.0'
      Type: ClientAccessible
      Attributes: Persistent, Client-accessible, No auto release, No writers, Differential
`

func TestParseVssadminOutput_Windows11RealSample(t *testing.T) {
	shadows := parseVssadminOutput(sampleWindows11Output)
	if len(shadows) != 1 {
		t.Fatalf("Win11 真实样例应解析出 1 个，实际 %d", len(shadows))
	}
	s := shadows[0]
	if s.OriginatingMachine != "WIN11-SAMPLE" {
		t.Errorf("OriginatingMachine 错: %q", s.OriginatingMachine)
	}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt 应被解析")
	}
	if s.CreatedAt.Year() != 2025 || s.CreatedAt.Month() != 12 {
		t.Errorf("CreatedAt 错: %v", s.CreatedAt)
	}
}

// 极端：只有 Shadow Copy ID 头但其他字段全缺失
func TestParseVssadminOutput_OnlyHeaderNoFields(t *testing.T) {
	stub := `Shadow Copy ID: {AAAA-BBBB-CCCC}`
	shadows := parseVssadminOutput(stub)
	// 缺 DevicePath 应被丢弃
	if len(shadows) != 0 {
		t.Errorf("缺 DevicePath 应丢弃，实际 %d", len(shadows))
	}
}
