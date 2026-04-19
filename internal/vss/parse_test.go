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
