// Package dtocontract_test 锁住 internal/* 包里 IPC DTO 的 JSON 字段名契约。
//
// 多次 bug 重演的模式：Go struct 写裸字段（PascalCase），Wails / json.Marshal 序列化
// 后字段名是 PascalCase，但前端 TS 代码读 camelCase → 全 undefined → UI 显示
// "undefined-undefined" / "0 盘" / "0 个 snapshot" 之类。
//
// 历史已知踩坑：
//   - SEDStatus (v2.8.3 修)
//   - SmartHealth (修过)
//   - gpt.Partition (v2.8.33 改 DTO 修)
//   - volmgr.DetectedArray (v2.8.33 加 tag)
//   - apfs.Snapshot (v2.8.33 加 tag)
//
// v2.8.46 把测试从 root 的 package main 搬到 tests/dtocontract，配合 GPT
// helpers 已抽到 internal/gpt。少数 main-package 私有 DTO（EncryptedVolumeInfo
// 等）的字段名契约由 root 下的 app_dto_contract_test.go 单独覆盖（那些 DTO
// 没法 import 到外部包，必须留 root）。
package dtocontract_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"data-recovery/internal/apfs"
	"data-recovery/internal/disk"
	"data-recovery/internal/forensics"
	"data-recovery/internal/gpt"
	"data-recovery/internal/netfs"
	"data-recovery/internal/parallel"
	"data-recovery/internal/recovery"
	"data-recovery/internal/session"
	"data-recovery/internal/types"
	"data-recovery/internal/updater"
	"data-recovery/internal/volmgr"
)

// TestVolmgrDetectedArray_JSONKeysAreCamelCase 锁住 DetectedArray 序列化字段名
func TestVolmgrDetectedArray_JSONKeysAreCamelCase(t *testing.T) {
	arr := volmgr.DetectedArray{
		UUID:         "aaa-bbb",
		Name:         "myraid",
		Level:        "raid5",
		ChunkBytes:   65536,
		RaidDisks:    4,
		OrderedPaths: []string{"/dev/sda", "/dev/sdb", "", "/dev/sdd"},
		DataOffset:   2048,
		Members: []volmgr.DetectedMember{
			{Path: "/dev/sda", Role: 0, DevUUID: "u1"},
		},
	}
	raw, err := json.Marshal(arr)
	if err != nil {
		t.Fatal(err)
	}
	requiredKeys := []string{
		`"uuid":`, `"level":`, `"chunkBytes":`, `"raidDisks":`,
		`"orderedPaths":`, `"dataOffset":`, `"members":`,
	}
	for _, k := range requiredKeys {
		if !strings.Contains(string(raw), k) {
			t.Errorf("缺 camelCase 字段 %s，实际 JSON：%s", k, raw)
		}
	}
	forbidden := []string{`"UUID":`, `"Level":`, `"ChunkBytes":`, `"RaidDisks":`}
	for _, k := range forbidden {
		if strings.Contains(string(raw), k) {
			t.Errorf("回归到 PascalCase！发现 %s，前端会读不到。JSON: %s", k, raw)
		}
	}
	if !strings.Contains(string(raw), `"path":"/dev/sda"`) {
		t.Errorf("DetectedMember.path 字段缺失或大小写不对: %s", raw)
	}
}

func TestNetFSMountAdvice_JSONTags(t *testing.T) {
	a := netfs.MountAdvice{Method: "macOS Finder", OS: "darwin", Steps: []string{"step1"}}
	raw, _ := json.Marshal(a)
	for _, k := range []string{`"method":"macOS Finder"`, `"os":"darwin"`, `"steps":[`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("MountAdvice 缺字段 %s: %s", k, raw)
		}
	}
}

func TestDiskBadSector_JSONTags(t *testing.T) {
	bs := disk.BadSector{Offset: 1024, Size: 512, Err: "read fail"}
	raw, _ := json.Marshal(bs)
	for _, k := range []string{`"offset":1024`, `"size":512`, `"err":"read fail"`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("BadSector 缺字段 %s: %s", k, raw)
		}
	}
}

func TestParallelDiskJobAndJobResult_JSONTags(t *testing.T) {
	j := parallel.DiskJob{DrivePath: "/dev/sda", Mode: "deep"}
	raw, _ := json.Marshal(j)
	if !strings.Contains(string(raw), `"drivePath":"/dev/sda"`) || !strings.Contains(string(raw), `"mode":"deep"`) {
		t.Errorf("DiskJob 字段不对: %s", raw)
	}
	r := parallel.JobResult{DrivePath: "/dev/sdb", Result: nil}
	raw2, _ := json.Marshal(r)
	if !strings.Contains(string(raw2), `"drivePath":"/dev/sdb"`) {
		t.Errorf("JobResult.drivePath 字段不对: %s", raw2)
	}
	if strings.Contains(string(raw2), `"Err"`) || strings.Contains(string(raw2), `"err"`) {
		t.Errorf("JobResult.Err 应该被 json:\"-\" 排除：%s", raw2)
	}
}

func TestDiskImageProgress_JSONTags(t *testing.T) {
	p := disk.ImageProgress{BytesTotal: 1 << 30, BytesRead: 1 << 28, BytesOK: 1 << 28, Speed: 100 * 1024 * 1024}
	raw, _ := json.Marshal(p)
	for _, k := range []string{`"bytesTotal":`, `"bytesRead":`, `"bytesOK":`, `"speed":`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("ImageProgress 缺字段 %s: %s", k, raw)
		}
	}
}

func TestAPFSSnapshot_JSONKeysAreCamelCase(t *testing.T) {
	s := apfs.Snapshot{
		XID:        12345,
		CreateTime: 1700000000,
		ChangeTime: 1700000001,
		Name:       "com.apple.TimeMachine.snap1",
		InodeNum:   42,
		Flags:      1,
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	requiredKeys := []string{
		`"xid":`, `"createTime":`, `"changeTime":`, `"name":`, `"inodeNum":`, `"flags":`,
	}
	for _, k := range requiredKeys {
		if !strings.Contains(string(raw), k) {
			t.Errorf("缺字段 %s：%s", k, raw)
		}
	}
	if strings.Contains(string(raw), `"XID":`) || strings.Contains(string(raw), `"CreateTime":`) {
		t.Errorf("回归到 PascalCase: %s", raw)
	}
}

// TestGPTPartitionInfo_JSONKeysAndDecoding 锁住 v2.8.33 加的 DTO 字段。
// v2.8.46 从 main 搬到 internal/gpt 后用 gpt.PartitionInfo。
func TestGPTPartitionInfo_JSONKeysAndDecoding(t *testing.T) {
	info := gpt.PartitionInfo{
		Index:     1,
		Name:      "Microsoft Data",
		TypeGUID:  "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
		TypeName:  "Microsoft Basic Data (NTFS / FAT32 / exFAT)",
		FirstLBA:  2048,
		LastLBA:   1000000,
		SizeBytes: 999998 * 512,
		SizeHuman: "488.3 MB",
	}
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		`"index":1`,
		`"name":"Microsoft Data"`,
		`"typeGUID":"EBD0A0A2-`,
		`"typeName":"Microsoft Basic`,
		`"firstLBA":2048`,
		`"lastLBA":1000000`,
		`"sizeBytes":`,
		`"sizeHuman":"488.3 MB"`,
	} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("缺字段 %s：%s", k, raw)
		}
	}
}

// TestFormatGPTGUID_StandardLayout 验证 GUID 字节序转换（mixed-endian）正确。
func TestFormatGPTGUID_StandardLayout(t *testing.T) {
	// Microsoft Basic Data Partition GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
	bytes := [16]byte{
		0xA2, 0xA0, 0xD0, 0xEB, // EBD0A0A2 (LE)
		0xE5, 0xB9, // B9E5 (LE)
		0x33, 0x44, // 4433 (LE)
		0x87, 0xC0, // 87C0 (BE)
		0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7, // 68B6B72699C7 (BE)
	}
	got := gpt.FormatGUID(bytes)
	want := "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
	if got != want {
		t.Errorf("FormatGUID: got %q, want %q", got, want)
	}
}

// TestInternalIPCStructsHaveJSONTags 反射检查 internal/* 包里所有 IPC DTO
// 必须给每个**导出**字段写 json tag。
//
// main-package DTO（EncryptedVolumeInfo 等 14 个）的同类断言在 root 下
// app_dto_contract_test.go —— 那些类型无法 import 出 package main。
func TestInternalIPCStructsHaveJSONTags(t *testing.T) {
	type sample struct {
		name string
		val  interface{}
	}
	samples := []sample{
		{"gpt.PartitionInfo", gpt.PartitionInfo{}},
		{"types.DriveInfo", types.DriveInfo{}},
		{"types.RecoveredFile", types.RecoveredFile{}},
		{"types.ScanProgress", types.ScanProgress{}},
		{"types.RecoveryProgress", types.RecoveryProgress{}},
		{"types.ScanResult", types.ScanResult{}},
		{"types.FileSignature", types.FileSignature{}},
		{"types.ScanOptions", types.ScanOptions{}},
		{"recovery.FileRecoveryRecord", recovery.FileRecoveryRecord{}},
		{"recovery.RecoveryResult", recovery.RecoveryResult{}},
		{"recovery.SMBScanRequest", recovery.SMBScanRequest{}},
		{"recovery.NFSScanRequest", recovery.NFSScanRequest{}},
		{"recovery.IOSBackupInfo", recovery.IOSBackupInfo{}},
		{"recovery.AndroidBackupInfo", recovery.AndroidBackupInfo{}},
		{"recovery.ManifestEntry", recovery.ManifestEntry{}},
		{"recovery.Manifest", recovery.Manifest{}},
		{"recovery.ManifestSummary", recovery.ManifestSummary{}},
		{"forensics.TimelineEvent", forensics.TimelineEvent{}},
		{"forensics.Custody", forensics.Custody{}},
		{"forensics.CustodyFile", forensics.CustodyFile{}},
		{"session.Snapshot", session.Snapshot{}},
		{"updater.CheckResult", updater.CheckResult{}},
		{"updater.Asset", updater.Asset{}},
		{"updater.Pending", updater.Pending{}},
		{"apfs.Snapshot", apfs.Snapshot{}},
		{"disk.BadSector", disk.BadSector{}},
		{"disk.ImageProgress", disk.ImageProgress{}},
		{"disk.FreeSpace", disk.FreeSpace{}},
		{"disk.CacheStats", disk.CacheStats{}},
		{"netfs.MountAdvice", netfs.MountAdvice{}},
		{"parallel.DiskJob", parallel.DiskJob{}},
		{"parallel.JobResult", parallel.JobResult{}},
		{"volmgr.DetectedArray", volmgr.DetectedArray{}},
		{"volmgr.DetectedMember", volmgr.DetectedMember{}},
	}

	for _, s := range samples {
		typ := reflect.TypeOf(s.val)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			tag, ok := f.Tag.Lookup("json")
			if !ok {
				t.Errorf("%s.%s 缺 json tag —— 前端会读到 undefined。\n"+
					"  Go field %q → JS expected %q\n"+
					"  请给字段加合适的 `json:\"camelCaseName\"` tag",
					s.name, f.Name, f.Name, strings.ToLower(string(f.Name[0]))+f.Name[1:])
				continue
			}
			tagName := strings.SplitN(tag, ",", 2)[0]
			if tagName == "" || tagName == "-" {
				continue
			}
			if tagName[0] >= 'A' && tagName[0] <= 'Z' {
				t.Errorf("%s.%s 的 json tag 是 PascalCase %q —— 前端约定 camelCase",
					s.name, f.Name, tagName)
			}
		}
	}
}

func TestGPTTypeNameByGUID_KnownPartitions(t *testing.T) {
	cases := map[string]string{
		"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
		"C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition",
		"7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
		"0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Filesystem",
		"00000000-0000-0000-0000-000000000000": "(空槽)",
		"12345678-AAAA-BBBB-CCCC-DDDDEEEEFFFF": "(未知类型 GUID)", // 真未知 → fallback
	}
	for guid, wantSub := range cases {
		got := gpt.TypeNameByGUID(guid)
		if !strings.Contains(got, wantSub) {
			t.Errorf("TypeNameByGUID(%q) = %q, 应含 %q", guid, got, wantSub)
		}
	}
}
