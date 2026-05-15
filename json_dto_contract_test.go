package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"data-recovery/internal/apfs"
	"data-recovery/internal/disk"
	"data-recovery/internal/forensics"
	"data-recovery/internal/netfs"
	"data-recovery/internal/parallel"
	"data-recovery/internal/recovery"
	"data-recovery/internal/session"
	"data-recovery/internal/types"
	"data-recovery/internal/updater"
	"data-recovery/internal/volmgr"
)

// 这个文件锁住"Go IPC 返回结构体的 JSON 字段名"契约。
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
// 本测试用反序列化 + map 检查字段名是 camelCase，防止再有人加裸字段忘了 json tag。

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
		`"uuid":`,
		`"level":`,
		`"chunkBytes":`,
		`"raidDisks":`,
		`"orderedPaths":`,
		`"dataOffset":`,
		`"members":`,
	}
	for _, k := range requiredKeys {
		if !strings.Contains(string(raw), k) {
			t.Errorf("缺 camelCase 字段 %s，实际 JSON：%s", k, raw)
		}
	}
	// 反向：不能含 PascalCase 字段（=没加 tag 的回归信号）
	forbidden := []string{`"UUID":`, `"Level":`, `"ChunkBytes":`, `"RaidDisks":`}
	for _, k := range forbidden {
		if strings.Contains(string(raw), k) {
			t.Errorf("回归到 PascalCase！发现 %s，前端会读不到。JSON: %s", k, raw)
		}
	}

	// 嵌套 DetectedMember 也得 camelCase
	if !strings.Contains(string(raw), `"path":"/dev/sda"`) {
		t.Errorf("DetectedMember.path 字段缺失或大小写不对: %s", raw)
	}
}

// TestNetFSMountAdvice_JSONTags v2.8.34 修复
func TestNetFSMountAdvice_JSONTags(t *testing.T) {
	a := netfs.MountAdvice{Method: "macOS Finder", OS: "darwin", Steps: []string{"step1"}}
	raw, _ := json.Marshal(a)
	for _, k := range []string{`"method":"macOS Finder"`, `"os":"darwin"`, `"steps":[`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("MountAdvice 缺字段 %s: %s", k, raw)
		}
	}
}

// TestDiskBadSector_JSONTags v2.8.34 修复
func TestDiskBadSector_JSONTags(t *testing.T) {
	bs := disk.BadSector{Offset: 1024, Size: 512, Err: "read fail"}
	raw, _ := json.Marshal(bs)
	for _, k := range []string{`"offset":1024`, `"size":512`, `"err":"read fail"`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("BadSector 缺字段 %s: %s", k, raw)
		}
	}
}

// TestParallelDiskJobAndJobResult_JSONTags v2.8.34 修复
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
	// JobResult.Err 是 error 接口，标 json:"-" 不应该出现在输出里
	if strings.Contains(string(raw2), `"Err"`) || strings.Contains(string(raw2), `"err"`) {
		t.Errorf("JobResult.Err 应该被 json:\"-\" 排除：%s", raw2)
	}
}

// TestDiskImageProgress_JSONTags v2.8.34 修复
func TestDiskImageProgress_JSONTags(t *testing.T) {
	p := disk.ImageProgress{BytesTotal: 1 << 30, BytesRead: 1 << 28, BytesOK: 1 << 28, Speed: 100 * 1024 * 1024}
	raw, _ := json.Marshal(p)
	for _, k := range []string{`"bytesTotal":`, `"bytesRead":`, `"bytesOK":`, `"speed":`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("ImageProgress 缺字段 %s: %s", k, raw)
		}
	}
}

// TestAPFSSnapshot_JSONKeysAreCamelCase 锁住 apfs.Snapshot 字段名
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
		`"xid":`,
		`"createTime":`,
		`"changeTime":`,
		`"name":`,
		`"inodeNum":`,
		`"flags":`,
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
// 之前直接返回 gpt.Partition struct 没 JSON tag，前端 undefined-undefined。
func TestGPTPartitionInfo_JSONKeysAndDecoding(t *testing.T) {
	info := GPTPartitionInfo{
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
	// 前端用的字段名必须全在
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
	// 在 GPT 磁盘上的字节序（前 3 段 little-endian，后 2 段 big-endian）:
	bytes := [16]byte{
		0xA2, 0xA0, 0xD0, 0xEB, // EBD0A0A2 (LE)
		0xE5, 0xB9, // B9E5 (LE)
		0x33, 0x44, // 4433 (LE)
		0x87, 0xC0, // 87C0 (BE)
		0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7, // 68B6B72699C7 (BE)
	}
	got := formatGPTGUID(bytes)
	want := "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
	if got != want {
		t.Errorf("formatGPTGUID: got %q, want %q", got, want)
	}
}

// TestIPCStructsHaveJSONTags 反射检查"返回给前端的所有结构体"必须给每个**导出**
// 字段写 json tag。
//
// 历史教训：连着 3 版才发现 gpt.Partition / DetectedArray / Snapshot 字段名
// PascalCase 被前端读 undefined。本测试枚举每个 IPC 关键 struct，反射拿字段，
// 任何导出字段没 json tag → fail。
//
// 不能覆盖所有 struct（Go 内部 struct 不该都加 tag），所以维护一份 IPC 名单。
// 新加 IPC struct 时在这里加一行（一次性 cost, 永久防御）。
func TestIPCStructsHaveJSONTags(t *testing.T) {
	type sample struct {
		name string
		val  interface{}
	}
	samples := []sample{
		// === app.go 顶层 IPC DTO ===
		{"GPTPartitionInfo", GPTPartitionInfo{}},
		{"EncryptedVolumeInfo", EncryptedVolumeInfo{}},
		{"APFSSnapshotInfo", APFSSnapshotInfo{}},
		{"DiscoveredNAS", DiscoveredNAS{}},
		{"CloudSyncRootInfo", CloudSyncRootInfo{}},
		{"CloudBackupFinding", CloudBackupFinding{}},
		{"MTPDeviceInfo", MTPDeviceInfo{}},
		{"MTPStatus", MTPStatus{}},
		{"AndroidPartitionInfo", AndroidPartitionInfo{}},
		{"PTPStatus", PTPStatus{}},
		{"PTPDeviceInfo", PTPDeviceInfo{}},
		{"IOSDirectStatus", IOSDirectStatus{}},
		{"IOSDeviceInfo", IOSDeviceInfo{}},
		{"EncryptedReaderCacheStatsResp", EncryptedReaderCacheStatsResp{}},
		{"RAIDScanRequest", RAIDScanRequest{}},

		// === internal/* 类型，会被 IPC / EventsEmit 透传 ===
		// 任何一个少 tag，UI 上都会出现 undefined。
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
					"  历史同类 bug：v2.8.33 修了 gpt.Partition / DetectedArray / Snapshot；\n"+
					"  v2.8.34 修了 MountAdvice / BadSector / DiskJob / JobResult / ImageProgress。\n"+
					"  请给字段加合适的 `json:\"camelCaseName\"` tag",
					s.name, f.Name, f.Name, strings.ToLower(string(f.Name[0]))+f.Name[1:])
				continue
			}
			// 也检查 tag 不是 PascalCase（除 "-" 跳过外，必须 lowerCamelCase）
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

// TestGPTTypeNameByGUID_KnownPartitions 锁住几个常见 GUID 翻译。
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
		got := gptTypeNameByGUID(guid)
		if !strings.Contains(got, wantSub) {
			t.Errorf("gptTypeNameByGUID(%q) = %q, 应含 %q", guid, got, wantSub)
		}
	}
}
