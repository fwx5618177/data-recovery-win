package main

import (
	"reflect"
	"strings"
	"testing"
)

// 本文件锁住 main-package 私有 DTO 的 JSON 字段名契约。
//
// 为什么必须留 root：这 14 个 DTO（EncryptedVolumeInfo / APFSSnapshotInfo /
// DiscoveredNAS / ... ）定义在 app.go 的 package main，无法被外部测试目录
// import（Go 禁止 import package main）。
//
// 绝大部分 IPC DTO 测试已搬到 tests/dtocontract/contract_test.go。本文件只
// 处理无法搬走的那部分。如果未来把 App 重构进 internal/app 包，本文件可一并
// 删除合并。
func TestMainPackageIPCDTOsHaveJSONTags(t *testing.T) {
	type sample struct {
		name string
		val  interface{}
	}
	samples := []sample{
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
				t.Errorf("%s.%s 缺 json tag —— 前端会读到 undefined。"+
					"Go field %q → JS expected %q",
					s.name, f.Name, f.Name,
					strings.ToLower(string(f.Name[0]))+f.Name[1:])
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
