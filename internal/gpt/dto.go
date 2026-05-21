package gpt

import (
	"fmt"
	"strings"
)

// PartitionInfo 是给前端展示的 GPT 分区 DTO —— 字段名 camelCase，
// 含人类可读的 typeGUID 字符串和 size 字段。
//
// v2.8.33 加（原为 main.GPTPartitionInfo）—— 之前直接返回 Partition struct,
// 里面字段都是 PascalCase 无 JSON tag，被 Wails 序列化后前端读
// `firstLBA/lastLBA/name/typeGUID` 全是 undefined。用户截图里看到的
// "未命名 (undefined-undefined)" 就是这个 bug。
//
// v2.8.46 从 main 包搬到 internal/gpt —— 配套的两个纯 helper（GUID 格式化 +
// 名称查询）也搬过来，让 IPC 测试能在外部目录跑而不锁死在 package main。
type PartitionInfo struct {
	Index     int    `json:"index"`    // 1-based 分区编号
	Name      string `json:"name"`     // UTF-16 LE 解码后的分区名（可能为空）
	TypeGUID  string `json:"typeGUID"` // 标准 GUID 字符串
	TypeName  string `json:"typeName"` // 已知 GUID 的人类名
	FirstLBA  uint64 `json:"firstLBA"`
	LastLBA   uint64 `json:"lastLBA"`
	SizeBytes uint64 `json:"sizeBytes"`
	SizeHuman string `json:"sizeHuman"` // 已格式化，如 "128.0 GB"
}

// FormatGUID 把 GPT mixed-endian GUID 字节序转成标准
// "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" 形式。
// GPT GUID 头 3 段是 little-endian，后 2 段是 big-endian（Win/Intel 历史遗留）。
func FormatGUID(b [16]byte) string {
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24,
		uint16(b[4])|uint16(b[5])<<8,
		uint16(b[6])|uint16(b[7])<<8,
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15])
}

// TypeNameByGUID 把已知的 GPT type GUID 翻译成人类名。
// 名单是业界公开标准（Microsoft / Apple / Linux 各家文档）。
func TypeNameByGUID(guid string) string {
	switch strings.ToUpper(guid) {
	case "C12A7328-F81F-11D2-BA4B-00A0C93EC93B":
		return "EFI System Partition"
	case "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7":
		return "Microsoft Basic Data (NTFS / FAT32 / exFAT)"
	case "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC":
		return "Microsoft Recovery"
	case "E3C9E316-0B5C-4DB8-817D-F92DF00215AE":
		return "Microsoft Reserved (MSR)"
	case "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3":
		return "Microsoft LDM Metadata"
	case "AF9B60A0-1431-4F62-BC68-3311714A69AD":
		return "Microsoft LDM Data"
	case "0FC63DAF-8483-4772-8E79-3D69D8477DE4":
		return "Linux Filesystem"
	case "E6D6D379-F507-44C2-A23C-238F2A3DF928":
		return "Linux LVM"
	case "A19D880F-05FC-4D3B-A006-743F0F84911E":
		return "Linux RAID"
	case "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F":
		return "Linux Swap"
	case "933AC7E1-2EB4-4F13-B844-0E14E2AEF915":
		return "Linux /home"
	case "48465300-0000-11AA-AA11-00306543ECAC":
		return "Apple HFS+"
	case "7C3457EF-0000-11AA-AA11-00306543ECAC":
		return "Apple APFS"
	case "55465300-0000-11AA-AA11-00306543ECAC":
		return "Apple UFS"
	case "6A898CC3-1DD2-11B2-99A6-080020736631":
		return "Solaris / illumos ZFS"
	case "21686148-6449-6E6F-744E-656564454649":
		return "BIOS Boot Partition"
	case "00000000-0000-0000-0000-000000000000":
		return "(空槽)"
	}
	return "(未知类型 GUID)"
}
