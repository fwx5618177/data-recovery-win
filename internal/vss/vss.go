// Package vss 枚举 Windows 的 Volume Shadow Copy（卷影副本），让数据恢复能读
// **重装/格式化之前**系统自动做的快照。这是 R-Studio 的"魔法功能"之一：
// 被盗 Windows 电脑在小偷重装之前如果系统还原点还在，里面会有用户个人数据的完整副本。
//
// 本实现走"调 vssadmin 解析 stdout"路径，理由：
//   - 不用引入 CGO / COM 绑定（跨平台编译友好）
//   - vssadmin 是 Windows 自带命令，1000% 可用
//   - 解析 stdout 虽然"脆"，但用 Go regexp + 单测覆盖能管好
//   - ShadowExplorer 等经典工具内部也用 vssadmin 路径
//
// 得到的 DevicePath 形如：
//
//	\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
//
// 可以像普通原盘一样用 CreateFile / os.Open 打开，后续扫描复用现成 NTFS/exFAT 路径。
package vss

import (
	"context"
	"errors"
	"time"
)

// ErrNotSupported 非 Windows 平台调用 ListShadows 的固定返回值
var ErrNotSupported = errors.New("VSS 枚举仅在 Windows 平台可用")

// Shadow 代表一个 Volume Shadow Copy 条目
type Shadow struct {
	ID                string    // GUID
	DevicePath        string    // \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
	OriginatingMachine string   // 创建这个快照的机器名
	ServiceMachine    string    // 持有这个快照的机器名
	OriginalVolume    string    // 快照来源的卷，如 \\?\Volume{...}\ 或 C:\
	CreatedAt         time.Time // 创建时间
}

// ListShadows 枚举本地 Windows 的所有 VSS 快照。
// 非 Windows 平台返回 ErrNotSupported。
// 无快照 / 无权限时返回空切片 + nil error（区分于真实错误）。
func ListShadows(ctx context.Context) ([]Shadow, error) {
	return listShadowsPlatform(ctx)
}
