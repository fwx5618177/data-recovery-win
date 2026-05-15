package mtp

// iOS 直连 via libimobiledevice 系统工具（idevice* CLI 套件）
//
// libimobiledevice 是 iOS 设备 USB 协议（USBmuxd / lockdownd）的开源 reverse
// engineering 实现，支持非越狱设备的：
//
//   - **idevicebackup2 backup <dest>**：触发 iOS 系统级备份到本地（等效于
//     iTunes "立即备份"按钮）。这是非越狱机能拿到最完整数据的方式（含 SQLite
//     数据库 / Keychain 加密包）。
//   - **idevicepair pair**：与 iPhone 建立 trust（用户在 iPhone 上点"信任此电脑"）
//   - **ideviceinfo**：基本信息（model / iOS 版本 / serial / battery）
//   - **idevicesyslog**：实时系统日志（取证有用）
//   - **ifuse**：把 iPhone 的 Documents 目录挂载到本地（仅 app sandbox 可见）
//
// 装方式：
//
//	macOS:    brew install libimobiledevice ifuse
//	Linux:    apt install libimobiledevice-utils ifuse
//	Windows:  imobiledevice-net (zwclose7 fork) — 较少用
//
// 越狱设备额外能用：
//   - **AFC2**（jailbroken 设备装 com.saurik.AFC2 后）能看整个文件系统而不只 sandbox
//   - 直接 SSH 到设备 (端口 22) 走标准 unix 工具
//
// 当前包提供：检测 + 列设备 + 触发备份。备份完成后接现有 internal/ios 解析链。

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// IOSDevice 是 idevice_id 列出的一个 iOS 设备
type IOSDevice struct {
	UDID    string // iOS 设备唯一标识
	Model   string // 例 "iPhone15,3" (iPhone 14 Pro Max)
	Name    string // 用户给设备起的名字（"小红的 iPhone"）
	IOSVer  string // 例 "17.4.1"
	Trusted bool   // 是否已 pair（用户在 iPhone 上点过"信任"）
}

// LibIMobileDeviceAvailable 检测 idevice_id 是否在 PATH 里
func LibIMobileDeviceAvailable() bool {
	_, err := exec.LookPath("idevice_id")
	return err == nil
}

// ListIOSDevices 调 `idevice_id -l` 列连上的 UDID，再 `ideviceinfo -u UDID`
// 取每个的 model/iOS 版本
func ListIOSDevices(ctx context.Context) ([]IOSDevice, error) {
	if !LibIMobileDeviceAvailable() {
		return nil, ErrLibIMobileDeviceNotInstalled
	}
	cmd := exec.CommandContext(ctx, "idevice_id", "-l")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("idevice_id -l: %w", err)
	}
	var devs []IOSDevice
	for _, line := range strings.Split(string(out), "\n") {
		udid := strings.TrimSpace(line)
		if udid == "" {
			continue
		}
		d := IOSDevice{UDID: udid}
		// ideviceinfo -u UDID -k ProductType / ProductVersion / DeviceName
		d.Model = ideviceinfoKey(ctx, udid, "ProductType")
		d.IOSVer = ideviceinfoKey(ctx, udid, "ProductVersion")
		d.Name = ideviceinfoKey(ctx, udid, "DeviceName")
		// 没 trust 的设备 ideviceinfo 会失败，model 为空
		d.Trusted = d.Model != ""
		devs = append(devs, d)
	}
	return devs, nil
}

func ideviceinfoKey(ctx context.Context, udid, key string) string {
	cmd := exec.CommandContext(ctx, "ideviceinfo", "-u", udid, "-k", key)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// PairIOSDevice 触发 idevicepair pair，会让 iPhone 弹"信任此电脑"提示
//
// 用户必须在 iPhone 屏幕上点"信任"才能继续。本函数发起 pair，返回 nil 表示
// 命令成功（不代表用户已信任 — 还要后续 `idevicepair list` 验证）。
func PairIOSDevice(ctx context.Context, udid string) error {
	if !LibIMobileDeviceAvailable() {
		return ErrLibIMobileDeviceNotInstalled
	}
	cmd := exec.CommandContext(ctx, "idevicepair", "-u", udid, "pair")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// 常见失败：用户拒绝 "信任此电脑" → idevicepair 返回 "ERROR: Could not validate"
		return fmt.Errorf("idevicepair: %w（输出: %s）", err, string(out))
	}
	return nil
}

// TriggerIOSBackup 触发系统级 iOS 备份到 destDir
//
// 用 idevicebackup2 backup --full UDID destDir
//
// 这是个**长操作**（>30GB 数据可能要 30 分钟），调用方应在 goroutine 里调
// + 显示进度。idevicebackup2 stdout 含进度行 "[X%] Receiving files..."
//
// 备份完成后 destDir 下会有：
//
//	destDir/<UDID>/Manifest.plist
//	destDir/<UDID>/Manifest.db   (SQLite，含文件清单)
//	destDir/<UDID>/Info.plist
//	destDir/<UDID>/<两位hash>/   (10000+ 文件分桶存储)
//
// 然后调 internal/ios.DiscoverBackups(destDir) 就能把它当做普通 iOS 备份扫。
func TriggerIOSBackup(ctx context.Context, udid, destDir string) error {
	if !LibIMobileDeviceAvailable() {
		return ErrLibIMobileDeviceNotInstalled
	}
	if udid == "" || destDir == "" {
		return errors.New("TriggerIOSBackup: udid/destDir 不能为空")
	}
	cmd := exec.CommandContext(ctx, "idevicebackup2",
		"backup", "--full", "-u", udid, destDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("idevicebackup2 backup: %w（输出: %s）", err, string(out))
	}
	return nil
}

// MountIOSDocuments 用 ifuse 把设备的 Documents 目录挂载到本地 mntPoint
//
// 这只能看 app sandbox 暴露的 Documents 区（极有限：照片要走 imageCapture，
// 用户文档要走具体 app 的 Document Provider）。**完整数据要走 idevicebackup2**。
//
// 越狱设备用 `ifuse --root mntPoint` 看整个文件系统（需要 AFC2）。
func MountIOSDocuments(ctx context.Context, udid, mntPoint string) error {
	if _, err := exec.LookPath("ifuse"); err != nil {
		return errors.New("ifuse 未安装：iOS 文件挂载需要 ifuse + libimobiledevice")
	}
	cmd := exec.CommandContext(ctx, "ifuse", "-u", udid, mntPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifuse: %w（输出: %s）", err, string(out))
	}
	return nil
}

// ErrLibIMobileDeviceNotInstalled libimobiledevice 工具链不在 PATH 时返回
var ErrLibIMobileDeviceNotInstalled = errors.New(
	"libimobiledevice 未安装：iOS 直连需要 idevice_id / idevicebackup2 等工具" +
		"（macOS: brew install libimobiledevice / Linux: apt install libimobiledevice-utils）")
