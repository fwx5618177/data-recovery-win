// Package mtp 提供"直连手机 / 相机"的数据访问入口（MTP / PTP / Android ADB）。
//
// MTP（Media Transfer Protocol）是 Android 手机和数码相机插 USB 时的默认协议。
// 直接走 USB MTP 在 Go 里需要 CGO + libmtp / libusb，这跟我们的"单二进制 / 无 CGO"
// 路线不兼容。
//
// 实用路径（业界主流恢复工具同款做法）：
//
//  1. **Android `adb pull` 路径**（推荐）
//     用户开启 USB 调试 → 接 USB → 我们调 adb 命令拉文件。
//     adb 是 Google 官方工具，跨平台，单文件二进制；用户已经装了 Android Studio
//     或 platform-tools 的 90% 都有。我们检测它的存在，命令找不到时引导用户去装。
//
//  2. **MTP 文件系统挂载路径**（备用）
//     用户用 OS 自带工具挂载手机（gvfs / Android File Transfer / File Explorer），
//     我们把挂载点当成普通目录扫描。这种路径下我们就是一个普通 file scanner，
//     不需要懂 MTP 协议。
//
//  3. **直接 libmtp 路径**（未实现）
//     未来若加 build tag 子集（含 CGO 的 build），可以接 github.com/hanwen/usb +
//     libmtp。当前主路线不带 CGO，留接口位等以后扩。
//
// 这个包只做路径 1：检测 adb，列设备，复制文件目录。 直连扫描的"数据流变成
// 普通文件目录"后，上层 recovery.Engine.ScanDirectory（或 ios/android 备份扫描器）
// 直接接续。
package mtp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Device 是 adb 列出来的一个 Android 设备
type Device struct {
	Serial      string // adb 用的 serial（USB serial 或 IP:port）
	State       string // "device" / "unauthorized" / "offline" / "no permissions"
	Product     string // 设备型号（adb -l 输出里的 product:）
	Model       string // 设备 model
	TransportID string
}

// AdbAvailable 检测 adb 是否在 PATH 里。
// 失败时上层应在 UI 上引导用户去 https://developer.android.com/tools/releases/platform-tools
func AdbAvailable() bool {
	_, err := exec.LookPath("adb")
	return err == nil
}

// AdbVersion 返回 `adb version` 的第一行（"Android Debug Bridge version X.Y.Z"）。
// 失败时返回空串。
func AdbVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "adb", "version")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Android Debug Bridge") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// ListDevices 调 `adb devices -l` 返回连上的 Android 设备清单。
//
// 没装 adb 时返回 ErrAdbNotInstalled。
//
// 设备状态含义：
//   - "device":         已授权，可以用
//   - "unauthorized":   设备插上了但还没在手机上点"允许 USB 调试"——UI 应提示用户去手机点
//   - "offline":        手机灭屏 / 重启中 / driver 没加载
//   - "no permissions": Linux 下 udev 没配置；OS 层面看不到 device node
func ListDevices(ctx context.Context) ([]Device, error) {
	if !AdbAvailable() {
		return nil, ErrAdbNotInstalled
	}
	cmd := exec.CommandContext(ctx, "adb", "devices", "-l")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("adb devices: %w", err)
	}
	var devs []Device
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		d := Device{
			Serial: fields[0],
			State:  fields[1],
		}
		// 解析 -l 扩展字段：product:foo  model:Pixel_7  transport_id:1
		for _, f := range fields[2:] {
			kv := strings.SplitN(f, ":", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "product":
				d.Product = kv[1]
			case "model":
				d.Model = kv[1]
			case "transport_id":
				d.TransportID = kv[1]
			}
		}
		devs = append(devs, d)
	}
	return devs, nil
}

// PullDirectory 用 `adb pull` 把手机端的 srcPath 整个目录拉到本地 destDir。
//
// 业界经验：不要用 adb pull /sdcard/ 整个根（含相机 raw / 大视频，可能 100GB+）；
// 调用方应让用户挑具体子目录（DCIM、WhatsApp 等）。
//
// 进度：adb pull 本身有内置进度行（"[ X% ] file"），上层若需要可以 stderr 流式读。
// 这里同步等到结束；UI 在调用前应显示一个 spinner。
func PullDirectory(ctx context.Context, serial, srcPath, destDir string) error {
	if !AdbAvailable() {
		return ErrAdbNotInstalled
	}
	if serial == "" || srcPath == "" || destDir == "" {
		return errors.New("MTP: 参数不完整 (serial/srcPath/destDir)")
	}
	args := []string{"-s", serial, "pull", srcPath, destDir}
	cmd := exec.CommandContext(ctx, "adb", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("adb pull 失败: %w（输出: %s）", err, string(out))
	}
	return nil
}

// ErrAdbNotInstalled 是 adb 不在 PATH 时所有 MTP 操作的标准错误。
// UI 应据此提示用户：
//
//	"请安装 Android Platform Tools (包含 adb)：https://developer.android.com/tools/releases/platform-tools"
var ErrAdbNotInstalled = errors.New("adb 未安装：MTP 直连依赖 Android Platform Tools (adb) ")
