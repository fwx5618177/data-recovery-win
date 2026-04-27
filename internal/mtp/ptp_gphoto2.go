package mtp

// PTP (Picture Transfer Protocol) 经 gphoto2 系统工具 —— 数码相机 / 部分 Android
// 老机型走 PTP 而不是 MTP（USB descriptor class 0x06 vs MTP class 0xFF）。
//
// 业界做法：
//
//   - **gphoto2** (libgphoto2)：开源命令行工具，支持 2300+ 相机/手机型号。
//     macOS: brew install gphoto2 / Linux: apt install gphoto2
//     Windows 上是 libgphoto2 + WinGphoto2 cli (zadig 装 USB driver)
//
//   - 替代方案：Linux 自带 gvfs-mtp（gvfs-mount, gio mount mtp://）
//     macOS 自带 Image Capture (ImageCaptureCore)，命令行 'imagesnap'
//     Windows 自带 WPD (Windows Portable Devices) via PowerShell
//
// 我们走 gphoto2 因为：
//   1. 三个平台都能装（不像 WPD 仅 Windows）
//   2. CLI 输出稳定可解析
//   3. 用户习惯：摄影圈 + 取证圈都熟
//
// 退化路径：gphoto2 不存在 → 提示装 + 给"用 OS 自带工具挂载手机后选挂载点"的方案

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// PTPDevice 是 gphoto2 --auto-detect 列出的一个设备
type PTPDevice struct {
	Model string // 例 "Canon EOS R5" / "Nikon Z9"
	Port  string // 例 "usb:001,015" — gphoto2 命令行选 device 用
}

// Gphoto2Available 检测 gphoto2 是否在 PATH 里
func Gphoto2Available() bool {
	_, err := exec.LookPath("gphoto2")
	return err == nil
}

// Gphoto2Version 返回 `gphoto2 --version` 第一行
func Gphoto2Version(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "gphoto2", "--version")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "gphoto2") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// ListPTPDevices 调 `gphoto2 --auto-detect`
//
// 输出格式（gphoto2 5.x）：
//
//	Model                          Port
//	----------------------------------------------------------
//	Canon EOS R5                   usb:001,015
//	Sony Alpha A7                  usb:002,003
func ListPTPDevices(ctx context.Context) ([]PTPDevice, error) {
	if !Gphoto2Available() {
		return nil, ErrGphoto2NotInstalled
	}
	cmd := exec.CommandContext(ctx, "gphoto2", "--auto-detect")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gphoto2 --auto-detect: %w", err)
	}
	var devs []PTPDevice
	skipHeader := true
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "----") {
			skipHeader = false
			continue
		}
		if skipHeader || line == "" {
			continue
		}
		// 行格式：MODEL ... PORT  （空格 padding 不固定，最后一个 field 是 port）
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		port := fields[len(fields)-1]
		if !strings.HasPrefix(port, "usb:") && !strings.HasPrefix(port, "ptpip:") {
			continue
		}
		model := strings.Join(fields[:len(fields)-1], " ")
		devs = append(devs, PTPDevice{Model: model, Port: port})
	}
	return devs, nil
}

// PullPTPAll 用 gphoto2 拉所有相机文件到本地 destDir
//
//	gphoto2 --port=<port> --get-all-files --filename "%f.%C"
//
// 命名模式 "%f.%C" = 原文件名.原扩展名 ；其他常用模式：
//
//	"%n_%f.%C"  — 编号_原名（防同名）
//	"%Y/%m/%f.%C" — 按年/月分目录
func PullPTPAll(ctx context.Context, port, destDir string) error {
	if !Gphoto2Available() {
		return ErrGphoto2NotInstalled
	}
	if port == "" || destDir == "" {
		return errors.New("PTP pull: port/destDir 不能为空")
	}
	cmd := exec.CommandContext(ctx, "gphoto2",
		"--port="+port,
		"--get-all-files",
		"--filename", "%n_%f.%C",
	)
	cmd.Dir = destDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gphoto2 --get-all-files: %w（输出: %s）", err, string(out))
	}
	return nil
}

// ErrGphoto2NotInstalled gphoto2 不在 PATH 时返回
var ErrGphoto2NotInstalled = errors.New("gphoto2 未安装：PTP 直连需要 libgphoto2 工具")
