package mtp

import (
	"context"
	"testing"
)

// IsRooted 在没 adb / 没设备时应返回 (false, ErrAdbNotInstalled) 或 (false, nil)
func TestIsRooted_NoAdb(t *testing.T) {
	if AdbAvailable() {
		t.Skip("跳过：本机有 adb，测试默认无 adb 路径")
	}
	got, err := IsRooted(context.Background(), "any-serial")
	if got || err != ErrAdbNotInstalled {
		t.Errorf("无 adb 时应返回 (false, ErrAdbNotInstalled), got (%v, %v)", got, err)
	}
}

// ListPartitions 在没 adb 时应返回 ErrAdbNotInstalled
func TestListPartitions_NoAdb(t *testing.T) {
	if AdbAvailable() {
		t.Skip()
	}
	_, err := ListPartitions(context.Background(), "any-serial")
	if err != ErrAdbNotInstalled {
		t.Errorf("应返回 ErrAdbNotInstalled, got %v", err)
	}
}

// 有 adb 但没设备：ListPartitions 应返回 ErrNotRooted
func TestListPartitions_NoDevice(t *testing.T) {
	if !AdbAvailable() {
		t.Skip("无 adb")
	}
	_, err := ListPartitions(context.Background(), "nonexistent-device-99999")
	if err == nil {
		t.Error("无设备时应报错")
	}
}

func TestPullViaRecoveryMode_NotEmpty(t *testing.T) {
	s := PullViaRecoveryMode()
	if len(s) < 100 {
		t.Errorf("Recovery mode 文档太短: %d 字符", len(s))
	}
}

// gphoto2 / libimobiledevice 装了的话能列设备（不强制；只在装了的环境下测）
func TestGphoto2_ListWhenAvailable(t *testing.T) {
	if !Gphoto2Available() {
		t.Skip("无 gphoto2")
	}
	devs, err := ListPTPDevices(context.Background())
	if err != nil {
		t.Logf("gphoto2 报错（无相机连接是正常的）: %v", err)
	}
	t.Logf("发现 %d PTP 设备", len(devs))
}

func TestLibIMobileDevice_ListWhenAvailable(t *testing.T) {
	if !LibIMobileDeviceAvailable() {
		t.Skip("无 libimobiledevice")
	}
	devs, err := ListIOSDevices(context.Background())
	if err != nil {
		t.Logf("idevice_id 报错（无 iPhone 连接是正常的）: %v", err)
	}
	t.Logf("发现 %d iOS 设备", len(devs))
}
