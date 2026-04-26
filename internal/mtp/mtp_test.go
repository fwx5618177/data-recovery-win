package mtp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 这个测试只验证"adb 不在时所有入口都安全降级"——CI 环境多数没有 adb。
// 真实功能需要插着 Android 手机才能跑，留给 manual integration 测。

func TestAdbAvailable_NoFalsePositive(t *testing.T) {
	// 不能 assert true / false——CI 环境不确定；只验证不 panic + 返回 bool
	got := AdbAvailable()
	t.Logf("adb available: %v", got)
}

func TestListDevices_NoAdbReturnsSentinel(t *testing.T) {
	if AdbAvailable() {
		t.Skip("环境里有 adb，跳过 'no adb' 路径测试")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := ListDevices(ctx)
	if !errors.Is(err, ErrAdbNotInstalled) {
		t.Errorf("无 adb 时应返回 ErrAdbNotInstalled, got %v", err)
	}
}

func TestPullDirectory_RejectsEmptyArgs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := PullDirectory(ctx, "", "", ""); err == nil {
		t.Errorf("空参数应被拒绝")
	}
}
