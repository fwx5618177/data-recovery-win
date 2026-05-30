package recovery

import (
	"strings"
	"testing"
)

// TestValidateRecoveryTarget_EmptyOutputDir 空 outputDir 一律拒
func TestValidateRecoveryTarget_EmptyOutputDir(t *testing.T) {
	e := NewEngine()
	defer e.Shutdown()
	if err := e.ValidateRecoveryTarget(""); err == nil {
		t.Error("空 outputDir 应报错")
	}
	if err := e.ValidateRecoveryTarget("   "); err == nil {
		t.Error("纯空白 outputDir 应报错")
	}
}

// TestValidateRecoveryTarget_NoSourceErrors 所有 source 都没设 → 报"尚未执行扫描"
func TestValidateRecoveryTarget_NoSourceErrors(t *testing.T) {
	e := NewEngine()
	defer e.Shutdown()
	err := e.ValidateRecoveryTarget("/tmp/out")
	if err == nil {
		t.Fatal("无任何 source 应报错")
	}
	if !strings.Contains(err.Error(), "尚未执行扫描") {
		t.Errorf("错误文案应含'尚未执行扫描'，得 %v", err)
	}
}

// TestValidateRecoveryTarget_LocalSourceAccepted v2.8.54 新分支契约：
// 设了 localSourceDir（ADB pull 后场景）→ ValidateRecoveryTarget 不再
// 报"尚未执行扫描"，而是用本地目录跟 outputDir 做跨盘校验。
//
// 本地路径不是 device path（不像 /dev/sdX），disk.ValidateRecoveryTarget
// 对非 device path 直接 nil（这是它的现行契约 —— 见 looksLikeDevicePath）。
// 所以这里期望返 nil。
func TestValidateRecoveryTarget_LocalSourceAccepted(t *testing.T) {
	e := NewEngine()
	defer e.Shutdown()

	// 之前 v2.8.53 这种情况会报"尚未执行扫描" —— 本测试锁住修复
	e.SetLocalSource("/tmp/adb-pull-out")
	if err := e.ValidateRecoveryTarget("/tmp/recovery-out"); err != nil {
		t.Errorf("有 localSourceDir 时 ValidateRecoveryTarget 不应报错（本地路径走 cross-disk nil 路径），得 %v", err)
	}
}

// TestValidateRecoveryTarget_LocalSourceCleared SetLocalSource("") 清空后,
// 跟原始 nil 行为一致 —— 报"尚未执行扫描"。
func TestValidateRecoveryTarget_LocalSourceCleared(t *testing.T) {
	e := NewEngine()
	defer e.Shutdown()

	e.SetLocalSource("/tmp/adb-pull-out")
	e.SetLocalSource("") // 清空
	err := e.ValidateRecoveryTarget("/tmp/recovery-out")
	if err == nil || !strings.Contains(err.Error(), "尚未执行扫描") {
		t.Errorf("SetLocalSource('') 后应回到'尚未执行扫描'错误，得 %v", err)
	}
}
