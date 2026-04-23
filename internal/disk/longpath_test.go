package disk

import (
	"runtime"
	"strings"
	"testing"
)

func TestEnsureLongPath_Short(t *testing.T) {
	// 短路径不改
	got := EnsureLongPath(`C:\foo\bar.txt`)
	if got != `C:\foo\bar.txt` {
		t.Errorf("短路径被改动: %q", got)
	}
}

func TestEnsureLongPath_NoOpOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 平台单独测试")
	}
	// 非 Windows 长路径也不改
	long := "/foo/" + strings.Repeat("a", 300) + ".txt"
	got := EnsureLongPath(long)
	if got != long {
		t.Errorf("非 Windows 不应改动: %q != %q", got, long)
	}
}

func TestEnsureLongPath_LongLocal(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows 加前缀")
	}
	long := `C:\` + strings.Repeat("a", 250) + `.txt`
	got := EnsureLongPath(long)
	if !strings.HasPrefix(got, `\\?\`) {
		t.Errorf("长路径应加 \\\\?\\ 前缀: %q", got)
	}
}

func TestEnsureLongPath_LongUNC(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows UNC 转 \\\\?\\UNC\\")
	}
	long := `\\server\share\` + strings.Repeat("a", 250) + `.txt`
	got := EnsureLongPath(long)
	if !strings.HasPrefix(got, `\\?\UNC\`) {
		t.Errorf("UNC 长路径应转 \\\\?\\UNC\\ 前缀: %q", got)
	}
}

func TestEnsureLongPath_AlreadyPrefixed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip()
	}
	long := `\\?\C:\` + strings.Repeat("a", 250) + `.txt`
	got := EnsureLongPath(long)
	if got != long {
		t.Errorf("已有前缀不应二次加: %q", got)
	}
}
