package recovery

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeFilename_WindowsIllegal(t *testing.T) {
	got := sanitizeFilename(`a<b>c:d"e/f\g|h?i*j`)
	for _, ch := range []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"} {
		if strings.Contains(got, ch) {
			t.Errorf("非法字符 %q 仍在结果里: %q", ch, got)
		}
	}
}

func TestSanitizeFilename_BidiOverride(t *testing.T) {
	// "evil\u202Efdp.exe" = "evil" + RLO + "fdp.exe" → 资源管理器会显示成 "eviltxt.live"
	// 过滤掉 U+202E 后应变成 "evilfdp.exe"
	got := sanitizeFilename("evil\u202Efdp.exe")
	if strings.ContainsRune(got, '\u202E') {
		t.Errorf("RLO 未过滤: %q", got)
	}
	if got != "evilfdp.exe" {
		t.Errorf("过滤后文件名异常: got %q want %q", got, "evilfdp.exe")
	}
}

func TestSanitizeFilename_RuneLimit(t *testing.T) {
	// 500 个中文字符（1500 bytes），按 rune 限 200 应保留 200 个中文
	name := strings.Repeat("中", 500) + ".txt"
	got := sanitizeFilename(name)
	if utf8.RuneCountInString(got) > 200 {
		t.Errorf("rune 数超限: %d", utf8.RuneCountInString(got))
	}
	if !strings.HasSuffix(got, ".txt") {
		t.Errorf("扩展名丢失: %q", got)
	}
}

func TestSanitizeFilename_WindowsReserved(t *testing.T) {
	cases := map[string]string{
		"CON":         "_CON",
		"con.txt":     "_con.txt",
		"AUX.log":     "_AUX.log",
		"COM1":        "_COM1",
		"LPT9.bin":    "_LPT9.bin",
		"NotReserved": "NotReserved",
	}
	for in, want := range cases {
		got := sanitizeFilename(in)
		if got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitizeFilename_NFCNormalize(t *testing.T) {
	// "é" 有两种表达：U+00E9 (NFC) 和 U+0065 U+0301 (NFD)
	// macOS 文件系统用 NFD。sanitize 应统一到 NFC
	nfd := "caf\u0065\u0301.txt" // "café" NFD
	nfc := "caf\u00E9.txt"       // "café" NFC
	got := sanitizeFilename(nfd)
	if got != nfc {
		t.Errorf("NFD 未归一到 NFC: got %q want %q", got, nfc)
	}
}

func TestSanitizeFilename_ControlChars(t *testing.T) {
	// C0 控制符 + DEL + C1 控制符 都应过滤
	in := "file\x00\x1F\x7F\x9Fname.txt"
	got := sanitizeFilename(in)
	if got != "filename.txt" {
		t.Errorf("控制字符未过滤: got %q", got)
	}
}

func TestSanitizeFilename_TrailingDotsAndSpaces(t *testing.T) {
	cases := map[string]string{
		"name.":      "name",
		".name":      "name",
		"  name  ":   "name",
		"name...":    "name",
		"...hidden.": "hidden",
	}
	for in, want := range cases {
		got := sanitizeFilename(in)
		if got != want {
			t.Errorf("sanitize(%q) = %q want %q", in, got, want)
		}
	}
}

func TestSanitizeFilename_Empty(t *testing.T) {
	cases := []string{"", "   ", "...", "<>|?"}
	for _, in := range cases {
		got := sanitizeFilename(in)
		if got == "" {
			t.Errorf("空输入 %q 不应返回空", in)
		}
	}
}
