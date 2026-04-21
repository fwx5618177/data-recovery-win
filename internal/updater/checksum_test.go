package updater

import (
	"strings"
	"testing"
)

func TestParseSHA256SUMS(t *testing.T) {
	input := `
# header comment
abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  DataRecovery-linux-amd64.tar.gz
1234567890123456789012345678901234567890123456789012345678901234 *DataRecovery-windows-amd64.exe
bad-line
# another comment
`
	m, err := parseSHA256SUMS(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("entries=%d want 2", len(m))
	}
	if m["DataRecovery-linux-amd64.tar.gz"] != "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Errorf("linux hash 错")
	}
	if m["DataRecovery-windows-amd64.exe"] != "1234567890123456789012345678901234567890123456789012345678901234" {
		t.Errorf("windows hash 错")
	}
}

func TestVerifyAssetChecksum(t *testing.T) {
	sums := map[string]string{"foo.exe": "abc"}
	if err := VerifyAssetChecksum("foo.exe", "ABC", sums); err != nil {
		t.Errorf("大小写应容忍: %v", err)
	}
	if err := VerifyAssetChecksum("foo.exe", "deadbeef", sums); err == nil {
		t.Error("hash 不匹配应报错")
	}
	if err := VerifyAssetChecksum("missing.exe", "xx", sums); err == nil {
		t.Error("找不到条目应报错")
	}
}
