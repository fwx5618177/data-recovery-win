package ntfs

import (
	"testing"
)

// FuzzParseUSNJournal 随机字节喂给 USN parser，确保不 panic / OOM。
// 跑法：go test -fuzz=FuzzParseUSNJournal ./internal/ntfs/...
func FuzzParseUSNJournal(f *testing.F) {
	// seed：合法 record + 损坏 record + 空字节
	f.Add([]byte{})
	f.Add(make([]byte, 16)) // 全 0
	f.Add(buildUSNRecordV2(0x1234, 5, UsnReasonFileDelete, "kitten.jpg"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// 不能 panic / 死循环；返回值不重要
		_, _ = ParseUSNJournal(data)
	})
}
