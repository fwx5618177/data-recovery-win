package ntfs

import (
	"testing"
)

// FuzzParseMFTEntry 喂任意字节给 MFT entry parser；目标是**不 panic**。
//
// 数据恢复工具吃用户的损坏盘是常态，parser 遇到恶意 / 损坏字节不能 panic，
// 应该返回 error 或 nil entry。go test -fuzz=FuzzParseMFTEntry -fuzztime=30s
// 自动生成边界 input 找 crash。
//
// 发现 crash 时 Go 会把 input 保存到 testdata/fuzz/FuzzParseMFTEntry/<hash>，
// 下次普通 `go test` 会把它当 regression test 跑 → CI 持续守护。
func FuzzParseMFTEntry(f *testing.F) {
	// seed：1024 字节 FILE record 大小
	seed := make([]byte, 1024)
	copy(seed[0:4], []byte("FILE"))
	f.Add(seed)

	// seed 2：短于 header 的数据
	f.Add([]byte{0x46, 0x49, 0x4C, 0x45}) // "FILE" 但后面没内容
	f.Add([]byte{}) // 空

	f.Fuzz(func(t *testing.T, data []byte) {
		s := &Scanner{}
		// parseMFTEntry 不应 panic，允许返回 error 或 nil
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseMFTEntry panic on len=%d input: %v", len(data), r)
			}
		}()
		_, _ = s.parseMFTEntry(data, 0)
	})
}

// FuzzApplyFixup 喂任意字节给 fixup 验证器；不 panic
func FuzzApplyFixup(f *testing.F) {
	f.Add(make([]byte, 1024))
	f.Add([]byte{0x46, 0x49, 0x4C, 0x45, 0, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("applyFixup panic: %v", r)
			}
		}()
		buf := make([]byte, len(data))
		copy(buf, data)
		_ = applyFixup(buf)
	})
}

