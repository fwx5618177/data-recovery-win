package btrfs

import "testing"

// FuzzParseTreeBlockHeader B-tree block header parser 不能 panic
func FuzzParseTreeBlockHeader(f *testing.F) {
	f.Add(make([]byte, btrfsHeaderSize))
	f.Add(make([]byte, 10)) // 短于 header
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseTreeBlockHeader panic on len=%d: %v", len(data), r)
			}
		}()
		_, _ = ParseTreeBlockHeader(data)
	})
}

// FuzzParseLeafItems leaf block items parser 不能 panic
func FuzzParseLeafItems(f *testing.F) {
	// 最小合法：header + 0 items
	seed := make([]byte, btrfsHeaderSize)
	f.Add(seed)
	f.Add(make([]byte, 4096))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseLeafItems panic on len=%d: %v", len(data), r)
			}
		}()
		if len(data) < btrfsHeaderSize {
			return
		}
		h, err := ParseTreeBlockHeader(data)
		if err != nil || h == nil {
			return
		}
		_, _ = ParseLeafItems(data, h)
	})
}

// FuzzParseSysChunkArray 系统 chunk array 解析不能 panic
func FuzzParseSysChunkArray(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSysChunkArray panic: %v", r)
			}
		}()
		_, _ = parseSysChunkArray(data)
	})
}
