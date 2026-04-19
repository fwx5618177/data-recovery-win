package signature

import (
	"bytes"
	"testing"

	"data-recovery/internal/types"
)

func newSig(ext string) *types.FileSignature {
	return &types.FileSignature{Extension: ext, Category: types.CategoryOther}
}

func TestAhoCorasick_SinglePattern(t *testing.T) {
	ac := NewAhoCorasick()
	ac.AddPattern([]byte{0xFF, 0xD8, 0xFF}, newSig("jpg"))
	ac.Build()

	data := make([]byte, 1024)
	copy(data[100:], []byte{0xFF, 0xD8, 0xFF, 0xE0})

	matches := ac.Search(data, 0)
	if len(matches) != 1 {
		t.Fatalf("期望 1 个匹配，实际 %d", len(matches))
	}
	if matches[0].Offset != 100 {
		t.Errorf("偏移错误: got %d, want 100", matches[0].Offset)
	}
	if matches[0].Signature.Extension != "jpg" {
		t.Errorf("扩展名错误: got %q", matches[0].Signature.Extension)
	}
}

func TestAhoCorasick_OverlappingPatterns(t *testing.T) {
	// he 和 she 共享后缀 "he"，经典 AC 后缀合并测试
	ac := NewAhoCorasick()
	ac.AddPattern([]byte("he"), newSig("he"))
	ac.AddPattern([]byte("she"), newSig("she"))
	ac.AddPattern([]byte("his"), newSig("his"))
	ac.AddPattern([]byte("hers"), newSig("hers"))
	ac.Build()

	matches := ac.Search([]byte("ushers"), 0)
	exts := make(map[string]int64)
	for _, m := range matches {
		exts[m.Signature.Extension] = m.Offset
	}

	// 期望命中: she(1), he(2), hers(2)
	if exts["she"] != 1 {
		t.Errorf("she 偏移错误: got %d", exts["she"])
	}
	if exts["he"] != 2 {
		t.Errorf("he 偏移错误: got %d", exts["he"])
	}
	if exts["hers"] != 2 {
		t.Errorf("hers 偏移错误: got %d", exts["hers"])
	}
	if _, ok := exts["his"]; ok {
		t.Errorf("不应匹配 his")
	}
}

func TestAhoCorasick_BaseOffset(t *testing.T) {
	ac := NewAhoCorasick()
	ac.AddPattern([]byte("PK"), newSig("zip"))
	ac.Build()

	matches := ac.Search([]byte{'x', 'P', 'K', 'y'}, 10_000)
	if len(matches) != 1 {
		t.Fatalf("期望 1 个匹配")
	}
	if matches[0].Offset != 10_001 {
		t.Errorf("绝对偏移错误: got %d, want 10001", matches[0].Offset)
	}
}

func TestAhoCorasick_BuildRequired(t *testing.T) {
	ac := NewAhoCorasick()
	ac.AddPattern([]byte("abc"), newSig("x"))
	// 未调用 Build
	matches := ac.Search([]byte("xxabcxx"), 0)
	if len(matches) != 0 {
		t.Errorf("未 Build 时不应返回匹配，实际 %d", len(matches))
	}
}

func TestAhoCorasick_EmptyPatternIgnored(t *testing.T) {
	ac := NewAhoCorasick()
	ac.AddPattern(nil, newSig("nil"))
	ac.AddPattern([]byte{}, newSig("empty"))
	ac.AddPattern([]byte("PK"), newSig("zip"))
	ac.Build()

	matches := ac.Search([]byte("aPKb"), 0)
	if len(matches) != 1 {
		t.Fatalf("期望 1 个匹配，实际 %d", len(matches))
	}
}

func TestAhoCorasick_BinarySafe(t *testing.T) {
	// AC 应对包含 0x00 的模式和数据都稳定工作
	pattern := []byte{0x00, 0x01, 0x02}
	ac := NewAhoCorasick()
	ac.AddPattern(pattern, newSig("bin"))
	ac.Build()

	data := bytes.Repeat([]byte{0x00}, 512)
	data[200] = 0x00
	data[201] = 0x01
	data[202] = 0x02

	matches := ac.Search(data, 0)
	found := false
	for _, m := range matches {
		if m.Offset == 200 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("未在偏移 200 命中二进制模式")
	}
}

func TestSignatureDB_AllHeadersNonEmpty(t *testing.T) {
	db := NewSignatureDB()
	headers := db.AllHeaders()
	if len(headers) == 0 {
		t.Fatal("签名库返回的 headers 为空")
	}
	for _, h := range headers {
		if len(h.Pattern) == 0 {
			t.Errorf("签名 %q 出现空 header", h.Signature.Extension)
		}
		if h.Signature == nil {
			t.Errorf("HeaderEntry 的 Signature 为 nil")
		}
	}
	if db.MaxHeaderLen() <= 0 {
		t.Error("MaxHeaderLen 应 > 0")
	}
}
