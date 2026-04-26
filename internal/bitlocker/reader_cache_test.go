package bitlocker

import (
	"bytes"
	"sync"
	"testing"

	"data-recovery/internal/testutil"
)

// countingCipher 用于验证 cache 命中后跳过 cipher。
type countingCipher struct {
	mu    sync.Mutex
	calls int
}

func (c *countingCipher) DecryptSector(dst, src []byte, _ uint64) error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if &dst[0] != &src[0] {
		copy(dst, src) // 模拟 in-place
	}
	return nil
}
func (c *countingCipher) SectorSize() int { return 512 }

// 同一 sector 反复读应只触发 1 次 Decrypt
func TestDecryptingReader_CacheHit(t *testing.T) {
	pt := bytes.Repeat([]byte{0xAB}, 4*512)
	mr := testutil.NewMemReader(pt)
	fc := &countingCipher{}
	r, err := NewDecryptingReaderWithCache(mr, fc, "test", 16)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 512)

	// 第 1 次读 sector 0 → miss → 1 次 Decrypt
	if _, err := r.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if fc.calls != 1 {
		t.Errorf("第 1 次应有 1 次 Decrypt, got %d", fc.calls)
	}
	// 后续 9 次读同一 sector → 命中，无新 Decrypt
	for i := 0; i < 9; i++ {
		if _, err := r.ReadAt(got, 0); err != nil {
			t.Fatal(err)
		}
	}
	if fc.calls != 1 {
		t.Errorf("命中后 Decrypt 计数应仍为 1, got %d", fc.calls)
	}
}

// 明文区不进缓存（plaintext header 段直接透传）
func TestDecryptingReader_CacheSkipsPlaintextHeader(t *testing.T) {
	pt := bytes.Repeat([]byte{0xCD}, 8*512)
	mr := testutil.NewMemReader(pt)
	fc := &countingCipher{}
	r, _ := NewDecryptingReaderWithCache(mr, fc, "test", 16)
	r.SetPlainTextHeaderEnd(2 * 512) // sector 0 + 1 是明文
	got := make([]byte, 512)

	// 读明文区 sector 0 → 不应 Decrypt 也不进 cache
	r.ReadAt(got, 0)
	if fc.calls != 0 {
		t.Errorf("明文区不应 Decrypt, got %d", fc.calls)
	}

	// 读加密区 sector 5 → miss → 1 次
	r.ReadAt(got, 5*512)
	if fc.calls != 1 {
		t.Errorf("加密区第 1 次应 1 次 Decrypt, got %d", fc.calls)
	}
	// 重读 sector 5 → cache 命中 → 不增
	r.ReadAt(got, 5*512)
	if fc.calls != 1 {
		t.Errorf("加密区命中后不应再 Decrypt, got %d", fc.calls)
	}
}

// 关闭缓存（cacheSectors=0）行为应与原版一致：每次 Decrypt
func TestDecryptingReader_CacheDisabled(t *testing.T) {
	pt := bytes.Repeat([]byte{0xEF}, 4*512)
	mr := testutil.NewMemReader(pt)
	fc := &countingCipher{}
	r, _ := NewDecryptingReaderWithCache(mr, fc, "test", 0) // 禁用缓存
	got := make([]byte, 512)

	for i := 0; i < 5; i++ {
		r.ReadAt(got, 0)
	}
	if fc.calls != 5 {
		t.Errorf("禁用 cache 时 5 次读应 5 次 Decrypt, got %d", fc.calls)
	}
}
