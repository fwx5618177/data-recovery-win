package apfs

import (
	"bytes"
	"testing"
)

// FileVault AES-XTS-128 round-trip：用 32 字节 VEK 加密一个扇区，再解回应等于原文
func TestFileVault_XTS128_RoundTrip(t *testing.T) {
	vek := make([]byte, 32)
	for i := range vek {
		vek[i] = byte(0xA0 ^ i)
	}
	c, err := NewFileVaultCipher(vek, 4096)
	if err != nil {
		t.Fatalf("NewFileVaultCipher: %v", err)
	}
	pt := make([]byte, 4096)
	for i := range pt {
		pt[i] = byte(i & 0xFF)
	}
	ct := make([]byte, 4096)
	pt2 := make([]byte, 4096)
	for _, blk := range []uint64{0, 1, 0xCAFE, 0xFFFFFFFFFFFFFFFF} {
		if err := c.EncryptSector(ct, pt, blk); err != nil {
			t.Fatalf("Enc(%d): %v", blk, err)
		}
		if bytes.Equal(ct, pt) {
			t.Errorf("CT == PT @blk=%d", blk)
		}
		if err := c.DecryptSector(pt2, ct, blk); err != nil {
			t.Fatalf("Dec(%d): %v", blk, err)
		}
		if !bytes.Equal(pt2, pt) {
			t.Errorf("FileVault XTS round-trip 失败 @blk=%d", blk)
		}
	}
}

func TestFileVault_XTS256_RoundTrip(t *testing.T) {
	vek := make([]byte, 64)
	c, err := NewFileVaultCipher(vek, 4096)
	if err != nil {
		t.Fatalf("NewFileVaultCipher 256: %v", err)
	}
	pt := make([]byte, 4096)
	ct := make([]byte, 4096)
	pt2 := make([]byte, 4096)
	c.EncryptSector(ct, pt, 7)
	c.DecryptSector(pt2, ct, 7)
	if !bytes.Equal(pt2, pt) {
		t.Error("XTS-256 round-trip 失败")
	}
}

func TestFileVault_RejectsBadVEKLen(t *testing.T) {
	for _, n := range []int{0, 16, 33, 48, 65} {
		_, err := NewFileVaultCipher(make([]byte, n), 4096)
		if err == nil {
			t.Errorf("VEK 长度 %d 应被拒", n)
		}
	}
}

func TestDeriveKeyFromPassword_DeterministicAndDifferentSalts(t *testing.T) {
	pw := "Sup3rStr0ng!"
	salt1 := []byte("salt-one-1234567")
	salt2 := []byte("salt-two-7654321")

	k1a := DeriveKeyFromPassword(pw, salt1, 1000, 32)
	k1b := DeriveKeyFromPassword(pw, salt1, 1000, 32)
	if !bytes.Equal(k1a, k1b) {
		t.Error("相同输入应得相同结果")
	}
	k2 := DeriveKeyFromPassword(pw, salt2, 1000, 32)
	if bytes.Equal(k1a, k2) {
		t.Error("不同 salt 应得不同 key")
	}
	k3 := DeriveKeyFromPassword(pw, salt1, 2000, 32)
	if bytes.Equal(k1a, k3) {
		t.Error("不同 iter 应得不同 key")
	}
	if len(k1a) != 32 {
		t.Errorf("key len=%d want 32", len(k1a))
	}
}
