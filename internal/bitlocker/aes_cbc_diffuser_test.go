package bitlocker

import (
	"bytes"
	"testing"
)

// AES-CBC-128 (no diffuser) round-trip
func TestCBCNoDiffuser_RoundTrip(t *testing.T) {
	fvek := make([]byte, 32) // K_Data(16) + K_Tweak(16)
	for i := range fvek {
		fvek[i] = byte(0x10 + i)
	}
	c, err := NewCBCDiffuserCipher(fvek, EncryptionAESCBC128, 512)
	if err != nil {
		t.Fatalf("NewCBCDiffuserCipher: %v", err)
	}

	pt := make([]byte, 512)
	for i := range pt {
		pt[i] = byte(0x80 ^ i)
	}
	ct := make([]byte, 512)
	pt2 := make([]byte, 512)

	for _, sn := range []uint64{0, 1, 7, 0xFFFFFF, 0xDEADBEEFCAFEBABE} {
		if err := c.EncryptSector(ct, pt, sn); err != nil {
			t.Fatalf("Encrypt(sn=%d): %v", sn, err)
		}
		if bytes.Equal(ct, pt) {
			t.Errorf("CT == PT @sn=%d，加密未生效", sn)
		}
		if err := c.DecryptSector(pt2, ct, sn); err != nil {
			t.Fatalf("Decrypt(sn=%d): %v", sn, err)
		}
		if !bytes.Equal(pt2, pt) {
			t.Errorf("CBC round-trip 失败 @sn=%d", sn)
		}
	}
}

// AES-CBC-128 + Elephant Diffuser round-trip
func TestCBCWithDiffuser_RoundTrip(t *testing.T) {
	fvek := make([]byte, 48) // K_Data(16) + K_Tweak(16) + K_SectorKey(16)
	for i := range fvek {
		fvek[i] = byte(0x70 + i)
	}
	c, err := NewCBCDiffuserCipher(fvek, EncryptionAESCBCDiff128, 512)
	if err != nil {
		t.Fatalf("NewCBCDiffuserCipher diff128: %v", err)
	}

	pt := make([]byte, 512)
	for i := range pt {
		pt[i] = byte(i & 0xFF)
	}
	ct := make([]byte, 512)
	pt2 := make([]byte, 512)

	for _, sn := range []uint64{0, 5, 100, 0xCAFE, 0xFFFF_FFFF_FFFF_FFFF} {
		if err := c.EncryptSector(ct, pt, sn); err != nil {
			t.Fatalf("Encrypt(diff, sn=%d): %v", sn, err)
		}
		if bytes.Equal(ct, pt) {
			t.Errorf("CT == PT diff @sn=%d", sn)
		}
		if err := c.DecryptSector(pt2, ct, sn); err != nil {
			t.Fatalf("Decrypt(diff, sn=%d): %v", sn, err)
		}
		if !bytes.Equal(pt2, pt) {
			t.Errorf("CBC+diffuser round-trip 失败 @sn=%d", sn)
		}
	}
}

// AES-CBC-256 + Diffuser round-trip
func TestCBC256WithDiffuser_RoundTrip(t *testing.T) {
	fvek := make([]byte, 96) // K_Data(32) + K_Tweak(32) + K_SectorKey(32)
	for i := range fvek {
		fvek[i] = byte(0xA0 + (i & 0x3F))
	}
	c, err := NewCBCDiffuserCipher(fvek, EncryptionAESCBCDiff256, 512)
	if err != nil {
		t.Fatalf("NewCBCDiffuserCipher diff256: %v", err)
	}
	pt := make([]byte, 512)
	for i := range pt {
		pt[i] = byte(i ^ 0x55)
	}
	ct := make([]byte, 512)
	pt2 := make([]byte, 512)
	for _, sn := range []uint64{0, 13, 0xABCDEF} {
		if err := c.EncryptSector(ct, pt, sn); err != nil {
			t.Fatalf("Encrypt 256-diff (sn=%d): %v", sn, err)
		}
		if err := c.DecryptSector(pt2, ct, sn); err != nil {
			t.Fatalf("Decrypt 256-diff (sn=%d): %v", sn, err)
		}
		if !bytes.Equal(pt2, pt) {
			t.Errorf("AES-CBC-256+diffuser round-trip 失败 @sn=%d", sn)
		}
	}
}

// 不同扇区号产生不同密文（确认 IV 起作用）
func TestCBC_DifferentSectorsDifferentCT(t *testing.T) {
	fvek := make([]byte, 32)
	c, _ := NewCBCDiffuserCipher(fvek, EncryptionAESCBC128, 512)
	pt := make([]byte, 512)
	ct1 := make([]byte, 512)
	ct2 := make([]byte, 512)
	c.EncryptSector(ct1, pt, 0)
	c.EncryptSector(ct2, pt, 1)
	if bytes.Equal(ct1, ct2) {
		t.Error("不同 sector 的密文应不同（IV tweak 失效？）")
	}
}

// Diffuser A 加密后再解密 = 原文
func TestDiffuserA_RoundTrip(t *testing.T) {
	buf := make([]byte, 512)
	for i := range buf {
		buf[i] = byte(i)
	}
	orig := append([]byte{}, buf...)
	diffuserAEncrypt(buf)
	diffuserADecrypt(buf)
	if !bytes.Equal(buf, orig) {
		t.Error("Diffuser A 加解密不互逆")
	}
}

// Diffuser B 加密后再解密 = 原文
func TestDiffuserB_RoundTrip(t *testing.T) {
	buf := make([]byte, 512)
	for i := range buf {
		buf[i] = byte(0xFF - i)
	}
	orig := append([]byte{}, buf...)
	diffuserBEncrypt(buf)
	diffuserBDecrypt(buf)
	if !bytes.Equal(buf, orig) {
		t.Error("Diffuser B 加解密不互逆")
	}
}

// 错误的 FVEK 长度应被拒
func TestCBC_RejectsBadFVEKLen(t *testing.T) {
	cases := []struct {
		method uint16
		fvek   int
	}{
		{EncryptionAESCBC128, 16},
		{EncryptionAESCBC256, 32},
		{EncryptionAESCBCDiff128, 32},
		{EncryptionAESCBCDiff256, 48},
	}
	for _, c := range cases {
		_, err := NewCBCDiffuserCipher(make([]byte, c.fvek), c.method, 512)
		if err == nil {
			t.Errorf("method=0x%04X len=%d 应被拒", c.method, c.fvek)
		}
	}
}
