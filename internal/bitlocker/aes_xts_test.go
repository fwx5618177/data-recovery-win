package bitlocker

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// IEEE Std 1619-2007 Appendix B 测试向量 1（AES-XTS-128）
// Key1 = 00..00 (16 bytes), Key2 = 00..00 (16 bytes)
// DataUnitNumber = 0
// PT = 32 bytes of 0x00
// CT = 917cf69ebd68b2ec9b9fe9a3eadda692 cd43d2f59598ed858c02c2652fbf922e
//
// 来源：IEEE Std 1619-2007 (XTS-AES)，Appendix B "Test Vectors"
func TestXTS_NIST_Vector1(t *testing.T) {
	key := mustHex(t, "00000000000000000000000000000000"+ // K1
		"00000000000000000000000000000000") // K2
	pt := mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000")
	wantCT := mustHex(t, "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e")

	// 用 32 字节 sector size 作为 data unit（这是 IEEE 测试向量的设定，不是 BitLocker）
	xts, err := NewXTSCipher(key, 32)
	if err != nil {
		t.Fatalf("NewXTSCipher: %v", err)
	}

	gotCT := make([]byte, len(pt))
	if err := xts.EncryptSector(gotCT, pt, 0); err != nil {
		t.Fatalf("EncryptSector: %v", err)
	}
	if !bytes.Equal(gotCT, wantCT) {
		t.Errorf("CT 不匹配 IEEE 1619 vector 1:\n  got  %s\n  want %s",
			hex.EncodeToString(gotCT), hex.EncodeToString(wantCT))
	}

	// 反向解密
	gotPT := make([]byte, len(wantCT))
	if err := xts.DecryptSector(gotPT, wantCT, 0); err != nil {
		t.Fatalf("DecryptSector: %v", err)
	}
	if !bytes.Equal(gotPT, pt) {
		t.Errorf("PT 解密不匹配:\n  got  %s\n  want %s",
			hex.EncodeToString(gotPT), hex.EncodeToString(pt))
	}
}

// IEEE Std 1619-2007 Vector 2: 不同 K1/K2 + DataUnit=0x3333333333
//
// Key1 = 11111111111111111111111111111111
// Key2 = 22222222222222222222222222222222
// DataUnitNumber = 0x3333333333
// PT = 4444444444444444444444444444444444444444444444444444444444444444
// CT = c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0
func TestXTS_NIST_Vector2(t *testing.T) {
	key := mustHex(t, "11111111111111111111111111111111"+
		"22222222222222222222222222222222")
	pt := mustHex(t, "4444444444444444444444444444444444444444444444444444444444444444")
	wantCT := mustHex(t, "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0")

	xts, _ := NewXTSCipher(key, 32)
	got := make([]byte, len(pt))
	if err := xts.EncryptSector(got, pt, 0x3333333333); err != nil {
		t.Fatalf("EncryptSector: %v", err)
	}
	if !bytes.Equal(got, wantCT) {
		t.Errorf("Vector 2 CT 不匹配:\n  got  %s\n  want %s",
			hex.EncodeToString(got), hex.EncodeToString(wantCT))
	}

	// 解密回去
	dec := make([]byte, len(wantCT))
	xts.DecryptSector(dec, wantCT, 0x3333333333)
	if !bytes.Equal(dec, pt) {
		t.Errorf("Vector 2 解密失败")
	}
}

// 512 字节扇区 round-trip（BitLocker 实际使用尺寸）
func TestXTS_512ByteSectorRoundTrip(t *testing.T) {
	key := mustHex(t, "0123456789ABCDEF0123456789ABCDEF"+
		"FEDCBA9876543210FEDCBA9876543210")

	pt := make([]byte, 512)
	for i := range pt {
		pt[i] = byte(i & 0xFF)
	}

	xts, err := NewXTSCipher(key, 512)
	if err != nil {
		t.Fatalf("NewXTSCipher: %v", err)
	}

	ct := make([]byte, 512)
	pt2 := make([]byte, 512)

	for _, sn := range []uint64{0, 1, 100, 0xDEADBEEF, 0xFFFFFFFFFFFFFFFF} {
		if err := xts.EncryptSector(ct, pt, sn); err != nil {
			t.Fatalf("Encrypt(sector=%d): %v", sn, err)
		}
		if bytes.Equal(ct, pt) {
			t.Errorf("CT 与 PT 完全相同（加密没起作用）@sector=%d", sn)
		}
		if err := xts.DecryptSector(pt2, ct, sn); err != nil {
			t.Fatalf("Decrypt(sector=%d): %v", sn, err)
		}
		if !bytes.Equal(pt2, pt) {
			t.Errorf("round-trip 失败 @sector=%d", sn)
		}
	}
}

// 不同扇区号产生不同密文（确认 tweak 起作用）
func TestXTS_DifferentSectorsDifferentCT(t *testing.T) {
	key := mustHex(t, "00000000000000000000000000000000"+
		"00000000000000000000000000000000")
	pt := make([]byte, 512)
	xts, _ := NewXTSCipher(key, 512)

	ct1 := make([]byte, 512)
	ct2 := make([]byte, 512)
	xts.EncryptSector(ct1, pt, 0)
	xts.EncryptSector(ct2, pt, 1)
	if bytes.Equal(ct1, ct2) {
		t.Error("不同 sector 的密文应不同（tweak 失效？）")
	}
}

// AES-XTS-256（K1+K2 各 32 字节）
func TestXTS_AES256(t *testing.T) {
	key := make([]byte, 64) // 全零 256-bit K1 + 256-bit K2
	pt := make([]byte, 512)
	for i := range pt {
		pt[i] = byte(i)
	}
	xts, err := NewXTSCipher(key, 512)
	if err != nil {
		t.Fatalf("NewXTSCipher AES-256: %v", err)
	}
	ct := make([]byte, 512)
	pt2 := make([]byte, 512)
	xts.EncryptSector(ct, pt, 42)
	xts.DecryptSector(pt2, ct, 42)
	if !bytes.Equal(pt2, pt) {
		t.Error("AES-XTS-256 round-trip 失败")
	}
}

// 错误密钥长度
func TestXTS_RejectsBadKeyLen(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 48, 63, 65, 128} {
		_, err := NewXTSCipher(make([]byte, n), 512)
		if err == nil {
			t.Errorf("len=%d 应被拒", n)
		}
	}
}

// gfMulAlpha 边界：当 bit 127 = 1 时溢出 + XOR 0x87
func TestGFMulAlpha_OverflowXOR(t *testing.T) {
	var t1 [xtsBlockSize]byte
	t1[15] = 0x80 // bit 127 = 1（最高位）
	gfMulAlpha(&t1)
	// 左移 1 位后 bit 127 = 0；溢出 → t1[0] 应 ^= 0x87
	if t1[0] != 0x87 {
		t.Errorf("溢出后 t1[0] 应为 0x87，实际 0x%02X", t1[0])
	}
	if t1[15] != 0x00 {
		t.Errorf("左移后 t1[15] 应为 0x00，实际 0x%02X", t1[15])
	}
}

// gfMulAlpha：连续乘 8 次 = 左移 8 位
func TestGFMulAlpha_LeftShift(t *testing.T) {
	var v [xtsBlockSize]byte
	v[0] = 0x01 // 最低位
	for i := 0; i < 8; i++ {
		gfMulAlpha(&v)
	}
	// 期望：v[1] = 0x01 (左移 8 位 = 移到下一字节)
	if v[1] != 0x01 || v[0] != 0 {
		t.Errorf("左移 8 位结果错: v[0]=0x%02X v[1]=0x%02X", v[0], v[1])
	}
}
