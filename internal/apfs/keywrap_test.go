package apfs

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 3394 测试向量 4.1（128-bit KEK + 128-bit Key Data）：
//
//	KEK    = 000102030405060708090A0B0C0D0E0F
//	Key    = 00112233445566778899AABBCCDDEEFF
//	Wrapped= 1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5
func TestAESKeyUnwrap_RFC3394_Vector4_1(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	wrapped, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	want, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	got, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("解 wrap 不匹配:\n  got  %x\n  want %x", got, want)
	}
}

// RFC 3394 4.4（256-bit KEK + 256-bit Key）
func TestAESKeyUnwrap_RFC3394_Vector4_6(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	wrapped, _ := hex.DecodeString(
		"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
	want, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")

	got, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap 256: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("256-bit 解 wrap 不匹配")
	}
}

// AESKeyWrap → AESKeyUnwrap round-trip
func TestAESKeyWrapUnwrap_RoundTrip(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i ^ 0x55)
	}
	plain := make([]byte, 32)
	for i := range plain {
		plain[i] = byte(i)
	}
	wrapped, err := AESKeyWrap(kek, plain)
	if err != nil {
		t.Fatalf("AESKeyWrap: %v", err)
	}
	got, err := AESKeyUnwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("AESKeyUnwrap: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round-trip 不一致:\n  got  %x\n  want %x", got, plain)
	}
}

// 错误密钥应失败（IV 不匹配）
func TestAESKeyUnwrap_WrongKEKFails(t *testing.T) {
	kek1 := make([]byte, 16)
	kek2 := make([]byte, 16)
	for i := range kek2 {
		kek2[i] = 0xFF
	}
	plain := make([]byte, 16)
	wrapped, _ := AESKeyWrap(kek1, plain)
	if _, err := AESKeyUnwrap(kek2, wrapped); err == nil {
		t.Error("错误密钥应失败")
	}
}

// FileVault 完整链：模拟"derived_key 已知"场景
func TestUnwrapVEKWithDerivedKey_FullChain(t *testing.T) {
	// 1. 真 VEK / KEK
	realVEK := make([]byte, 32)
	for i := range realVEK {
		realVEK[i] = byte(0xC0 + i)
	}
	realKEK := make([]byte, 32)
	for i := range realKEK {
		realKEK[i] = byte(0x70 + i)
	}
	derivedKey := make([]byte, 32) // = "user password 跑完 PBKDF2 的输出"
	for i := range derivedKey {
		derivedKey[i] = byte(0xA0 + i)
	}

	// 2. wrapped chain
	wrappedKEK, err := AESKeyWrap(derivedKey, realKEK)
	if err != nil {
		t.Fatalf("wrap KEK: %v", err)
	}
	wrappedVEK, err := AESKeyWrap(realKEK, realVEK)
	if err != nil {
		t.Fatalf("wrap VEK: %v", err)
	}

	// 3. 反向解
	got, err := UnwrapVEKWithDerivedKey(derivedKey, wrappedKEK, wrappedVEK)
	if err != nil {
		t.Fatalf("UnwrapVEKWithDerivedKey: %v", err)
	}
	if !bytes.Equal(got, realVEK) {
		t.Errorf("VEK 不匹配")
	}

	// 4. 错的 derivedKey 应失败
	bad := make([]byte, 32)
	if _, err := UnwrapVEKWithDerivedKey(bad, wrappedKEK, wrappedVEK); err == nil {
		t.Error("错的 derivedKey 应失败")
	}
}
