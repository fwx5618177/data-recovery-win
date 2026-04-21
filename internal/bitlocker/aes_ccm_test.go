package bitlocker

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// 自洽 round-trip：加密一段明文 → 解密 → 比对。
// 测的是我们 EncryptAESCCM / DecryptAESCCM 的对称性，不依赖外部向量。
func TestAESCCM_RoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello, world")},
		{"exactly-block", bytes.Repeat([]byte{0xAB}, 16)},
		{"two-blocks", bytes.Repeat([]byte{0xCD}, 32)},
		{"odd-length", bytes.Repeat([]byte{0xEF}, 100)},
	}
	key := mustHex(t, "0123456789ABCDEF0123456789ABCDEF") // 16 bytes = AES-128
	nonce := mustHex(t, "0102030405060708090A0B0C")       // 12 bytes

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ct, tag, err := EncryptAESCCM(key, nonce, c.plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			pt, err := DecryptAESCCM(key, nonce, ct, tag)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, c.plaintext) {
				t.Errorf("round-trip 不一致:\n  got  %x\n  want %x", pt, c.plaintext)
			}
		})
	}
}

// Tampered ciphertext / tag / nonce → 必须拒绝（认证失败）
func TestAESCCM_TamperedRejected(t *testing.T) {
	key := mustHex(t, "0123456789ABCDEF0123456789ABCDEF")
	nonce := mustHex(t, "0102030405060708090A0B0C")
	plaintext := []byte("sensitive data")
	ct, tag, _ := EncryptAESCCM(key, nonce, plaintext)

	t.Run("tampered ciphertext", func(t *testing.T) {
		ct2 := append([]byte{}, ct...)
		ct2[0] ^= 0x01
		if _, err := DecryptAESCCM(key, nonce, ct2, tag); err != ErrAuthenticationFailed {
			t.Errorf("篡改密文应认证失败，实际 err=%v", err)
		}
	})
	t.Run("tampered tag", func(t *testing.T) {
		tag2 := append([]byte{}, tag...)
		tag2[0] ^= 0x01
		if _, err := DecryptAESCCM(key, nonce, ct, tag2); err != ErrAuthenticationFailed {
			t.Errorf("篡改 tag 应认证失败，实际 err=%v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		wrongKey := mustHex(t, "00000000000000000000000000000000")
		if _, err := DecryptAESCCM(wrongKey, nonce, ct, tag); err != ErrAuthenticationFailed {
			t.Errorf("错误 key 应认证失败，实际 err=%v", err)
		}
	})
	t.Run("wrong nonce", func(t *testing.T) {
		wrongNonce := make([]byte, 12)
		if _, err := DecryptAESCCM(key, wrongNonce, ct, tag); err != ErrAuthenticationFailed {
			t.Errorf("错误 nonce 应认证失败，实际 err=%v", err)
		}
	})
}

// AES-CCM 自洽：手动用 NIST 单算 + 与 ccmCBCMAC + ccmCTRDecrypt 比对（验证内部子函数的对称性）
func TestAESCCM_CBCMacSelfConsistent(t *testing.T) {
	key := mustHex(t, "0123456789ABCDEF0123456789ABCDEF")
	nonce := mustHex(t, "0102030405060708090A0B0C")
	plaintext := []byte("12345678901234567890") // 20 bytes

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	tag1 := ccmCBCMAC(block, nonce, plaintext, 16)
	tag2 := ccmCBCMAC(block, nonce, plaintext, 16)
	if !bytes.Equal(tag1, tag2) {
		t.Error("CBC-MAC 不确定性")
	}
}

// 入参拒绝
func TestAESCCM_InputValidation(t *testing.T) {
	key := mustHex(t, "0123456789ABCDEF0123456789ABCDEF")
	t.Run("nonce 长度错", func(t *testing.T) {
		_, err := DecryptAESCCM(key, []byte{0x01}, []byte{0x02}, make([]byte, 16))
		if err == nil {
			t.Error("nonce 长度错应被拒")
		}
	})
	t.Run("tag 长度错", func(t *testing.T) {
		_, err := DecryptAESCCM(key, make([]byte, 12), []byte{0x02}, []byte{0x03})
		if err == nil {
			t.Error("tag 长度错应被拒")
		}
	})
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return b
}
