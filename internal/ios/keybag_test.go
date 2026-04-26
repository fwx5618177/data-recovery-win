package ios

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ============================================================================
// RFC 3394 官方测试向量 —— 权威验证 AES-KW 实现的正确性。
//
// 业界共识（NIST CAVP、openssl test suite、Apple CoreCrypto）：
// 自实现的加密原语**必须**过官方 test vector，再谈 round-trip。
// 单纯 roundtrip 只能保证 encode↔decode 配套，但可能相对标准错位（比如
// 端序、IV、迭代方向），在和其它实现互通时才暴露。
//
// RFC 3394 §4 的 6 组官方向量：
//   §4.1  KEK 128 / plain 128
//   §4.2  KEK 192 / plain 128
//   §4.3  KEK 256 / plain 128
//   §4.4  KEK 192 / plain 192
//   §4.5  KEK 256 / plain 192
//   §4.6  KEK 256 / plain 256   ← iOS 备份用的是这个
// ============================================================================

type kwVector struct {
	name    string
	kek     string // hex
	plain   string // hex
	wrapped string // hex
}

var rfc3394Vectors = []kwVector{
	{
		name:    "RFC3394 §4.1 (128/128)",
		kek:     "000102030405060708090A0B0C0D0E0F",
		plain:   "00112233445566778899AABBCCDDEEFF",
		wrapped: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
	},
	{
		name:    "RFC3394 §4.2 (192/128)",
		kek:     "000102030405060708090A0B0C0D0E0F1011121314151617",
		plain:   "00112233445566778899AABBCCDDEEFF",
		wrapped: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
	},
	{
		name:    "RFC3394 §4.3 (256/128)",
		kek:     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		plain:   "00112233445566778899AABBCCDDEEFF",
		wrapped: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
	},
	{
		name:    "RFC3394 §4.4 (192/192)",
		kek:     "000102030405060708090A0B0C0D0E0F1011121314151617",
		plain:   "00112233445566778899AABBCCDDEEFF0001020304050607",
		wrapped: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
	},
	{
		name:    "RFC3394 §4.5 (256/192)",
		kek:     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		plain:   "00112233445566778899AABBCCDDEEFF0001020304050607",
		wrapped: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
	},
	{
		name:    "RFC3394 §4.6 (256/256)",
		kek:     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		plain:   "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
		wrapped: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestAESKeyWrap_RFC3394Vectors(t *testing.T) {
	for _, v := range rfc3394Vectors {
		t.Run(v.name, func(t *testing.T) {
			kek := mustHex(t, v.kek)
			plain := mustHex(t, v.plain)
			want := mustHex(t, v.wrapped)

			got, err := AESKeyWrap(kek, plain)
			if err != nil {
				t.Fatalf("wrap: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("wrap mismatch\n  got  %x\n  want %x", got, want)
			}

			// 反向：unwrap 应拿回 plaintext
			back, err := AESKeyUnwrap(kek, want)
			if err != nil {
				t.Fatalf("unwrap: %v", err)
			}
			if !bytes.Equal(back, plain) {
				t.Errorf("unwrap mismatch\n  got  %x\n  want %x", back, plain)
			}
		})
	}
}

func TestAESKeyUnwrap_TamperedFails(t *testing.T) {
	kek := mustHex(t, rfc3394Vectors[5].kek)
	wrapped := mustHex(t, rfc3394Vectors[5].wrapped)

	// 翻转 wrapped 最后一个字节的一位 —— unwrap 必须检测并报错
	tampered := dup(wrapped)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := AESKeyUnwrap(kek, tampered); err == nil {
		t.Errorf("tampered ciphertext 应被 integrity check 拒绝")
	}
}

func TestAESKeyUnwrap_WrongKEKFails(t *testing.T) {
	kek := mustHex(t, rfc3394Vectors[5].kek)
	wrapped := mustHex(t, rfc3394Vectors[5].wrapped)

	wrongKEK := dup(kek)
	wrongKEK[0] ^= 0xFF
	if _, err := AESKeyUnwrap(wrongKEK, wrapped); err == nil {
		t.Errorf("错误的 KEK 应被 integrity check 拒绝")
	}
}

// ============================================================================
// Keybag TLV 解析测试
// ============================================================================

func buildKeybagTLV(tag string, value []byte) []byte {
	out := []byte(tag)
	var l [4]byte
	l[0] = byte(len(value) >> 24)
	l[1] = byte(len(value) >> 16)
	l[2] = byte(len(value) >> 8)
	l[3] = byte(len(value))
	out = append(out, l[:]...)
	out = append(out, value...)
	return out
}

func TestParseKeybag_Minimal(t *testing.T) {
	var blob []byte
	blob = append(blob, buildKeybagTLV("VERS", []byte{0, 0, 0, 4})...)          // v4
	blob = append(blob, buildKeybagTLV("TYPE", []byte{0, 0, 0, 1})...)          // Backup
	blob = append(blob, buildKeybagTLV("UUID", bytes.Repeat([]byte{0xAA}, 16))...)
	blob = append(blob, buildKeybagTLV("SALT", bytes.Repeat([]byte{0xBB}, 20))...)
	blob = append(blob, buildKeybagTLV("ITER", []byte{0, 0, 0x27, 0x10})...)    // 10000
	// 一个 class
	blob = append(blob, buildKeybagTLV("CLAS", []byte{0, 0, 0, 3})...)          // class 3
	blob = append(blob, buildKeybagTLV("KTYP", []byte{0, 0, 0, 0})...)          // AES
	blob = append(blob, buildKeybagTLV("WPKY", bytes.Repeat([]byte{0xCC}, 40))...)

	kb, err := ParseKeybag(blob)
	if err != nil {
		t.Fatalf("parse keybag: %v", err)
	}
	if kb.Version != 4 || kb.Type != 1 {
		t.Errorf("VERS/TYPE 错: %d %d", kb.Version, kb.Type)
	}
	if kb.Iter != 10000 {
		t.Errorf("ITER 错: %d", kb.Iter)
	}
	if len(kb.Classes) != 1 || kb.Classes[0].Class != 3 {
		t.Errorf("class 错: %+v", kb.Classes)
	}
	if len(kb.Classes[0].WrappedKey) != 40 {
		t.Errorf("WPKY 长度错")
	}
}

func TestParseKeybag_RejectsEmpty(t *testing.T) {
	_, err := ParseKeybag(nil)
	if err == nil {
		t.Error("空 keybag 应被拒绝")
	}
}

func TestParseKeybag_MissingSaltRejected(t *testing.T) {
	// 没 SALT/ITER 的 keybag 不能 unlock，必须拒绝
	blob := buildKeybagTLV("VERS", []byte{0, 0, 0, 4})
	_, err := ParseKeybag(blob)
	if err == nil {
		t.Error("缺 SALT/ITER 应返回错误")
	}
}

func TestKeybag_UnlockWithRealPBKDF2(t *testing.T) {
	// 端到端：构造一个已知 password → 我们自己计算正确 unlock-key → AESKeyWrap 一个 class key →
	// 装进 keybag → Unlock 应能还原
	password := "testpass"
	// 用标准库 PBKDF2 算一个 unlock key
	saltLen := 20
	salt := bytes.Repeat([]byte{0x11}, saltLen)
	iter := uint32(500) // 测试用低轮次避免测试慢
	unlockKey := pbkdf2HelperSingle([]byte(password), salt, int(iter), 32)

	// Class key：随机 32 字节（固定以便可重复）
	classKey := bytes.Repeat([]byte{0x42}, 32)
	wrapped, err := AESKeyWrap(unlockKey, classKey)
	if err != nil {
		t.Fatal(err)
	}

	// 组装 keybag
	var blob []byte
	blob = append(blob, buildKeybagTLV("VERS", []byte{0, 0, 0, 4})...)
	blob = append(blob, buildKeybagTLV("TYPE", []byte{0, 0, 0, 1})...)
	blob = append(blob, buildKeybagTLV("UUID", bytes.Repeat([]byte{0xDD}, 16))...)
	blob = append(blob, buildKeybagTLV("SALT", salt)...)
	// ITER 4 字节 BE
	var iterBE [4]byte
	iterBE[0] = byte(iter >> 24)
	iterBE[1] = byte(iter >> 16)
	iterBE[2] = byte(iter >> 8)
	iterBE[3] = byte(iter)
	blob = append(blob, buildKeybagTLV("ITER", iterBE[:])...)
	blob = append(blob, buildKeybagTLV("CLAS", []byte{0, 0, 0, 3})...)
	blob = append(blob, buildKeybagTLV("KTYP", []byte{0, 0, 0, 0})...)
	blob = append(blob, buildKeybagTLV("WPKY", wrapped)...)

	kb, err := ParseKeybag(blob)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kb.Unlock(password)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	got := keys[3]
	if !bytes.Equal(got, classKey) {
		t.Errorf("class 3 key mismatch\n  got  %x\n  want %x", got, classKey)
	}
}

func TestKeybag_WrongPasswordFails(t *testing.T) {
	// 同样构造一个 keybag，用错密码应返回 err
	salt := bytes.Repeat([]byte{0x22}, 20)
	iter := uint32(500)
	unlockKey := pbkdf2HelperSingle([]byte("correctpass"), salt, int(iter), 32)
	wrapped, _ := AESKeyWrap(unlockKey, bytes.Repeat([]byte{0x33}, 32))

	var blob []byte
	blob = append(blob, buildKeybagTLV("SALT", salt)...)
	blob = append(blob, buildKeybagTLV("ITER", []byte{0, 0, 0x01, 0xF4})...) // 500
	blob = append(blob, buildKeybagTLV("CLAS", []byte{0, 0, 0, 3})...)
	blob = append(blob, buildKeybagTLV("WPKY", wrapped)...)

	kb, err := ParseKeybag(blob)
	if err != nil {
		t.Fatal(err)
	}
	_, err = kb.Unlock("wrongpass")
	if err == nil {
		t.Error("错误密码应 Unlock 失败")
	}
}
