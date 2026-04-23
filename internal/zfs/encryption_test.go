package zfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// RFC 3394 A.1 test vector: AES-128 Key Wrap
// 虽然本代码用 AES-256，但 RFC 3394 算法相同，A.2 是 256-bit KEK
func TestUnwrapMasterKey_RFC3394_A2(t *testing.T) {
	// RFC 3394 Section 4.2 测试向量 (AES-256 wrap 128-bit key)
	// 但我们的 UnwrapMasterKey 只解 AES-256 KEK；这里构造自己的 round-trip
	// （用 AES-256 wrap 一个 256-bit key，再 unwrap，应等原值）

	// 手工 AES-256 Wrap（RFC 3394 forward）
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	plaintext, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF0001020304050607")
	expectedWrapped, _ := hex.DecodeString(
		"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")
	// 这个向量是 RFC 3394 Section 4.4 (AES-256 wrap 192-bit key)

	// 用 wrapped → unwrap → 应得 plaintext
	mk, err := UnwrapMasterKey(kek, expectedWrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(mk, plaintext) {
		t.Errorf("unwrap 不匹配\n got %x\nwant %x", mk, plaintext)
	}
}

// 端到端 AES-GCM round-trip：encrypt with known DEK/IV/AAD → decrypt → compare
func TestDecryptDataBlockAESGCM_RoundTrip(t *testing.T) {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	iv := []byte("123456789012")        // 12 bytes
	aad := []byte("ZFS-BP-header-aad")
	plaintext := []byte("这是 ZFS 加密池里的秘密数据 secret payload")

	// 先用 Go 标准 GCM encrypt
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCMWithNonceSize(block, 12)
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	// sealed = ciphertext || tag（16 字节）
	ciphertext := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]

	// 再用我们的函数 decrypt
	got, err := DecryptDataBlockAESGCM(dek, ciphertext, iv, tag, aad)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip:\n got %s\nwant %s", got, plaintext)
	}
}

// 密码错误场景 → unwrap 应失败
func TestUnwrapMasterKey_WrongPassword(t *testing.T) {
	wrongKEK := make([]byte, 32) // 全零错误 KEK
	// 随便一个 wrapped key（合法 RFC 3394 vector）
	wrapped, _ := hex.DecodeString(
		"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")

	_, err := UnwrapMasterKey(wrongKEK, wrapped)
	if err == nil {
		t.Error("错误 KEK 应当 unwrap 失败")
	}
}

// PBKDF2 一致性：相同 password + salt 应始终产出同 WK
func TestDeriveWrappingKey_Deterministic(t *testing.T) {
	wk1 := DeriveWrappingKey([]byte("mypassword"), []byte("testsalt"))
	wk2 := DeriveWrappingKey([]byte("mypassword"), []byte("testsalt"))
	if !bytes.Equal(wk1, wk2) {
		t.Error("PBKDF2 不稳定")
	}
	if len(wk1) != 32 {
		t.Errorf("WK 长度应 32，got %d", len(wk1))
	}
}

// HKDF 派生确定性 + 不同 info 给不同 DEK
func TestDeriveDEK_DifferentInfoDifferentKeys(t *testing.T) {
	mk := make([]byte, 32)
	for i := range mk {
		mk[i] = byte(i)
	}
	dek1, err := DeriveDEK(mk, []byte("salt"), []byte("info-A"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	dek2, err := DeriveDEK(mk, []byte("salt"), []byte("info-B"))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if bytes.Equal(dek1, dek2) {
		t.Error("不同 info 应产出不同 DEK")
	}
	// 同参数确定性
	dek1b, _ := DeriveDEK(mk, []byte("salt"), []byte("info-A"))
	if !bytes.Equal(dek1, dek1b) {
		t.Error("HKDF 不稳定")
	}
}

// ExtractCryptoFromBP: IV 12 + Tag 16 从 Cksum 抽
func TestExtractCryptoFromBP(t *testing.T) {
	bp := &BlockPointer{}
	for i := range bp.Cksum {
		bp.Cksum[i] = byte(i)
	}
	iv, tag := ExtractCryptoFromBP(bp)
	if len(iv) != 12 || len(tag) != 16 {
		t.Errorf("长度: iv=%d tag=%d", len(iv), len(tag))
	}
	if iv[0] != 0 || iv[11] != 11 {
		t.Errorf("IV 错: %x", iv)
	}
	if tag[0] != 16 || tag[15] != 31 {
		t.Errorf("Tag 错: %x", tag)
	}
	_ = binary.LittleEndian // silence unused
}
