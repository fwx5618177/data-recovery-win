package android

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// 端到端测试：构造一个完整的加密 backup header（用我们自己的 encryptor 反向构造），
// 然后用 DeriveAndDecryptMasterKey 解出来，验证 master_key 正确。

func buildEncryptedHeader(t *testing.T, password string, version int, masterKey, masterIV []byte) *ABHeader {
	t.Helper()

	// 测试用低轮次以保证 < 1s
	const rounds = 1000

	userSalt := bytes.Repeat([]byte{0xA1}, 64)
	checksumSalt := bytes.Repeat([]byte{0xC2}, 64)
	userIV := bytes.Repeat([]byte{0xE3}, 16)

	// 1) user_key = PBKDF2(password, userSalt, rounds, 32)
	userKey := pbkdf2.Key([]byte(password), userSalt, rounds, 32, sha1.New)

	// 2) checksum = PBKDF2(encoded master_key, checksumSalt, rounds, 32)
	var pwd []byte
	if version >= 3 {
		pwd = encodeMasterKeyAsChars(masterKey)
	} else {
		pwd = masterKey
	}
	checksum := pbkdf2.Key(pwd, checksumSalt, rounds, 32, sha1.New)

	// 3) blob = [1B len][iv][1B len][key][1B len][checksum]
	var blob bytes.Buffer
	blob.WriteByte(byte(len(masterIV)))
	blob.Write(masterIV)
	blob.WriteByte(byte(len(masterKey)))
	blob.Write(masterKey)
	blob.WriteByte(byte(len(checksum)))
	blob.Write(checksum)

	plain := pkcs7Pad(blob.Bytes(), aes.BlockSize)

	// 4) 用 user_key + userIV 加密 blob
	block, _ := aes.NewCipher(userKey)
	enc := cipher.NewCBCEncrypter(block, userIV)
	encrypted := make([]byte, len(plain))
	enc.CryptBlocks(encrypted, plain)

	return &ABHeader{
		Version:               version,
		IsCompressed:          true,
		Encryption:            "AES-256",
		UserPasswordSalt:      userSalt,
		MasterKeyChecksumSalt: checksumSalt,
		PBKDF2Rounds:          rounds,
		UserKeyIV:             userIV,
		MasterKeyBlob:         encrypted,
	}
}

func pkcs7Pad(in []byte, block int) []byte {
	pad := block - len(in)%block
	out := make([]byte, len(in)+pad)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func TestDeriveAndDecryptMasterKey_v4(t *testing.T) {
	const password = "Hunter2!"
	mk := bytes.Repeat([]byte{0x42}, 32)
	mkIV := bytes.Repeat([]byte{0x55}, 16)

	h := buildEncryptedHeader(t, password, 4, mk, mkIV)
	got, err := DeriveAndDecryptMasterKey(h, password)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !bytes.Equal(got.Key, mk) {
		t.Errorf("master key mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got.Key), hex.EncodeToString(mk))
	}
	if !bytes.Equal(got.IV, mkIV) {
		t.Errorf("master iv mismatch")
	}
}

func TestDeriveAndDecryptMasterKey_v1(t *testing.T) {
	// v1/v2 走"原始字节作 password"路径
	const password = "1234"
	mk := bytes.Repeat([]byte{0x99}, 32)
	mkIV := bytes.Repeat([]byte{0xBB}, 16)

	h := buildEncryptedHeader(t, password, 1, mk, mkIV)
	got, err := DeriveAndDecryptMasterKey(h, password)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !bytes.Equal(got.Key, mk) {
		t.Errorf("v1 master key mismatch")
	}
}

func TestDeriveAndDecryptMasterKey_WrongPassword(t *testing.T) {
	mk := bytes.Repeat([]byte{0x33}, 32)
	mkIV := bytes.Repeat([]byte{0x44}, 16)
	h := buildEncryptedHeader(t, "correct", 4, mk, mkIV)

	if _, err := DeriveAndDecryptMasterKey(h, "wrong"); err == nil {
		t.Errorf("错误密码应失败")
	}
}

func TestDeriveAndDecryptMasterKey_NonEncryptedHeaderRejected(t *testing.T) {
	h := &ABHeader{Encryption: "none"}
	if _, err := DeriveAndDecryptMasterKey(h, "any"); err == nil {
		t.Errorf("非加密 backup 不该走解密路径")
	}
}

func TestEncodeMasterKeyAsChars(t *testing.T) {
	// 确认 UTF-8 扩展规则：0x00..0x7F → 1B；0x80..0xFF → 2B
	in := []byte{0x00, 0x41, 0x7F, 0x80, 0xFF}
	out := encodeMasterKeyAsChars(in)
	// 0x00 → 0x00 (1B)
	// 0x41 → 0x41 (1B)
	// 0x7F → 0x7F (1B)
	// 0x80 → 0xC2 0x80 (2B)
	// 0xFF → 0xC3 0xBF (2B)
	want := []byte{0x00, 0x41, 0x7F, 0xC2, 0x80, 0xC3, 0xBF}
	if !bytes.Equal(out, want) {
		t.Errorf("encode wrong:\n  got  %x\n  want %x", out, want)
	}
}

func TestPKCS7Unpad_Valid(t *testing.T) {
	b, err := pkcs7Unpad([]byte{0x01, 0x02, 0x03, 0x05, 0x05, 0x05, 0x05, 0x05})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("pkcs7 unpad: got %x", b)
	}
}

func TestPKCS7Unpad_Invalid(t *testing.T) {
	cases := [][]byte{
		{},                                   // 空
		{0x00},                               // pad=0
		{0xFF},                               // pad>16
		{0x01, 0x02, 0x05, 0x05, 0x05, 0x04}, // 不一致
	}
	for i, c := range cases {
		if _, err := pkcs7Unpad(c); err == nil {
			t.Errorf("case %d 应被拒", i)
		}
	}
}
