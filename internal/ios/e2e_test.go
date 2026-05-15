package ios

// ============================================================================
// 端到端加密备份测试
//
// 构造一份完整"加密备份"的内存 fixture，跑一遍：
//   password → keybag unlock → class key → file key → AES-CBC decrypt → 明文
//
// 这是对"整条解密链"的 contract check，比单元测试更能防回归。
// ============================================================================

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"crypto/sha1"
	"golang.org/x/crypto/pbkdf2"
)

// 把 plaintext 按 iOS 备份用的 CBC(IV=0) + PKCS7 加密
func encryptCBCZeroIVWithPadding(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	// PKCS#7 padding
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(padLen)}, padLen)...)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aes.BlockSize) // 全 0 IV
	enc := cipher.NewCBCEncrypter(block, iv)
	out := make([]byte, len(padded))
	enc.CryptBlocks(out, padded)
	return out
}

func TestIOSBackup_EndToEndDecryption(t *testing.T) {
	const password = "Hunter2!"

	// --- 1. 生成一个 class 3 的 file key（"Protected Until First Login" 等价的简化版）
	classKey := make([]byte, 32)
	_, _ = rand.Read(classKey)

	// --- 2. 用随机 salt / 低 iteration 算 unlock key（测试场景，生产用 10 万+）
	salt := bytes.Repeat([]byte{0xA5}, 20)
	iter := uint32(500)
	unlockKey := pbkdf2.Key([]byte(password), salt, int(iter), 32, sha1.New)

	// --- 3. 用 unlockKey wrap 出 class 3 的 WPKY
	wpky, err := AESKeyWrap(unlockKey, classKey)
	if err != nil {
		t.Fatalf("wrap class key: %v", err)
	}

	// --- 4. 构造一个单文件：file key 随机；用 class3 wrap；明文随便一串
	fileKey := make([]byte, 32)
	_, _ = rand.Read(fileKey)
	wrappedFileKey, err := AESKeyWrap(classKey, fileKey)
	if err != nil {
		t.Fatal(err)
	}
	// EncryptionKey 字段 = class_id(4B LE) + wrapped(40B)
	var encKeyField [44]byte
	binary.LittleEndian.PutUint32(encKeyField[:4], 3)
	copy(encKeyField[4:], wrappedFileKey)

	plaintext := []byte("The quick brown fox jumps over the lazy dog — 测试一段中文 Unicode 混合内容")
	ciphertext := encryptCBCZeroIVWithPadding(t, fileKey, plaintext)

	// --- 5. 写"加密备份文件"到临时位置
	tmpDir := t.TempDir()
	// iOS 备份按 FileID 前 2 字节分桶
	fileID := "abcdef0123456789abcdef0123456789abcdef01"
	bucketDir := filepath.Join(tmpDir, fileID[:2])
	if err := os.MkdirAll(bucketDir, 0o755); err != nil {
		t.Fatal(err)
	}
	encFilePath := filepath.Join(bucketDir, fileID)
	if err := os.WriteFile(encFilePath, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}

	// --- 6. 构造 keybag (TLV)
	var kbBlob []byte
	put := func(tag string, val []byte) {
		kbBlob = append(kbBlob, buildKeybagTLV(tag, val)...)
	}
	be32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b
	}
	put("VERS", be32(4))
	put("TYPE", be32(1))
	put("UUID", bytes.Repeat([]byte{0xDE}, 16))
	put("SALT", salt)
	put("ITER", be32(iter))
	put("CLAS", be32(3))
	put("KTYP", be32(0))
	put("WPKY", wpky)

	kb, err := ParseKeybag(kbBlob)
	if err != nil {
		t.Fatalf("parse keybag: %v", err)
	}

	// --- 7. Unlock
	classKeys, err := kb.Unlock(password)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	recovered := classKeys[3]
	if !bytes.Equal(recovered, classKey) {
		t.Fatalf("class 3 key 还原失败")
	}

	// --- 8. 用 session.RecoverFile 的底层 DecryptBackupFile 解密
	outPath := filepath.Join(tmpDir, "out.txt")
	n, err := DecryptBackupFile(encFilePath, outPath, FileRecord{
		FileID:        fileID,
		EncryptionKey: encKeyField[:],
	}, classKeys)
	if err != nil {
		t.Fatalf("decrypt backup file: %v", err)
	}
	if int(n) != len(plaintext) {
		t.Errorf("解密后长度错: got %d want %d", n, len(plaintext))
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("解密后内容不对\n  got:  %q\n  want: %q", got, plaintext)
	}
}

func TestIOSBackup_EndToEnd_WrongPasswordRejected(t *testing.T) {
	classKey := bytes.Repeat([]byte{0x99}, 32)
	salt := bytes.Repeat([]byte{0x11}, 20)
	iter := uint32(500)
	unlockKey := pbkdf2.Key([]byte("correct-pass"), salt, int(iter), 32, sha1.New)
	wpky, _ := AESKeyWrap(unlockKey, classKey)

	var kbBlob []byte
	be32 := func(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
	put := func(tag string, val []byte) { kbBlob = append(kbBlob, buildKeybagTLV(tag, val)...) }
	put("SALT", salt)
	put("ITER", be32(iter))
	put("CLAS", be32(3))
	put("WPKY", wpky)

	kb, err := ParseKeybag(kbBlob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kb.Unlock("wrong-pass"); err == nil {
		t.Error("错误密码应被拒绝")
	}
}

func TestIOSBackup_PKCS7Validation(t *testing.T) {
	// 非法 padding 必须报错（不能悄悄截断给用户看似"有内容"的数据）
	cases := [][]byte{
		{}, // 0 长度 OK（空文件）
	}
	for _, c := range cases {
		if _, err := removePKCS7Padding(c); err != nil {
			t.Errorf("0 长度不应报错")
		}
	}
	// 非法: padding 字节不一致
	bad := []byte{0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0xFF}
	if _, err := removePKCS7Padding(bad); err == nil {
		t.Errorf("padding 不一致应被拒")
	}
	// 非法: pad=0
	if _, err := removePKCS7Padding([]byte{0x00}); err == nil {
		t.Errorf("pad=0 应被拒")
	}
	// 非法: pad > blocksize
	if _, err := removePKCS7Padding([]byte{0x11}); err == nil {
		t.Errorf("pad > 16 应被拒")
	}
}
