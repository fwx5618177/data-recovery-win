package android

import (
	"archive/tar"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// 构造一份完整的"加密 .ab"测试 fixture（写到磁盘临时文件），跑 Session 端到端。

func writeFixtureAB(t *testing.T, dir string, password string, files map[string][]byte) string {
	t.Helper()

	// 1) tar
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, data := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		tw.Write(data)
	}
	tw.Close()

	// 2) zlib 压缩
	var zBuf bytes.Buffer
	zw := zlib.NewWriter(&zBuf)
	zw.Write(tarBuf.Bytes())
	zw.Close()

	// 3) AES-CBC 加密 master_key+IV
	masterKey := bytes.Repeat([]byte{0xAA}, 32)
	masterIV := bytes.Repeat([]byte{0xBB}, 16)
	plain := pkcs7Pad(zBuf.Bytes(), aes.BlockSize)
	block, _ := aes.NewCipher(masterKey)
	enc := cipher.NewCBCEncrypter(block, masterIV)
	encryptedPayload := make([]byte, len(plain))
	enc.CryptBlocks(encryptedPayload, plain)

	// 4) 用 password → user_key 加密 master key blob
	const rounds = 1000
	userSalt := bytes.Repeat([]byte{0x11}, 64)
	checksumSalt := bytes.Repeat([]byte{0x22}, 64)
	userIV := bytes.Repeat([]byte{0x33}, 16)
	userKey := pbkdf2.Key([]byte(password), userSalt, rounds, 32, sha1.New)
	checksum := pbkdf2.Key(encodeMasterKeyAsChars(masterKey), checksumSalt, rounds, 32, sha1.New)

	var blob bytes.Buffer
	blob.WriteByte(byte(len(masterIV)))
	blob.Write(masterIV)
	blob.WriteByte(byte(len(masterKey)))
	blob.Write(masterKey)
	blob.WriteByte(byte(len(checksum)))
	blob.Write(checksum)

	blobPlain := pkcs7Pad(blob.Bytes(), aes.BlockSize)
	blockUK, _ := aes.NewCipher(userKey)
	encUK := cipher.NewCBCEncrypter(blockUK, userIV)
	encryptedBlob := make([]byte, len(blobPlain))
	encUK.CryptBlocks(encryptedBlob, blobPlain)

	// 5) 写头部
	var header strings.Builder
	header.WriteString("ANDROID BACKUP\n")
	header.WriteString("4\n")
	header.WriteString("1\n")
	header.WriteString("AES-256\n")
	header.WriteString(hex.EncodeToString(userSalt) + "\n")
	header.WriteString(hex.EncodeToString(checksumSalt) + "\n")
	header.WriteString("1000\n")
	header.WriteString(hex.EncodeToString(userIV) + "\n")
	header.WriteString(hex.EncodeToString(encryptedBlob) + "\n")

	// 6) 落到磁盘
	abPath := filepath.Join(dir, "test.ab")
	full := append([]byte(header.String()), encryptedPayload...)
	if err := os.WriteFile(abPath, full, 0o600); err != nil {
		t.Fatal(err)
	}
	return abPath
}

func TestSession_EndToEnd_EncryptedBackup(t *testing.T) {
	const password = "MyPhonePin0000"
	files := map[string][]byte{
		"apps/com.example/files/note.txt":    []byte("从 Android 备份里恢复出来的笔记"),
		"apps/com.example/databases/main.db": bytes.Repeat([]byte{0x42}, 4096),
		"shared/0/Pictures/IMG_001.jpg":      bytes.Repeat([]byte{0xCC}, 1024),
	}

	tmpDir := t.TempDir()
	abPath := writeFixtureAB(t, tmpDir, password, files)

	// 1) 没密码先试
	if _, err := DialBackup(context.Background(), abPath, ""); err != ErrEncrypted {
		t.Errorf("没密码应返回 ErrEncrypted, got %v", err)
	}

	// 2) 错密码
	if _, err := DialBackup(context.Background(), abPath, "wrongpass"); err == nil {
		t.Errorf("错密码应失败")
	}

	// 3) 对密码
	b, err := DialBackup(context.Background(), abPath, password)
	if err != nil {
		t.Fatalf("对密码 dial 失败: %v", err)
	}
	defer b.Close()

	// 4) 枚举
	var entries []ABEntry
	if err := b.EnumerateFiles(context.Background(), func(e ABEntry) {
		entries = append(entries, e)
	}); err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(entries) != len(files) {
		t.Errorf("entry 数: got %d, want %d", len(entries), len(files))
	}

	// 5) 一次性批量恢复
	outDir := t.TempDir()
	items := []recoverItem{}
	for name := range files {
		items = append(items, recoverItem{
			Name: name,
			Out:  filepath.Join(outDir, name),
		})
	}
	if err := b.RecoverMany(context.Background(), items); err != nil {
		t.Fatalf("RecoverMany: %v", err)
	}

	// 6) 校验内容
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Errorf("读 %s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s 内容不对", name)
		}
	}
}

func TestSession_PlainTar(t *testing.T) {
	// 写一个 不加密 + 不压缩 的最简 .ab
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	tw.WriteHeader(&tar.Header{Name: "x.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
	tw.Write([]byte("hello"))
	tw.Close()

	header := "ANDROID BACKUP\n4\n0\nnone\n"
	full := append([]byte(header), tarBuf.Bytes()...)
	abPath := filepath.Join(t.TempDir(), "plain.ab")
	if err := os.WriteFile(abPath, full, 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := DialBackup(context.Background(), abPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	var found ABEntry
	b.EnumerateFiles(context.Background(), func(e ABEntry) { found = e })
	if found.Name != "x.txt" || found.Size != 5 {
		t.Errorf("entry 错: %+v", found)
	}

	out := filepath.Join(t.TempDir(), "out.txt")
	if err := b.RecoverFile(context.Background(), "x.txt", out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "hello" {
		t.Errorf("recover 错: %q", got)
	}
}

func TestAppDomainFromPath(t *testing.T) {
	cases := map[string]string{
		"apps/com.android.providers.contacts/db/contacts2.db": "com.android.providers.contacts",
		"apps/com.whatsapp/files/log.txt":                     "com.whatsapp",
		"shared/0/Pictures/img.jpg":                           "shared(共享存储)",
		"unrelated/path":                                      "(其它)",
	}
	for in, want := range cases {
		if got := AppDomainFromPath(in); got != want {
			t.Errorf("AppDomainFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// 测试覆盖：流式解密器读到 EOF 时去 padding 必须正确
func TestCBCStreamDecrypter_TailPadding(t *testing.T) {
	key := bytes.Repeat([]byte{0x99}, 32)
	iv := bytes.Repeat([]byte{0xAA}, 16)
	plain := []byte("Hello, World! 数据恢复测试. " + strings.Repeat("X", 100))
	padded := pkcs7Pad(plain, aes.BlockSize)

	block, _ := aes.NewCipher(key)
	enc := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(padded))
	enc.CryptBlocks(encrypted, padded)

	d, _ := newCBCStreamDecrypter(bytes.NewReader(encrypted), key, iv)
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("CBC 流尾部 padding 处理错")
	}
}
