package android

import (
	"archive/tar"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"testing"
)

// 端到端：构造 tar → zlib 压缩 → AES-CBC 加密 → 跑 OpenPayloadReader 解出来。
// 这是 .ab 完整解码链路的真验证。
func TestOpenPayloadReader_FullDecodeChain(t *testing.T) {
	// 1) 写一个有两个文件的 tar 流
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	files := map[string][]byte{
		"apps/com.example/files/note.txt": []byte("Hello from Android backup\n这里是中文"),
		"apps/com.example/files/data.bin": bytes.Repeat([]byte{0x42}, 4096),
	}
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	// 2) zlib 压缩
	var zBuf bytes.Buffer
	zw := zlib.NewWriter(&zBuf)
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// 3) AES-CBC 加密 + PKCS7 padding
	key := bytes.Repeat([]byte{0x55}, 32)
	iv := bytes.Repeat([]byte{0x33}, 16)
	plaintext := pkcs7Pad(zBuf.Bytes(), aes.BlockSize)
	block, _ := aes.NewCipher(key)
	enc := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(plaintext))
	enc.CryptBlocks(encrypted, plaintext)

	// 4) OpenPayloadReader：解密 + 解压
	header := &ABHeader{
		Version: 4, IsCompressed: true, Encryption: "AES-256",
	}
	master := &MasterKey{IV: iv, Key: key}

	rc, err := OpenPayloadReader(bytes.NewReader(encrypted), header, master)
	if err != nil {
		t.Fatalf("OpenPayloadReader: %v", err)
	}
	defer rc.Close()

	// 5) tar 解出来
	tr := tar.NewReader(rc)
	got := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar Next: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		buf, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar Read: %v", err)
		}
		got[hdr.Name] = buf
	}

	if len(got) != len(files) {
		t.Errorf("文件数量: got %d, want %d", len(got), len(files))
	}
	for name, want := range files {
		gotData, ok := got[name]
		if !ok {
			t.Errorf("缺少文件 %s", name)
			continue
		}
		if !bytes.Equal(gotData, want) {
			t.Errorf("文件 %s 内容不对", name)
		}
	}
}

// 测试无加密 + 无压缩的最简路径
func TestOpenPayloadReader_PlainTar(t *testing.T) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	tw.WriteHeader(&tar.Header{Name: "x.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
	tw.Write([]byte("hello"))
	tw.Close()

	header := &ABHeader{Version: 4, IsCompressed: false, Encryption: "none"}
	rc, err := OpenPayloadReader(bytes.NewReader(tarBuf.Bytes()), header, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("tar Next: %v", err)
	}
	if hdr.Name != "x.txt" {
		t.Errorf("name 错")
	}
}

// 加密但不压缩
func TestOpenPayloadReader_EncryptedNoCompression(t *testing.T) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	tw.WriteHeader(&tar.Header{Name: "y.bin", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	tw.Write([]byte{0x01, 0x02, 0x03})
	tw.Close()

	key := bytes.Repeat([]byte{0x77}, 32)
	iv := bytes.Repeat([]byte{0x88}, 16)
	plain := pkcs7Pad(tarBuf.Bytes(), aes.BlockSize)
	block, _ := aes.NewCipher(key)
	enc := cipher.NewCBCEncrypter(block, iv)
	enct := make([]byte, len(plain))
	enc.CryptBlocks(enct, plain)

	header := &ABHeader{
		Version: 4, IsCompressed: false, Encryption: "AES-256",
	}
	rc, err := OpenPayloadReader(bytes.NewReader(enct), header, &MasterKey{Key: key, IV: iv})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("tar Next: %v", err)
	}
	if hdr.Name != "y.bin" {
		t.Errorf("name 错: %q", hdr.Name)
	}
}

func TestOpenPayloadReader_RejectsMissingMasterKey(t *testing.T) {
	header := &ABHeader{Version: 4, Encryption: "AES-256", IsCompressed: false}
	if _, err := OpenPayloadReader(bytes.NewReader([]byte{1, 2, 3}), header, nil); err == nil {
		t.Errorf("加密 backup 不传 master key 应失败")
	}
}
