package android

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseHeader_NoEncryption(t *testing.T) {
	header := "ANDROID BACKUP\n4\n1\nnone\n"
	payload := []byte{0x78, 0x9c, 0xff, 0xff} // 假装的 deflate 起头

	full := append([]byte(header), payload...)
	h, err := ParseHeader(bytes.NewReader(full))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.Version != 4 {
		t.Errorf("version: got %d, want 4", h.Version)
	}
	if !h.IsCompressed {
		t.Errorf("expected compressed=true")
	}
	if h.IsEncrypted() {
		t.Errorf("不应识别为加密")
	}
	if int(h.PayloadOffset) != len(header) {
		t.Errorf("PayloadOffset: got %d, want %d", h.PayloadOffset, len(header))
	}
}

func TestParseHeader_AES256(t *testing.T) {
	salt1 := bytes.Repeat([]byte{0xAA}, 64)
	salt2 := bytes.Repeat([]byte{0xBB}, 64)
	iv := bytes.Repeat([]byte{0xCC}, 16)
	blob := bytes.Repeat([]byte{0xDD}, 80)

	var sb strings.Builder
	sb.WriteString("ANDROID BACKUP\n")
	sb.WriteString("3\n")
	sb.WriteString("1\n")
	sb.WriteString("AES-256\n")
	sb.WriteString(hex.EncodeToString(salt1) + "\n")
	sb.WriteString(hex.EncodeToString(salt2) + "\n")
	sb.WriteString("10000\n")
	sb.WriteString(hex.EncodeToString(iv) + "\n")
	sb.WriteString(hex.EncodeToString(blob) + "\n")

	full := append([]byte(sb.String()), 0x01, 0x02, 0x03)
	h, err := ParseHeader(bytes.NewReader(full))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !h.IsEncrypted() {
		t.Errorf("应识别为加密")
	}
	if h.PBKDF2Rounds != 10000 {
		t.Errorf("rounds: got %d", h.PBKDF2Rounds)
	}
	if !bytes.Equal(h.UserPasswordSalt, salt1) {
		t.Errorf("user salt 不匹配")
	}
	if !bytes.Equal(h.MasterKeyChecksumSalt, salt2) {
		t.Errorf("checksum salt 不匹配")
	}
	if !bytes.Equal(h.UserKeyIV, iv) {
		t.Errorf("iv 不匹配")
	}
	if !bytes.Equal(h.MasterKeyBlob, blob) {
		t.Errorf("master key blob 不匹配")
	}
}

func TestParseHeader_RejectsUnknownEncryption(t *testing.T) {
	header := "ANDROID BACKUP\n4\n1\nXOR-42\n"
	if _, err := ParseHeader(strings.NewReader(header)); err == nil {
		t.Errorf("未知 ENCRYPTION 应被拒绝")
	}
}

func TestParseHeader_RejectsBadVersion(t *testing.T) {
	for _, ver := range []string{"0", "99", "abc"} {
		header := "ANDROID BACKUP\n" + ver + "\n1\nnone\n"
		if _, err := ParseHeader(strings.NewReader(header)); err == nil {
			t.Errorf("version=%q 应被拒绝", ver)
		}
	}
}

func TestParseHeader_RejectsBadMagic(t *testing.T) {
	header := "DROID BACKUP\n4\n1\nnone\n"
	if _, err := ParseHeader(strings.NewReader(header)); err == nil {
		t.Errorf("错误 magic 应被拒绝")
	}
}

func TestParseHeader_HandlesCRLF(t *testing.T) {
	// AOSP 某些版本会写 \r\n —— 必须容错
	header := "ANDROID BACKUP\r\n4\r\n0\r\nnone\r\n"
	h, err := ParseHeader(strings.NewReader(header))
	if err != nil {
		t.Fatalf("CRLF 头不应失败: %v", err)
	}
	if h.IsCompressed {
		t.Errorf("compressed 应为 false")
	}
}
