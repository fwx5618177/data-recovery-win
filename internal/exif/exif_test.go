package exif

import (
	"encoding/binary"
	"testing"
	"time"
)

// 合成最小 JPEG + EXIF：SOI + APP1 (Exif) + TIFF + IFD0 含 DateTime + EOI
func makeJPEGWithDateTime(dateStr string) []byte {
	tiff := []byte{}
	// TIFF header (LE): "II" + 0x002A + 4-byte IFD0 offset (8)
	tiff = append(tiff, 'I', 'I')
	tiff = append(tiff, 0x2A, 0x00)
	tiff = append(tiff, 0x08, 0x00, 0x00, 0x00) // IFD0 @ offset 8 (相对 TIFF 起点)

	// IFD0：1 entry + next IFD = 0
	const dateValueOffset = 8 + 2 + 12 + 4 // IFD0 entry table 后面就是 value 区
	ifd0 := []byte{}
	ifd0 = append(ifd0, 0x01, 0x00) // num entries = 1
	// entry: tag=0x0132, type=2 (ASCII), count=20, value_offset
	ifd0 = append(ifd0, 0x32, 0x01)
	ifd0 = append(ifd0, 0x02, 0x00)
	count := uint32(20)
	cb := make([]byte, 4)
	binary.LittleEndian.PutUint32(cb, count)
	ifd0 = append(ifd0, cb...)
	vb := make([]byte, 4)
	binary.LittleEndian.PutUint32(vb, dateValueOffset)
	ifd0 = append(ifd0, vb...)
	// next IFD
	ifd0 = append(ifd0, 0x00, 0x00, 0x00, 0x00)

	tiff = append(tiff, ifd0...)
	// value 区：dateStr + 1 字节 \0 + padding 到 20
	dateBytes := make([]byte, 20)
	copy(dateBytes, []byte(dateStr))
	tiff = append(tiff, dateBytes...)

	// APP1 payload = "Exif\0\0" + tiff
	app1 := append([]byte("Exif\x00\x00"), tiff...)

	// JPEG: SOI + APP1 marker + length + payload + EOI
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE1}
	segLen := uint16(len(app1) + 2)
	lb := []byte{byte(segLen >> 8), byte(segLen)}
	jpeg = append(jpeg, lb...)
	jpeg = append(jpeg, app1...)
	jpeg = append(jpeg, 0xFF, 0xD9)
	return jpeg
}

func TestExtractDateTime_FromIFD0(t *testing.T) {
	jpeg := makeJPEGWithDateTime("2023:08:15 14:30:00")
	got, err := ExtractDateTime(jpeg)
	if err != nil {
		t.Fatalf("ExtractDateTime: %v", err)
	}
	want := time.Date(2023, 8, 15, 14, 30, 0, 0, time.Local)
	if !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestExtractDateTime_NotJPEG(t *testing.T) {
	got, err := ExtractDateTime([]byte{0x00, 0x01, 0x02, 0x03})
	if err == nil {
		t.Error("非 JPEG 应返回错误")
	}
	if !got.IsZero() {
		t.Error("失败时 time 应为 zero")
	}
}

func TestExtractDateTime_NoEXIF(t *testing.T) {
	// 仅 SOI + EOI（无 APP1）
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xD9}
	got, err := ExtractDateTime(jpeg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !got.IsZero() {
		t.Error("无 EXIF 应返回 zero time")
	}
}

func TestArchiveSubdir(t *testing.T) {
	tm := time.Date(2024, 3, 8, 12, 0, 0, 0, time.UTC)
	if s := ArchiveSubdir(tm); s != "2024/03" {
		t.Errorf("ArchiveSubdir=%q want 2024/03", s)
	}
	if s := ArchiveSubdir(time.Time{}); s != "Unknown_Date" {
		t.Errorf("ArchiveSubdir(zero)=%q want Unknown_Date", s)
	}
}
