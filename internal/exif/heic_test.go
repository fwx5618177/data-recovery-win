package exif

import (
	"encoding/binary"
	"testing"
	"time"
)

// 合成最小 HEIC：ftyp + 嵌入 "Exif\0\0" + TIFF + DateTime
func TestExtractDateTimeHEIC_FindsDate(t *testing.T) {
	// ftyp box: size=20, type=ftyp, brand=heic + 4 字节 minor_version + 4 字节 compatible
	heic := []byte{}
	heic = append(heic, 0, 0, 0, 20)
	heic = append(heic, []byte("ftyp")...)
	heic = append(heic, []byte("heic")...)
	heic = append(heic, 0, 0, 0, 0)
	heic = append(heic, []byte("mif1")...)

	// 后面追加任意 binary + 嵌入完整 EXIF payload
	heic = append(heic, make([]byte, 1024)...)

	// 构造 TIFF + DateTime
	tiff := []byte{}
	tiff = append(tiff, 'I', 'I')
	tiff = append(tiff, 0x2A, 0x00)
	tiff = append(tiff, 0x08, 0x00, 0x00, 0x00) // IFD0 @ 8
	// IFD0: 1 entry + next IFD = 0
	tiff = append(tiff, 0x01, 0x00)
	tiff = append(tiff, 0x32, 0x01)             // tag DateTime
	tiff = append(tiff, 0x02, 0x00)             // type ASCII
	tiff = append(tiff, 0x14, 0x00, 0x00, 0x00) // count = 20
	dvOffset := uint32(8 + 2 + 12 + 4)
	tb := make([]byte, 4)
	binary.LittleEndian.PutUint32(tb, dvOffset)
	tiff = append(tiff, tb...)
	tiff = append(tiff, 0x00, 0x00, 0x00, 0x00) // next IFD
	dateBytes := make([]byte, 20)
	copy(dateBytes, []byte("2024:09:15 10:00:00"))
	tiff = append(tiff, dateBytes...)

	exif := append([]byte("Exif\x00\x00"), tiff...)
	heic = append(heic, exif...)

	got, err := ExtractDateTimeHEIC(heic)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := time.Date(2024, 9, 15, 10, 0, 0, 0, time.Local)
	if !got.Equal(want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestFindLivePhotoPairs(t *testing.T) {
	files := []string{
		"IMG_1234.HEIC",
		"IMG_1234.MOV",
		"IMG_2222.heic",
		"IMG_2222.mov",
		"IMG_9999.HEIC", // 没配对的
		"random.jpg",
	}
	pairs := FindLivePhotoPairs(files)
	if len(pairs) != 2 {
		t.Fatalf("pairs=%d want 2", len(pairs))
	}
}
