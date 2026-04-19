package carver

import (
	"bytes"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
	"data-recovery/internal/types"
)

// buildFtypHeader 造一个 ftyp atom 头：长度(4) + "ftyp" + brand(4) + minor(4)。
// atomLen = 24 够完整 ftyp 结构用。
func buildFtypHeader(brand string, atomLen uint32) []byte {
	b := &bytes.Buffer{}
	binary.Write(b, binary.BigEndian, atomLen)
	b.WriteString("ftyp")
	b.WriteString(brand)
	b.Write([]byte{0, 0, 0, 0}) // minor version
	// padding 到 atomLen
	for b.Len() < int(atomLen) {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func TestClassifyFTYP_HEIC(t *testing.T) {
	eng := &Engine{}
	reader := testutil.NewMemReader(buildFtypHeader("heic", 24))
	ext, cat := eng.classifyFTYP(reader, 0)
	if ext != "heic" || cat != types.CategoryImage {
		t.Errorf("HEIC 识别错: ext=%q cat=%q", ext, cat)
	}
}

func TestClassifyFTYP_AVIF(t *testing.T) {
	eng := &Engine{}
	reader := testutil.NewMemReader(buildFtypHeader("avif", 24))
	ext, cat := eng.classifyFTYP(reader, 0)
	if ext != "avif" || cat != types.CategoryImage {
		t.Errorf("AVIF 识别错: ext=%q cat=%q", ext, cat)
	}
}

func TestClassifyFTYP_M4A(t *testing.T) {
	eng := &Engine{}
	reader := testutil.NewMemReader(buildFtypHeader("M4A ", 24))
	ext, cat := eng.classifyFTYP(reader, 0)
	if ext != "m4a" || cat != types.CategoryAudio {
		t.Errorf("M4A 识别错: ext=%q cat=%q", ext, cat)
	}
}

func TestClassifyFTYP_3GP(t *testing.T) {
	eng := &Engine{}
	reader := testutil.NewMemReader(buildFtypHeader("3gp5", 24))
	ext, cat := eng.classifyFTYP(reader, 0)
	if ext != "3gp" || cat != types.CategoryVideo {
		t.Errorf("3GP 识别错: ext=%q cat=%q", ext, cat)
	}
}

func TestClassifyFTYP_MOV(t *testing.T) {
	eng := &Engine{}
	reader := testutil.NewMemReader(buildFtypHeader("qt  ", 24))
	ext, cat := eng.classifyFTYP(reader, 0)
	if ext != "mov" || cat != types.CategoryVideo {
		t.Errorf("MOV 识别错: ext=%q cat=%q", ext, cat)
	}
}

func TestClassifyFTYP_CR3(t *testing.T) {
	eng := &Engine{}
	reader := testutil.NewMemReader(buildFtypHeader("crx ", 24))
	ext, cat := eng.classifyFTYP(reader, 0)
	if ext != "cr3" || cat != types.CategoryImage {
		t.Errorf("CR3 识别错: ext=%q cat=%q", ext, cat)
	}
}

func TestClassifyFTYP_UnknownBrandFallsBack(t *testing.T) {
	eng := &Engine{}
	reader := testutil.NewMemReader(buildFtypHeader("zzzz", 24))
	ext, _ := eng.classifyFTYP(reader, 0)
	if ext != "" {
		t.Errorf("未知 brand 应返回空 ext，实际 %q", ext)
	}
}

func TestClassifyTIFF_CR2(t *testing.T) {
	// TIFF little-endian header + CR2 marker
	data := []byte{
		0x49, 0x49, 0x2A, 0x00, // "II*\0"
		0x10, 0x00, 0x00, 0x00, // IFD offset
		'C', 'R', 0x02, 0x00, // CR2 marker
	}
	// pad
	data = append(data, make([]byte, 100)...)

	eng := &Engine{}
	reader := testutil.NewMemReader(data)
	ext, cat := eng.classifyTIFF(reader, 0)
	if ext != "cr2" || cat != types.CategoryImage {
		t.Errorf("CR2 识别错: ext=%q cat=%q", ext, cat)
	}
}

func TestClassifyTIFF_RegularTIFFFallsBack(t *testing.T) {
	// 没有 CR2 marker 的普通 TIFF
	data := []byte{
		0x49, 0x49, 0x2A, 0x00,
		0x10, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // 非 CR2 marker
	}
	data = append(data, make([]byte, 100)...)

	eng := &Engine{}
	reader := testutil.NewMemReader(data)
	ext, _ := eng.classifyTIFF(reader, 0)
	if ext != "" {
		t.Errorf("普通 TIFF 应返回空 ext 保持默认分类，实际 %q", ext)
	}
}
