package validator

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// mockReader: 给 validator 喂内存数据（不开实际磁盘）
type mockReader struct {
	data []byte
}

func (m *mockReader) Open() error  { return nil }
func (m *mockReader) Close() error { return nil }
func (m *mockReader) Size() (int64, error) {
	return int64(len(m.data)), nil
}
func (m *mockReader) SectorSize() int    { return 512 }
func (m *mockReader) DevicePath() string { return "memory" }
func (m *mockReader) ReadAt(buf []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.data)) {
		return 0, nil
	}
	return copy(buf, m.data[off:]), nil
}

// 合法 PDF：%PDF- + obj + xref + startxref + %%EOF
func TestValidatePDF_CleanDocument(t *testing.T) {
	pdf := buildCleanPDF()
	v := &Validator{reader: &mockReader{data: pdf}}
	res := v.validatePDF(0, int64(len(pdf)))
	if !res.IsValid {
		t.Errorf("clean PDF 应 valid: %+v", res)
	}
	if res.Confidence < 0.8 {
		t.Errorf("clean PDF confidence 应 >=0.8: %v", res.Confidence)
	}
}

// 碎片化 PDF：startxref 指向错误位置
func TestValidatePDF_BadStartxref(t *testing.T) {
	pdf := buildPDFWithBadXref()
	v := &Validator{reader: &mockReader{data: pdf}}
	res := v.validatePDF(0, int64(len(pdf)))
	if res.Confidence >= 0.8 {
		t.Errorf("bad xref PDF 置信度不该太高: %v\n%s", res.Confidence, res.Message)
	}
}

func buildCleanPDF() []byte {
	// 简化 PDF
	body := "%PDF-1.4\n"
	// Catalog / Pages 两个 obj
	obj1 := "1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
	obj2 := "2 0 obj\n<</Type/Pages/Count 1>>\nendobj\n"
	obj3 := "3 0 obj\n<</Type/Page>>\nendobj\n"
	body += obj1 + obj2 + obj3
	xrefStart := len(body)
	xref := "xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000055 00000 n \n0000000100 00000 n \n"
	body += xref
	body += "trailer\n<</Size 4/Root 1 0 R>>\nstartxref\n" +
		itoa(xrefStart) + "\n%%EOF\n"
	return []byte(body)
}

func buildPDFWithBadXref() []byte {
	body := "%PDF-1.4\n1 0 obj\n<<>>\nendobj\n"
	body += "trailer\n<</Size 1>>\nstartxref\n99999999\n%%EOF\n"
	return []byte(body)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// 合法 MP4: ftyp + moov + mdat，box size 精确填文件
func TestValidateMP4_FullyValid(t *testing.T) {
	mp4 := buildMP4Full()
	v := &Validator{reader: &mockReader{data: mp4}}
	res := v.validateMP4(0, int64(len(mp4)))
	if !res.IsValid {
		t.Errorf("valid MP4 应 valid: %+v", res)
	}
	if res.Confidence < 0.8 {
		t.Errorf("full MP4 confidence 应 >=0.8: %v", res.Confidence)
	}
}

// MP4 仅 moov 无 mdat — 应 confidence 低
func TestValidateMP4_MoovOnly(t *testing.T) {
	mp4 := buildMP4MoovOnly()
	v := &Validator{reader: &mockReader{data: mp4}}
	res := v.validateMP4(0, int64(len(mp4)))
	if res.Confidence >= 0.8 {
		t.Errorf("仅 moov 置信度不该太高: %v\n%s", res.Confidence, res.Message)
	}
}

// MP4 box 链中断（atomSize 超出文件尾）
func TestValidateMP4_BrokenBoxChain(t *testing.T) {
	mp4 := buildMP4BrokenChain()
	v := &Validator{reader: &mockReader{data: mp4}}
	res := v.validateMP4(0, int64(len(mp4)))
	// Message 应提示链中断
	if !bytes.Contains([]byte(res.Message), []byte("碎片化嫌疑")) {
		t.Errorf("应报告碎片化嫌疑: %s", res.Message)
	}
}

// buildMP4Full: ftyp(24) + moov(32) + mdat(16) = 72 字节
func buildMP4Full() []byte {
	out := &bytes.Buffer{}
	// ftyp size=24: 8 header + 16 brand info
	writeBE32(out, 24)
	out.WriteString("ftyp")
	out.WriteString("isom")
	writeBE32(out, 512) // minor version
	out.WriteString("isomiso2")
	// moov size=32: 8 header + 24 填充
	writeBE32(out, 32)
	out.WriteString("moov")
	out.Write(make([]byte, 24))
	// mdat size=16: 8 header + 8 data
	writeBE32(out, 16)
	out.WriteString("mdat")
	out.Write(make([]byte, 8))
	return out.Bytes()
}

func buildMP4MoovOnly() []byte {
	out := &bytes.Buffer{}
	writeBE32(out, 24)
	out.WriteString("ftyp")
	out.WriteString("isom")
	writeBE32(out, 512)
	out.WriteString("isomiso2")
	writeBE32(out, 32)
	out.WriteString("moov")
	out.Write(make([]byte, 24))
	return out.Bytes()
}

func buildMP4BrokenChain() []byte {
	out := &bytes.Buffer{}
	writeBE32(out, 24)
	out.WriteString("ftyp")
	out.WriteString("isom")
	writeBE32(out, 512)
	out.WriteString("isomiso2")
	// 下一个 atom 声明 size=999999 但文件只有 24 + 8 = 32 字节
	writeBE32(out, 999999)
	out.WriteString("moov")
	return out.Bytes()
}

func writeBE32(out *bytes.Buffer, v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	out.Write(b)
}
