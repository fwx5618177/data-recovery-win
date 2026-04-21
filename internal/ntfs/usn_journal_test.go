package ntfs

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// 合成一条 USN_RECORD_V2 字节流（删除事件，文件名 "kitten.jpg"）
func buildUSNRecordV2(fileRef, parentRef uint64, reason uint32, name string) []byte {
	codes := utf16.Encode([]rune(name))
	nameBytes := make([]byte, 2*len(codes))
	for i, c := range codes {
		binary.LittleEndian.PutUint16(nameBytes[2*i:2*i+2], c)
	}
	const headerLen = 0x3C
	recLen := uint32(headerLen + len(nameBytes))
	// 8 字节对齐
	if recLen%8 != 0 {
		recLen += 8 - recLen%8
	}
	buf := make([]byte, recLen)
	binary.LittleEndian.PutUint32(buf[0x00:0x04], recLen)
	binary.LittleEndian.PutUint16(buf[0x04:0x06], 2) // major
	binary.LittleEndian.PutUint16(buf[0x06:0x08], 0)
	binary.LittleEndian.PutUint64(buf[0x08:0x10], fileRef)
	binary.LittleEndian.PutUint64(buf[0x10:0x18], parentRef)
	binary.LittleEndian.PutUint64(buf[0x18:0x20], 0xCAFE)
	// 时间戳：2024-01-01 00:00:00 UTC = FILETIME 133479360000000000
	binary.LittleEndian.PutUint64(buf[0x20:0x28], 133479360000000000)
	binary.LittleEndian.PutUint32(buf[0x28:0x2C], reason)
	binary.LittleEndian.PutUint16(buf[0x38:0x3A], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint16(buf[0x3A:0x3C], headerLen)
	copy(buf[headerLen:], nameBytes)
	return buf
}

func TestParseUSNJournal_ExtractsDeletedFiles(t *testing.T) {
	// 合成 3 条 record：1 创建 / 1 删除 / 1 修改
	buf := []byte{}
	buf = append(buf, buildUSNRecordV2(0x1234, 5, UsnReasonFileCreate|UsnReasonClose, "newfile.txt")...)
	buf = append(buf, buildUSNRecordV2(0x5678, 5, UsnReasonFileDelete|UsnReasonClose, "deleted.docx")...)
	buf = append(buf, buildUSNRecordV2(0x9ABC, 5, UsnReasonDataOverwrite|UsnReasonClose, "modified.xlsx")...)

	records, err := ParseUSNJournal(buf)
	if err != nil {
		t.Fatalf("ParseUSNJournal: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("解出 %d 条 want 3", len(records))
	}
	if records[1].FileName != "deleted.docx" {
		t.Errorf("filename: %q", records[1].FileName)
	}
	if !records[1].IsDeletion() {
		t.Error("第二条应是 deletion")
	}
	if records[1].MFTEntryNumber() != 0x5678 {
		t.Errorf("MFT entry: 0x%X want 0x5678", records[1].MFTEntryNumber())
	}

	dels := ExtractDeletedFiles(records)
	if len(dels) != 1 {
		t.Fatalf("ExtractDeletedFiles 应返回 1 条 deletion，得到 %d", len(dels))
	}
	if dels[0].FileName != "deleted.docx" {
		t.Errorf("deleted filename: %q", dels[0].FileName)
	}
}

// USN journal 头部常常是 sparse 0 字节；解析应跳过
func TestParseUSNJournal_SkipsLeadingZeros(t *testing.T) {
	buf := make([]byte, 1024) // 全 0
	buf = append(buf, buildUSNRecordV2(0x1, 5, UsnReasonFileDelete|UsnReasonClose, "kitten.jpg")...)
	records, err := ParseUSNJournal(buf)
	if err != nil {
		t.Fatalf("ParseUSNJournal: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("找到 %d 条 want 1", len(records))
	}
	if records[0].FileName != "kitten.jpg" {
		t.Errorf("filename: %q", records[0].FileName)
	}
}

// UTF-16 中文文件名
func TestParseUSNJournal_UTF16Chinese(t *testing.T) {
	rec := buildUSNRecordV2(0x42, 5, UsnReasonFileDelete|UsnReasonClose, "重要文档.docx")
	records, _ := ParseUSNJournal(rec)
	if len(records) != 1 || records[0].FileName != "重要文档.docx" {
		t.Errorf("中文解码失败: %v", records)
	}
}

// 损坏的 record（recLen 异常）应安全停止
func TestParseUSNJournal_HandlesBadRecLen(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], 999999) // 大于实际剩余
	records, err := ParseUSNJournal(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("应跳过损坏 record")
	}
}
