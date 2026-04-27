package refs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// 构造一个假 leaf MSB+ page，带 1-2 entry，验证 ParseNodeStructured 标记成 Leaf
type fakeReader struct{ data []byte }

func (f *fakeReader) Open() error { return nil }
func (f *fakeReader) ReadAt(p []byte, off int64) (int, error) {
	if int(off) >= len(f.data) {
		return 0, nil
	}
	n := copy(p, f.data[off:])
	return n, nil
}
func (f *fakeReader) Size() (int64, error) { return int64(len(f.data)), nil }
func (f *fakeReader) Close() error         { return nil }
func (f *fakeReader) SectorSize() int      { return 512 }
func (f *fakeReader) DevicePath() string   { return "fake" }

func TestParseValueAsTLV(t *testing.T) {
	// 构造一个带 2 个 fields 的 value：tag=0x10 len=10 (4 byte payload), tag=0x30 len=8 (2 byte payload)
	value := []byte{
		0x10, 0x00, // tag 0x10
		0x0A, 0x00, 0x00, 0x00, // length = 10
		0xAA, 0xBB, 0xCC, 0xDD, // payload 4 bytes
		0x30, 0x00, // tag 0x30
		0x08, 0x00, 0x00, 0x00, // length = 8
		0xEE, 0xFF, // payload 2 bytes
	}
	fields := ParseValueAsTLV(value)
	if len(fields) != 2 {
		t.Fatalf("got %d fields want 2", len(fields))
	}
	if fields[0].Tag != 0x10 || len(fields[0].Payload) != 4 {
		t.Errorf("field 0: %+v", fields[0])
	}
	if fields[1].Tag != 0x30 || len(fields[1].Payload) != 2 {
		t.Errorf("field 1: %+v", fields[1])
	}
}

func TestParseValueAsTLV_Truncated(t *testing.T) {
	// length 越界 → 解到一半就停，不 panic
	bad := []byte{0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA}
	fields := ParseValueAsTLV(bad)
	if len(fields) != 0 {
		t.Errorf("应跳过越界 length, got %d fields", len(fields))
	}
}

func TestExtractFileNameFromTLV(t *testing.T) {
	// 构造 $FILE_NAME field：parent=42, ..., name="hello"
	payload := make([]byte, 0x40+5*2) // 0x40 头 + 5 UTF-16 chars
	binary.LittleEndian.PutUint64(payload[0:8], 42) // parent
	payload[0x3C] = 5 // name_length
	payload[0x3D] = 1 // Win32 type
	for i, c := range "hello" {
		binary.LittleEndian.PutUint16(payload[0x3E+i*2:], uint16(c))
	}
	field := FieldTLV{
		Tag:     refsFieldFileName,
		Length:  uint32(6 + len(payload)),
		Payload: payload,
	}
	name, parent, ok := ExtractFileNameFromTLV([]FieldTLV{field})
	if !ok {
		t.Fatal("ExtractFileNameFromTLV 失败")
	}
	if name != "hello" {
		t.Errorf("name: got %q want hello", name)
	}
	if parent != 42 {
		t.Errorf("parent: got %d want 42", parent)
	}
}

func TestExtractFileNameFromTLV_NoMatch(t *testing.T) {
	// 没有 $FILE_NAME tag → ok=false
	other := FieldTLV{Tag: 0x99, Length: 6, Payload: nil}
	_, _, ok := ExtractFileNameFromTLV([]FieldTLV{other})
	if ok {
		t.Error("无 FILE_NAME tag 时不应找到")
	}
}

// 构造一个假 page 走 ParseNodeStructured，确认 leaf 识别
func TestParseNodeStructured_LeafDetection(t *testing.T) {
	page := make([]byte, MinstorePageSize)
	copy(page[0:4], pageMagicMSBPlus)

	// index header at 0x20: first_entry_offset=0x40, free_offset, num_entries=1
	binary.LittleEndian.PutUint32(page[0x20:0x24], 0x40)
	binary.LittleEndian.PutUint32(page[0x28:0x2C], 1) // num_entries

	// entry at 0x40: entry_size=32, key_off=16, key_len=8, val_off=24, val_len=4
	entryStart := 0x40
	binary.LittleEndian.PutUint16(page[entryStart:], 32) // entry_size
	binary.LittleEndian.PutUint16(page[entryStart+2:], 16)
	binary.LittleEndian.PutUint16(page[entryStart+4:], 8) // key_len
	binary.LittleEndian.PutUint16(page[entryStart+6:], 24)
	binary.LittleEndian.PutUint16(page[entryStart+8:], 4) // val_len
	// key: "AAAAAAAA" (8 bytes random)
	copy(page[entryStart+16:], bytes.Repeat([]byte{0x41}, 8))
	// value: 0xAA 0xBB 0xCC 0xDD —— 4 byte 不像 page ref → leaf
	copy(page[entryStart+24:], []byte{0xAA, 0xBB, 0xCC, 0xDD})

	r := &fakeReader{data: page}
	node, err := ParseNodeStructured(r, 0, 0, MinstorePageSize)
	if err != nil {
		t.Fatal(err)
	}
	if node.Kind != NodeKindLeaf {
		t.Errorf("kind = %d want leaf", node.Kind)
	}
	if len(node.Entries) != 1 {
		t.Errorf("entries = %d want 1", len(node.Entries))
	}
}

// Internal node：value 头 8 字节是合法 page ref → 应识别成 Internal
func TestParseNodeStructured_InternalDetection(t *testing.T) {
	page := make([]byte, MinstorePageSize)
	copy(page[0:4], pageMagicMSBPlus)
	binary.LittleEndian.PutUint32(page[0x20:0x24], 0x40)
	binary.LittleEndian.PutUint32(page[0x28:0x2C], 1)

	entryStart := 0x40
	binary.LittleEndian.PutUint16(page[entryStart:], 32)
	binary.LittleEndian.PutUint16(page[entryStart+2:], 16)
	binary.LittleEndian.PutUint16(page[entryStart+4:], 8)
	binary.LittleEndian.PutUint16(page[entryStart+6:], 24)
	binary.LittleEndian.PutUint16(page[entryStart+8:], 8) // val_len = 8 = page ref
	copy(page[entryStart+16:], bytes.Repeat([]byte{0x41}, 8))
	// value = uint64 page ref to offset 0x4000 (16KB aligned, in volume range)
	binary.LittleEndian.PutUint64(page[entryStart+24:], 0x4000)

	r := &fakeReader{data: make([]byte, 0x10000)}
	r.data = page
	// volStart=0, volSize=64KB - 0x4000 在范围内 + 16KB 对齐 → 视为 child page
	node, err := ParseNodeStructured(r, 0, 0, 0x10000)
	if err != nil {
		t.Fatal(err)
	}
	if node.Kind != NodeKindInternal {
		t.Errorf("kind = %d want internal", node.Kind)
	}
	if len(node.ChildPages) != 1 || node.ChildPages[0] != 0x4000 {
		t.Errorf("childPages: %v", node.ChildPages)
	}
}
