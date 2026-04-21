package bitlocker

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// 造一个最小 datum：8 字节头 + N 字节 body
func buildDatum(typeCode, valueType uint16, body []byte) []byte {
	size := 8 + len(body)
	buf := make([]byte, size)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(size))
	binary.LittleEndian.PutUint16(buf[2:4], typeCode)
	binary.LittleEndian.PutUint16(buf[4:6], valueType)
	binary.LittleEndian.PutUint16(buf[6:8], 1) // version
	copy(buf[8:], body)
	return buf
}

func TestParseDatum_BasicHeader(t *testing.T) {
	body := []byte{0xAA, 0xBB, 0xCC}
	raw := buildDatum(DatumEntryProperty, DatumValueKey, body)

	d, consumed, err := ParseDatum(raw, 0)
	if err != nil {
		t.Fatalf("ParseDatum: %v", err)
	}
	if consumed != len(raw) {
		t.Errorf("consumed 错: got %d want %d", consumed, len(raw))
	}
	if d.Type != DatumEntryProperty {
		t.Errorf("Type: %d", d.Type)
	}
	if d.ValueType != DatumValueKey {
		t.Errorf("ValueType: %d", d.ValueType)
	}
	if !bytes.Equal(d.Body, body) {
		t.Errorf("Body 错: got %x want %x", d.Body, body)
	}
}

func TestParseDatum_RejectsBadSize(t *testing.T) {
	// size = 4（< 8 头部最小）
	bad := make([]byte, 8)
	binary.LittleEndian.PutUint16(bad[0:2], 4)
	if _, _, err := ParseDatum(bad, 0); err == nil {
		t.Error("size=4 应被拒")
	}
	// size 超出 buf 长度（uint16 自然上限 65535，只能用 buf 长度做边界）
	bad2 := make([]byte, 8)
	binary.LittleEndian.PutUint16(bad2[0:2], 9999) // 远超 8 字节 buf
	if _, _, err := ParseDatum(bad2, 0); err == nil {
		t.Error("size 越界应被拒")
	}
}

// 嵌套 datum：VMK datum 28 字节头 + 内部 KEY datum
func TestParseDatum_VMKWithChildren(t *testing.T) {
	// 内部子 datum：一个 KEY datum
	childBody := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	childRaw := buildDatum(DatumEntryProperty, DatumValueKey, childBody)

	// VMK body = 28 字节 header + child datum
	vmkBody := make([]byte, 28+len(childRaw))
	// VMK header: GUID(16) + lastChange(8) + protection(2) + ?(2)
	for i := 0; i < 16; i++ {
		vmkBody[i] = byte(0xA0 + i) // GUID
	}
	binary.LittleEndian.PutUint16(vmkBody[24:26], VMKProtectionRecoveryPwd)
	copy(vmkBody[28:], childRaw)

	vmkRaw := buildDatum(DatumEntryVMKInfo, DatumValueVMK, vmkBody)
	d, _, err := ParseDatum(vmkRaw, 0)
	if err != nil {
		t.Fatalf("ParseDatum: %v", err)
	}
	if len(d.Children) != 1 {
		t.Fatalf("应解析出 1 个子 datum，实际 %d", len(d.Children))
	}
	if d.Children[0].ValueType != DatumValueKey {
		t.Errorf("子 datum ValueType: %d", d.Children[0].ValueType)
	}
	if !bytes.Equal(d.Children[0].Body, childBody) {
		t.Errorf("子 datum body: got %x want %x", d.Children[0].Body, childBody)
	}
}

func TestFindDatumByValueType_Recursive(t *testing.T) {
	// 构造："VMK datum (含 STRETCH_KEY datum (含 KEY datum))"
	keyDatum := Datum{ValueType: DatumValueKey, Body: []byte{0x01}}
	stretchDatum := Datum{ValueType: DatumValueStretchKey, Children: []Datum{keyDatum}}
	vmkDatum := Datum{ValueType: DatumValueVMK, Children: []Datum{stretchDatum}}

	root := []Datum{vmkDatum}

	if FindDatumByValueType(root, DatumValueVMK) == nil {
		t.Error("应找到 VMK")
	}
	if FindDatumByValueType(root, DatumValueStretchKey) == nil {
		t.Error("应递归找到 STRETCH_KEY")
	}
	if FindDatumByValueType(root, DatumValueKey) == nil {
		t.Error("应递归找到 KEY")
	}
	if FindDatumByValueType(root, 0xFFFF) != nil {
		t.Error("不存在的 ValueType 应返回 nil")
	}
}

func TestFindAllDatumByValueType(t *testing.T) {
	r := []Datum{
		{ValueType: DatumValueVMK},
		{ValueType: DatumValueVMK},
		{ValueType: DatumValueKey},
	}
	if got := FindAllDatumByValueType(r, DatumValueVMK); len(got) != 2 {
		t.Errorf("应找到 2 个 VMK，实际 %d", len(got))
	}
}
