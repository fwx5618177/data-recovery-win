package ios

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

// 最简 bplist 构造器：for unit testing only。
// 真正的生产 marshal 在 plutil / CoreFoundation；我们写解码器所以测试只造几个样本。
// 参考 Apple source: CoreFoundation/CFBinaryPList.c

// buildMinimalPlist 组装一个 bplist00 样本：
//   top = dict { key: value, ... } 其中 key 是 ASCII 字符串。
// count 最大 14（用 marker lo 字段），避免处理 extended length。
func buildMinimalPlist(t *testing.T, pairs []kv) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("bplist00")

	// 分配 object id：
	//   0 = top dict
	//   1..N = keys + values（交错）
	n := len(pairs)
	totalObjects := 1 + n*2

	var offsets []int
	// 先写完每个对象，同时记录它们的 offset
	objectBytes := make([][]byte, totalObjects)

	// top dict marker: 0xD<count> + key refs + val refs
	// 每个 ref 1 字节（只要 totalObjects < 256）
	if totalObjects > 255 {
		t.Fatalf("测试构造器 ref 宽度限于 1 字节，pairs 太多")
	}
	topBuf := []byte{0xD0 | byte(n)}
	for i := 0; i < n; i++ {
		topBuf = append(topBuf, byte(1+i*2)) // key 对象 id
	}
	for i := 0; i < n; i++ {
		topBuf = append(topBuf, byte(2+i*2)) // val 对象 id
	}
	objectBytes[0] = topBuf

	for i, kv := range pairs {
		// key: ASCII string
		key := []byte(kv.k)
		keyBuf := append([]byte{0x50 | byte(len(key))}, key...)
		objectBytes[1+i*2] = keyBuf
		// value 根据类型
		objectBytes[2+i*2] = marshalValue(kv.v)
	}

	// 依次写入并记 offset
	for _, o := range objectBytes {
		offsets = append(offsets, buf.Len())
		buf.Write(o)
	}

	// offset table
	offsetTableOffset := buf.Len()
	for _, o := range offsets {
		buf.WriteByte(byte(o))
	}

	// trailer：5 保留 + 1 sortVer + 1 offSize + 1 refSize + 8 numObj + 8 topObj + 8 offTableOff
	buf.Write(make([]byte, 5))
	buf.WriteByte(0)             // sortVersion
	buf.WriteByte(1)             // offsetIntSize
	buf.WriteByte(1)             // objectRefSize
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(totalObjects))
	buf.Write(tmp[:])
	binary.BigEndian.PutUint64(tmp[:], 0)
	buf.Write(tmp[:])
	binary.BigEndian.PutUint64(tmp[:], uint64(offsetTableOffset))
	buf.Write(tmp[:])

	return buf.Bytes()
}

type kv struct {
	k string
	v any
}

func marshalValue(v any) []byte {
	switch x := v.(type) {
	case bool:
		if x {
			return []byte{0x09}
		}
		return []byte{0x08}
	case int64:
		// 用 4 字节
		b := make([]byte, 5)
		b[0] = 0x12
		binary.BigEndian.PutUint32(b[1:], uint32(x))
		return b
	case string:
		return append([]byte{0x50 | byte(len(x))}, []byte(x)...)
	case []byte:
		if len(x) < 15 {
			return append([]byte{0x40 | byte(len(x))}, x...)
		}
		panic("unit test 只支持 < 15 字节 data")
	case float64:
		b := make([]byte, 9)
		b[0] = 0x23
		binary.BigEndian.PutUint64(b[1:], math.Float64bits(x))
		return b
	}
	panic("不支持的测试类型")
}

// ---- 实际测试 ----

func TestParsePlist_DictBoolStringInt(t *testing.T) {
	data := buildMinimalPlist(t, []kv{
		{"IsEncrypted", true},
		{"ProductType", "iPhone14,5"},
		{"BackupState", int64(42)},
	})
	v, err := ParsePlist(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v.Kind != KindDict {
		t.Fatalf("根不是 dict")
	}
	if !v.GetBool("IsEncrypted", false) {
		t.Errorf("IsEncrypted 应为 true")
	}
	if v.GetString("ProductType") != "iPhone14,5" {
		t.Errorf("ProductType = %q", v.GetString("ProductType"))
	}
	if n, ok := v.GetInt("BackupState"); !ok || n != 42 {
		t.Errorf("BackupState = %d ok=%v", n, ok)
	}
}

func TestParsePlist_InvalidMagic(t *testing.T) {
	_, err := ParsePlist([]byte("notplist" + string(make([]byte, 100))))
	if err == nil {
		t.Errorf("非 bplist 应报错")
	}
}

// XML plist 现在被支持（自动 dispatch 到 ParseXMLPlist）—— 详细测试在
// xml_plist_test.go。这里只验证 dispatch 不报错。
func TestParsePlist_XMLAccepted(t *testing.T) {
	xml := []byte(`<?xml version="1.0"?><plist><dict></dict></plist>`)
	v, err := ParsePlist(xml)
	if err != nil {
		t.Fatalf("XML plist 应被自动 dispatch 到 XML 解析: %v", err)
	}
	if v.Kind != KindDict {
		t.Errorf("空 dict 应解析为 KindDict, got %v", v.Kind)
	}
}

func TestParsePlist_EmptyTooShort(t *testing.T) {
	_, err := ParsePlist([]byte("bplist00"))
	if err == nil {
		t.Errorf("缺 trailer 应报错")
	}
}

func TestParsePlist_Data(t *testing.T) {
	data := buildMinimalPlist(t, []kv{
		{"BackupKeyBag", []byte{0x01, 0x02, 0x03, 0x04}},
	})
	v, _ := ParsePlist(data)
	got := v.GetData("BackupKeyBag")
	if !bytes.Equal(got, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("data 字段: %x", got)
	}
}
