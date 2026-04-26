package ios

import (
	"bytes"
	"testing"
	"time"
)

// 核心 round-trip：构造 Value → EncodePlist → ParsePlist → 比对
func TestEncodePlist_RoundTrip_AllTypes(t *testing.T) {
	tm := time.Date(2024, 1, 15, 14, 30, 0, 0, time.UTC)
	root := &Value{
		Kind: KindDict,
		Dict: map[string]*Value{
			"BackupName":   {Kind: KindString, String: "iPhone of Alice"},
			"IsEncrypted":  {Kind: KindBool, Bool: true},
			"FailedCount":  {Kind: KindBool, Bool: false},
			"Iterations":   {Kind: KindInt, Int: 10000000},
			"NegativeNum":  {Kind: KindInt, Int: -42},
			"BigInt":       {Kind: KindInt, Int: 1<<40 + 1234},
			"Quality":      {Kind: KindReal, Real: 3.14159},
			"BackupDate":   {Kind: KindDate, Time: tm},
			"Salt":         {Kind: KindData, Data: []byte("rawSaltBytes")},
			"Empty":        {Kind: KindNull},
			"Tags": {
				Kind: KindArray,
				Array: []*Value{
					{Kind: KindString, String: "encrypted"},
					{Kind: KindString, String: "iOS17"},
					{Kind: KindInt, Int: 7},
				},
			},
			"Sub": {
				Kind: KindDict,
				Dict: map[string]*Value{
					"Inner": {Kind: KindString, String: "nestedValue"},
					"List":  {Kind: KindArray, Array: []*Value{{Kind: KindInt, Int: 1}, {Kind: KindInt, Int: 2}}},
				},
			},
		},
	}

	encoded, err := EncodePlist(root)
	if err != nil {
		t.Fatalf("EncodePlist: %v", err)
	}
	if !bytes.HasPrefix(encoded, []byte("bplist00")) {
		t.Fatalf("应以 bplist00 magic 开头, got %q", encoded[:8])
	}

	parsed, err := ParsePlist(encoded)
	if err != nil {
		t.Fatalf("ParsePlist 反向: %v", err)
	}

	// 字段验证
	if parsed.GetString("BackupName") != "iPhone of Alice" {
		t.Errorf("BackupName")
	}
	if !parsed.GetBool("IsEncrypted", false) {
		t.Errorf("IsEncrypted")
	}
	if parsed.GetBool("FailedCount", true) {
		t.Errorf("FailedCount = false 没保留")
	}
	if it, ok := parsed.GetInt("Iterations"); !ok || it != 10000000 {
		t.Errorf("Iterations: %d ok=%v", it, ok)
	}
	if it, ok := parsed.GetInt("NegativeNum"); !ok || it != -42 {
		t.Errorf("NegativeNum: %d ok=%v", it, ok)
	}
	if it, ok := parsed.GetInt("BigInt"); !ok || it != 1<<40+1234 {
		t.Errorf("BigInt: %d ok=%v", it, ok)
	}
	if !bytes.Equal(parsed.GetData("Salt"), []byte("rawSaltBytes")) {
		t.Errorf("Salt 不一致")
	}
	if d := parsed.Dict["BackupDate"]; d == nil || d.Kind != KindDate {
		t.Fatal("BackupDate 缺失")
	} else if !d.Time.Equal(tm) {
		t.Errorf("BackupDate = %v want %v", d.Time, tm)
	}
	if r := parsed.Dict["Quality"]; r == nil || r.Kind != KindReal {
		t.Fatal("Quality 缺失")
	} else if r.Real < 3.14158 || r.Real > 3.1416 {
		t.Errorf("Quality = %v", r.Real)
	}

	// array
	tags := parsed.Dict["Tags"]
	if tags == nil || len(tags.Array) != 3 {
		t.Fatalf("Tags 数: %d", len(tags.Array))
	}
	if tags.Array[0].String != "encrypted" || tags.Array[1].String != "iOS17" {
		t.Errorf("Tags 字符串错")
	}
	if tags.Array[2].Int != 7 {
		t.Errorf("Tags[2] int 错")
	}

	// nested dict
	sub := parsed.GetDict("Sub")
	if sub == nil {
		t.Fatal("Sub 缺失")
	}
	if sub.GetString("Inner") != "nestedValue" {
		t.Errorf("Sub.Inner")
	}
	list := sub.Dict["List"]
	if list == nil || len(list.Array) != 2 || list.Array[1].Int != 2 {
		t.Errorf("Sub.List")
	}
}

// UTF-16BE 字符串（含中文）round-trip
func TestEncodePlist_UTF16String(t *testing.T) {
	root := &Value{
		Kind: KindDict,
		Dict: map[string]*Value{
			"Chinese": {Kind: KindString, String: "你好世界"},
			"Mixed":   {Kind: KindString, String: "hello 世界 🌍"},
		},
	}
	enc, err := EncodePlist(root)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePlist(enc)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.GetString("Chinese") != "你好世界" {
		t.Errorf("中文丢失: %q", parsed.GetString("Chinese"))
	}
	if parsed.GetString("Mixed") != "hello 世界 🌍" {
		t.Errorf("Mixed 丢失: %q", parsed.GetString("Mixed"))
	}
}

// 大长度（>= 15）触发 extended length 编码
func TestEncodePlist_ExtendedLength(t *testing.T) {
	bigStr := make([]byte, 0, 1000)
	for i := 0; i < 1000; i++ {
		bigStr = append(bigStr, byte('A'+(i%26)))
	}
	root := &Value{
		Kind: KindDict,
		Dict: map[string]*Value{
			"Big": {Kind: KindString, String: string(bigStr)},
			"BigData": {Kind: KindData, Data: bytes.Repeat([]byte{0xAB}, 500)},
			"BigArray": func() *Value {
				items := make([]*Value, 100)
				for i := range items {
					items[i] = &Value{Kind: KindInt, Int: int64(i)}
				}
				return &Value{Kind: KindArray, Array: items}
			}(),
		},
	}
	enc, err := EncodePlist(root)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePlist(enc)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.GetString("Big") != string(bigStr) {
		t.Errorf("Big string 丢失")
	}
	if !bytes.Equal(parsed.GetData("BigData"), bytes.Repeat([]byte{0xAB}, 500)) {
		t.Errorf("BigData 丢失")
	}
	arr := parsed.Dict["BigArray"]
	if arr == nil || len(arr.Array) != 100 {
		t.Fatalf("BigArray 数: %d", len(arr.Array))
	}
	for i, v := range arr.Array {
		if v.Int != int64(i) {
			t.Errorf("BigArray[%d] = %d", i, v.Int)
			break
		}
	}
}

// nil root 拒绝
func TestEncodePlist_RejectNil(t *testing.T) {
	if _, err := EncodePlist(nil); err == nil {
		t.Errorf("nil root 应拒绝")
	}
}

// trailer 字段值正确性
func TestEncodePlist_TrailerStructure(t *testing.T) {
	root := &Value{Kind: KindString, String: "x"}
	enc, err := EncodePlist(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) < 32+8 {
		t.Fatalf("太短: %d", len(enc))
	}
	tr := enc[len(enc)-32:]
	// trailer[6] = offsetIntSize, trailer[7] = objectRefSize
	if tr[6] == 0 || tr[6] > 8 {
		t.Errorf("offsetIntSize 不合理: %d", tr[6])
	}
	if tr[7] == 0 || tr[7] > 8 {
		t.Errorf("objectRefSize 不合理: %d", tr[7])
	}
	// trailer[8..16] = numObjects（root 是单 string → 1 object）
	if tr[15] != 1 || tr[14] != 0 {
		t.Errorf("numObjects 字节错: %x", tr[8:16])
	}
}
