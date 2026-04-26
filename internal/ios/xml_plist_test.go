package ios

import (
	"bytes"
	"strings"
	"testing"
)

const sampleXMLPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BackupName</key>
	<string>iPhone of Alice</string>
	<key>IsEncrypted</key>
	<true/>
	<key>BuildVersion</key>
	<string>21A329</string>
	<key>Iterations</key>
	<integer>10000000</integer>
	<key>Salt</key>
	<data>
	YWJjZGVmZ2hpams=
	</data>
	<key>BackupDate</key>
	<date>2024-01-15T14:30:00Z</date>
	<key>Tags</key>
	<array>
		<string>encrypted</string>
		<string>iOS17</string>
	</array>
	<key>SubDict</key>
	<dict>
		<key>Quality</key>
		<real>3.14</real>
		<key>Negative</key>
		<integer>-42</integer>
	</dict>
</dict>
</plist>`

func TestParseXMLPlist_AllTypes(t *testing.T) {
	v, err := ParseXMLPlist([]byte(sampleXMLPlist))
	if err != nil {
		t.Fatalf("ParseXMLPlist: %v", err)
	}
	if v.Kind != KindDict {
		t.Fatalf("根应是 dict, got %v", v.Kind)
	}

	if got := v.GetString("BackupName"); got != "iPhone of Alice" {
		t.Errorf("BackupName = %q", got)
	}
	if !v.GetBool("IsEncrypted", false) {
		t.Errorf("IsEncrypted 应 true")
	}
	if it, ok := v.GetInt("Iterations"); !ok || it != 10000000 {
		t.Errorf("Iterations = %d (ok=%v)", it, ok)
	}
	if salt := v.GetData("Salt"); !bytes.Equal(salt, []byte("abcdefghijk")) {
		t.Errorf("Salt = %q", salt)
	}

	tags := v.Dict["Tags"]
	if tags == nil || tags.Kind != KindArray || len(tags.Array) != 2 {
		t.Fatalf("Tags array 解析错")
	}
	if tags.Array[0].String != "encrypted" || tags.Array[1].String != "iOS17" {
		t.Errorf("Tags 内容: %v", tags.Array)
	}

	sub := v.GetDict("SubDict")
	if sub == nil {
		t.Fatal("SubDict 为 nil")
	}
	q := sub.Dict["Quality"]
	if q == nil || q.Kind != KindReal || q.Real != 3.14 {
		t.Errorf("Quality = %v", q)
	}
	neg := sub.Dict["Negative"]
	if neg == nil || neg.Kind != KindInt || neg.Int != -42 {
		t.Errorf("Negative = %v", neg)
	}

	// date 应该解出来
	d := v.Dict["BackupDate"]
	if d == nil || d.Kind != KindDate {
		t.Fatal("BackupDate 解析错")
	}
	if d.Time.Year() != 2024 {
		t.Errorf("BackupDate.Year = %d", d.Time.Year())
	}
}

// ParsePlist 自动转 XML 路径
func TestParsePlist_AutoDispatchToXML(t *testing.T) {
	v, err := ParsePlist([]byte(sampleXMLPlist))
	if err != nil {
		t.Fatalf("ParsePlist 应自动 dispatch 到 XML: %v", err)
	}
	if v.GetString("BackupName") != "iPhone of Alice" {
		t.Errorf("XML dispatch 解析错")
	}
}

// 无 <plist> 根元素应 error
func TestParseXMLPlist_NoRoot(t *testing.T) {
	junk := `<?xml version="1.0"?><foo></foo>`
	if _, err := ParseXMLPlist([]byte(junk)); err == nil {
		t.Errorf("无 <plist> 根元素应 error")
	}
}

// dict 里 key 不配对应 error
func TestParseXMLPlist_UnpairedKey(t *testing.T) {
	bad := `<?xml version="1.0"?><plist><dict><key>orphan</key></dict></plist>`
	if _, err := ParseXMLPlist([]byte(bad)); err == nil {
		t.Errorf("dict 末尾未配对 <key> 应 error")
	}
}

// 兼容老 iTunes 不带 'Z' 的 date 格式
func TestParseXMLPlist_DateWithoutZ(t *testing.T) {
	pl := `<?xml version="1.0"?><plist><dict><key>D</key><date>2020-06-01T00:00:00</date></dict></plist>`
	v, err := ParseXMLPlist([]byte(pl))
	if err != nil {
		t.Fatalf("老 date 格式应被接受: %v", err)
	}
	d := v.Dict["D"]
	if d == nil || d.Kind != KindDate || d.Time.Year() != 2020 {
		t.Errorf("解析结果不对: %v", d)
	}
}

// data 元素的 base64 内允许 whitespace
func TestParseXMLPlist_DataWithWhitespace(t *testing.T) {
	pl := `<?xml version="1.0"?><plist><dict><key>D</key><data>
	dGVz
	dA==
	</data></dict></plist>`
	v, err := ParseXMLPlist([]byte(pl))
	if err != nil {
		t.Fatal(err)
	}
	if got := v.GetData("D"); !bytes.Equal(got, []byte("test")) {
		t.Errorf("base64 with whitespace 解析错: %q", got)
	}
}

// 大量元素压力测试（性能不至于太离谱 + 不 panic）
func TestParseXMLPlist_LargeArray(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><plist><array>`)
	for i := 0; i < 1000; i++ {
		sb.WriteString("<integer>")
		sb.WriteString("123")
		sb.WriteString("</integer>")
	}
	sb.WriteString(`</array></plist>`)
	v, err := ParseXMLPlist([]byte(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != KindArray || len(v.Array) != 1000 {
		t.Errorf("大 array 解析错: kind=%v len=%d", v.Kind, len(v.Array))
	}
}
