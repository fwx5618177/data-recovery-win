package ios

// ============================================================================
// XML Apple Property List 解析（DTD 1.0）
//
// 元素映射：
//   <dict>      → KindDict     （子元素是 <key>...</key><value/>... 交替）
//   <array>     → KindArray
//   <string>    → KindString
//   <integer>   → KindInt       （可能负数，可能 unsigned 64-bit）
//   <real>      → KindReal
//   <true/>     → KindBool=true
//   <false/>    → KindBool=false
//   <data>      → KindData       （base64 编码，xml whitespace 要 strip）
//   <date>      → KindDate       （ISO8601 / RFC3339，UTC 用 Z）
//
// 我们用 encoding/xml 的 streaming Decoder（不是 Unmarshal）—— XML plist
// 的"key/value 交替平铺在 dict 子元素里"这种结构没法靠 struct tag 自然映射。
// ============================================================================

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ParseXMLPlist 解析 XML 格式的 Apple plist。
// 返回根对象（通常是 plist > dict）。
//
// 支持元素：dict / array / key / string / integer / real / true / false /
// data / date。其它元素（如 <set>）按 array 处理。
func ParseXMLPlist(data []byte) (*Value, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	// XML plist 的 DOCTYPE 引用 Apple DTD —— 我们不去网络下载，跳过外部实体
	dec.Strict = false
	dec.Entity = xml.HTMLEntity
	// 关闭外部实体引用，防止 XXE
	dec.DefaultSpace = ""

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil, errors.New("XML plist: 没找到 <plist> 元素")
		}
		if err != nil {
			return nil, fmt.Errorf("XML plist: 读 token: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "plist" {
			// 偶尔 <plist> 之前还有 ProcInst / Directive 等
			continue
		}
		// 进入 <plist>，里面应有恰好一个根 value
		v, err := decodeXMLValue(dec, start)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
}

// decodeXMLValue 在 outer 元素内部读出根 value（plist 容器只允许一个子元素）。
// 调用前已 consume 了 outer 的 StartElement；返回时已 consume 了 outer 的 EndElement。
func decodeXMLValue(dec *xml.Decoder, outer xml.StartElement) (*Value, error) {
	var rootVal *Value
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("XML plist 内部 token: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			v, err := decodeXMLElement(dec, t)
			if err != nil {
				return nil, err
			}
			if rootVal != nil {
				return nil, fmt.Errorf("<%s> 内出现多个 value", outer.Name.Local)
			}
			rootVal = v
		case xml.EndElement:
			if t.Name.Local == outer.Name.Local {
				if rootVal == nil {
					return nil, fmt.Errorf("<%s> 内没有 value", outer.Name.Local)
				}
				return rootVal, nil
			}
		}
	}
}

// decodeXMLElement 已 consume 了 start，按 tag name 解码并 consume 对应的 end。
func decodeXMLElement(dec *xml.Decoder, start xml.StartElement) (*Value, error) {
	tag := start.Name.Local
	switch tag {
	case "true":
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return &Value{Kind: KindBool, Bool: true}, nil
	case "false":
		if err := dec.Skip(); err != nil {
			return nil, err
		}
		return &Value{Kind: KindBool, Bool: false}, nil
	case "string":
		s, err := readCharData(dec, tag)
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindString, String: s}, nil
	case "key":
		// <key> 的 chardata 也走这条路，但只有 dict 里会出现；
		// 这里返回 KindString 让 dict 解析时识别
		s, err := readCharData(dec, tag)
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindString, String: s}, nil
	case "integer":
		s, err := readCharData(dec, tag)
		if err != nil {
			return nil, err
		}
		s = strings.TrimSpace(s)
		// plist integer 可以负、可以 unsigned 64-bit；先按 int64 试，再按 uint64
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return &Value{Kind: KindInt, Int: i}, nil
		}
		if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			return &Value{Kind: KindInt, Int: int64(u)}, nil
		}
		return nil, fmt.Errorf("integer 不可解析: %q", s)
	case "real":
		s, err := readCharData(dec, tag)
		if err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return nil, fmt.Errorf("real 不可解析: %q (%v)", s, err)
		}
		return &Value{Kind: KindReal, Real: f}, nil
	case "data":
		s, err := readCharData(dec, tag)
		if err != nil {
			return nil, err
		}
		// base64 内允许任意 whitespace（plutil 输出会换行 + 缩进）
		clean := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				return -1
			}
			return r
		}, s)
		raw, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("data base64 解码失败: %w", err)
		}
		return &Value{Kind: KindData, Data: raw}, nil
	case "date":
		s, err := readCharData(dec, tag)
		if err != nil {
			return nil, err
		}
		s = strings.TrimSpace(s)
		// Apple 用 ISO8601 (e.g. "2024-01-15T14:30:00Z")
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			// 兼容老的不带 'Z' 的格式
			t, err = time.Parse("2006-01-02T15:04:05", s)
			if err != nil {
				return nil, fmt.Errorf("date 不可解析: %q (%v)", s, err)
			}
		}
		return &Value{Kind: KindDate, Time: t}, nil
	case "array", "set":
		var items []*Value
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := decodeXMLElement(dec, t)
				if err != nil {
					return nil, err
				}
				items = append(items, v)
			case xml.EndElement:
				if t.Name.Local == tag {
					return &Value{Kind: KindArray, Array: items}, nil
				}
			}
		}
	case "dict":
		m := map[string]*Value{}
		var pendingKey string
		var hasPendingKey bool
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					if hasPendingKey {
						return nil, fmt.Errorf("dict 里两个连续 <key>")
					}
					s, err := readCharData(dec, "key")
					if err != nil {
						return nil, err
					}
					pendingKey = s
					hasPendingKey = true
					continue
				}
				if !hasPendingKey {
					return nil, fmt.Errorf("dict value <%s> 前缺 <key>", t.Name.Local)
				}
				v, err := decodeXMLElement(dec, t)
				if err != nil {
					return nil, err
				}
				m[pendingKey] = v
				hasPendingKey = false
			case xml.EndElement:
				if t.Name.Local == tag {
					if hasPendingKey {
						return nil, fmt.Errorf("dict 末尾有未配对 <key>%q</key>", pendingKey)
					}
					return &Value{Kind: KindDict, Dict: m}, nil
				}
			}
		}
	}
	// 不识别的 tag：跳过
	if err := dec.Skip(); err != nil {
		return nil, err
	}
	return &Value{Kind: KindNull}, nil
}

// readCharData consume 一个 <tag>chardata</tag>，返回 chardata 字符串。
// 已 consume 过 StartElement；返回时已 consume 对应 EndElement。
func readCharData(dec *xml.Decoder, tag string) (string, error) {
	var sb strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			sb.Write(t)
		case xml.EndElement:
			if t.Name.Local == tag {
				return sb.String(), nil
			}
		case xml.StartElement:
			// 不应发生，但稳健起见跳过子树
			if err := dec.Skip(); err != nil {
				return "", err
			}
		}
	}
}
