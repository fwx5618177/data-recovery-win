// Package ios 负责 iOS 备份（iTunes / Finder MobileSync）的扫描与恢复。
//
// 本批次（Batch 3）范围：
//   - 本地已有的 MobileSync/Backup 目录扫描
//   - 未加密备份：直接按 SHA1(domain-relativePath) 映射到物理文件拷贝
//   - 加密备份：keybag 解包 + 每文件 class key → AES-CBC 解密
//
// 不做：用 USB 连手机拉备份（MTP/PTP），那属于 Batch 8。
package ios

// ============================================================================
// 最小 Apple binary plist (bplist00) 解析器
//
// 为什么自己写：
//   Apple plist 规范非常稳定（2002 年定型至今没动过），自己写 400 行纯 Go
//   可读代码 < 引一个第三方依赖（howett.net/plist 10k+ 行、有历史 CVE）。
//   对"会处理法律证据的工具"，每减一个依赖都是减一个 supply-chain 风险面。
//
// 覆盖范围：
//   - bplist00 版本（iOS 备份用的都是这个）
//   - null / bool / int (1/2/4/8 bytes) / real (4/8 bytes) / date (同 real)
//   - data (短/长) / string ASCII / string UTF-16BE / array / dict / UID
//   - offset table + trailer 完整解析
//   - XML plist（老 iTunes / 第三方备份导出有时是 XML；自动 fallback 到 XML 解析）
//
// 不覆盖：
//   - bplist15 / bplist16（Apple 新版，iOS 18+ 才偶尔出现，目前用不到）
//   - set 类型（iOS 备份不用）
// ============================================================================

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"
	"unicode/utf16"
)

// Value 是 plist 解析后的统一节点。
// 用 any 子字段而非 interface 是为了让调用方易辨认（Kind + Raw）。
type Value struct {
	Kind Kind

	Bool   bool
	Int    int64
	Real   float64
	Time   time.Time
	Data   []byte
	String string
	Array  []*Value
	Dict   map[string]*Value
	UID    uint64
}

// Kind 节点类型
type Kind int

const (
	KindNull Kind = iota
	KindBool
	KindInt
	KindReal
	KindDate
	KindData
	KindString
	KindArray
	KindDict
	KindUID
)

// ParsePlist 解析一段 plist 数据。bplist00 走 binary 路径；XML plist 自动转
// 给 ParseXMLPlist。返回根对象（通常是 dict）。
func ParsePlist(data []byte) (*Value, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("plist 太短: %d 字节", len(data))
	}
	// XML plist 优先识别（iTunes 老版本 / plutil -convert xml1 输出）
	if bytes.HasPrefix(data, []byte("<?xml")) || bytes.HasPrefix(data, []byte("<plist")) {
		return ParseXMLPlist(data)
	}
	if len(data) < 8+32 {
		return nil, fmt.Errorf("bplist 太短: %d 字节", len(data))
	}
	if !bytes.HasPrefix(data, []byte("bplist00")) {
		return nil, fmt.Errorf("不是 bplist00 魔数也不是 XML plist")
	}

	// trailer 在最后 32 字节：
	//   [5 保留] [1 sortVersion] [1 offsetIntSize] [1 objectRefSize]
	//   [8 numObjects] [8 topObject] [8 offsetTableOffset]
	trailerStart := len(data) - 32
	offsetIntSize := int(data[trailerStart+6])
	objectRefSize := int(data[trailerStart+7])
	numObjects := int(binary.BigEndian.Uint64(data[trailerStart+8:]))
	topObject := int(binary.BigEndian.Uint64(data[trailerStart+16:]))
	offsetTableOffset := int(binary.BigEndian.Uint64(data[trailerStart+24:]))

	if offsetIntSize < 1 || offsetIntSize > 8 || objectRefSize < 1 || objectRefSize > 8 {
		return nil, fmt.Errorf("bplist trailer 字段非法: offSize=%d refSize=%d", offsetIntSize, objectRefSize)
	}
	if numObjects <= 0 || numObjects > 1<<24 {
		return nil, fmt.Errorf("对象数目超界: %d", numObjects)
	}
	if topObject >= numObjects {
		return nil, fmt.Errorf("topObject %d 越界 (numObjects=%d)", topObject, numObjects)
	}

	// 读 offset table
	if offsetTableOffset+numObjects*offsetIntSize > len(data) {
		return nil, fmt.Errorf("offset table 越界")
	}
	offsets := make([]int, numObjects)
	for i := 0; i < numObjects; i++ {
		pos := offsetTableOffset + i*offsetIntSize
		offsets[i] = readBigEndianN(data[pos : pos+offsetIntSize])
	}

	p := &parser{
		buf:           data,
		offsets:       offsets,
		objectRefSize: objectRefSize,
		cache:         make(map[int]*Value, numObjects),
	}
	return p.decodeObject(topObject)
}

// 下面是内部解析器状态。

type parser struct {
	buf           []byte
	offsets       []int
	objectRefSize int
	cache         map[int]*Value
}

func (p *parser) decodeObject(idx int) (*Value, error) {
	if v, ok := p.cache[idx]; ok {
		return v, nil
	}
	if idx < 0 || idx >= len(p.offsets) {
		return nil, fmt.Errorf("对象索引越界: %d", idx)
	}
	off := p.offsets[idx]
	if off >= len(p.buf) {
		return nil, fmt.Errorf("对象偏移越界: %d", off)
	}
	v, err := p.decodeAt(off)
	if err != nil {
		return nil, err
	}
	p.cache[idx] = v
	return v, nil
}

// decodeAt 从字节流 offset 处解码一个对象。
// 首字节 marker 的高 4 位 = 类型，低 4 位 = 小参数（通常是长度或位宽）。
func (p *parser) decodeAt(off int) (*Value, error) {
	if off >= len(p.buf) {
		return nil, fmt.Errorf("decode 越界")
	}
	marker := p.buf[off]
	hi := marker >> 4
	lo := marker & 0x0F

	switch hi {
	case 0x0: // 特殊：null / true / false / fill
		switch lo {
		case 0x00:
			return &Value{Kind: KindNull}, nil
		case 0x08:
			return &Value{Kind: KindBool, Bool: false}, nil
		case 0x09:
			return &Value{Kind: KindBool, Bool: true}, nil
		case 0x0F:
			return &Value{Kind: KindNull}, nil
		default:
			return nil, fmt.Errorf("未知 singleton marker: %02X", marker)
		}
	case 0x1: // int：长度 = 2^lo 字节
		size := 1 << lo
		if off+1+size > len(p.buf) {
			return nil, fmt.Errorf("int 越界")
		}
		v := readBigEndianSigned(p.buf[off+1 : off+1+size])
		return &Value{Kind: KindInt, Int: v}, nil
	case 0x2: // real：长度 = 2^lo 字节
		size := 1 << lo
		if off+1+size > len(p.buf) {
			return nil, fmt.Errorf("real 越界")
		}
		switch size {
		case 4:
			bits := binary.BigEndian.Uint32(p.buf[off+1:])
			return &Value{Kind: KindReal, Real: float64(math.Float32frombits(bits))}, nil
		case 8:
			bits := binary.BigEndian.Uint64(p.buf[off+1:])
			return &Value{Kind: KindReal, Real: math.Float64frombits(bits)}, nil
		default:
			return nil, fmt.Errorf("不支持的 real 长度: %d", size)
		}
	case 0x3: // date：8 字节 float，自 2001-01-01 UTC 的秒数
		if off+9 > len(p.buf) {
			return nil, fmt.Errorf("date 越界")
		}
		secs := math.Float64frombits(binary.BigEndian.Uint64(p.buf[off+1:]))
		base := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		return &Value{Kind: KindDate, Time: base.Add(time.Duration(secs * float64(time.Second)))}, nil
	case 0x4: // data
		length, hdrLen, err := p.readLength(off, lo)
		if err != nil {
			return nil, err
		}
		if off+hdrLen+length > len(p.buf) {
			return nil, fmt.Errorf("data 越界")
		}
		d := make([]byte, length)
		copy(d, p.buf[off+hdrLen:off+hdrLen+length])
		return &Value{Kind: KindData, Data: d}, nil
	case 0x5: // ASCII string
		length, hdrLen, err := p.readLength(off, lo)
		if err != nil {
			return nil, err
		}
		if off+hdrLen+length > len(p.buf) {
			return nil, fmt.Errorf("ASCII string 越界")
		}
		return &Value{Kind: KindString, String: string(p.buf[off+hdrLen : off+hdrLen+length])}, nil
	case 0x6: // UTF-16BE string
		charCount, hdrLen, err := p.readLength(off, lo)
		if err != nil {
			return nil, err
		}
		byteLen := charCount * 2
		if off+hdrLen+byteLen > len(p.buf) {
			return nil, fmt.Errorf("UTF-16 string 越界")
		}
		u := make([]uint16, charCount)
		for i := 0; i < charCount; i++ {
			u[i] = binary.BigEndian.Uint16(p.buf[off+hdrLen+i*2:])
		}
		return &Value{Kind: KindString, String: string(utf16.Decode(u))}, nil
	case 0x8: // UID
		size := int(lo) + 1
		if off+1+size > len(p.buf) {
			return nil, fmt.Errorf("UID 越界")
		}
		u := uint64(0)
		for i := 0; i < size; i++ {
			u = (u << 8) | uint64(p.buf[off+1+i])
		}
		return &Value{Kind: KindUID, UID: u}, nil
	case 0xA, 0xC: // array / set（按同样的引用序列读）
		count, hdrLen, err := p.readLength(off, lo)
		if err != nil {
			return nil, err
		}
		refs, err := p.readObjectRefs(off+hdrLen, count)
		if err != nil {
			return nil, err
		}
		items := make([]*Value, count)
		for i, r := range refs {
			v, err := p.decodeObject(r)
			if err != nil {
				return nil, err
			}
			items[i] = v
		}
		return &Value{Kind: KindArray, Array: items}, nil
	case 0xD: // dict
		count, hdrLen, err := p.readLength(off, lo)
		if err != nil {
			return nil, err
		}
		keyRefs, err := p.readObjectRefs(off+hdrLen, count)
		if err != nil {
			return nil, err
		}
		valRefs, err := p.readObjectRefs(off+hdrLen+count*p.objectRefSize, count)
		if err != nil {
			return nil, err
		}
		m := make(map[string]*Value, count)
		for i := 0; i < count; i++ {
			k, err := p.decodeObject(keyRefs[i])
			if err != nil {
				return nil, err
			}
			if k.Kind != KindString {
				return nil, fmt.Errorf("dict key 不是字符串: %v", k.Kind)
			}
			v, err := p.decodeObject(valRefs[i])
			if err != nil {
				return nil, err
			}
			m[k.String] = v
		}
		return &Value{Kind: KindDict, Dict: m}, nil
	}
	return nil, fmt.Errorf("未知 marker 高位: %X", hi)
}

// readLength 处理"lo == 0xF 时实际长度跟在 marker 后面作为 int 对象"的情况
func (p *parser) readLength(off int, lo byte) (length, hdrLen int, err error) {
	if lo != 0x0F {
		return int(lo), 1, nil
	}
	// 下一个 byte 是 int marker (type=0x1)，后面跟 1/2/4/8 字节
	if off+1 >= len(p.buf) {
		return 0, 0, fmt.Errorf("扩展长度越界")
	}
	nextMarker := p.buf[off+1]
	if nextMarker>>4 != 0x1 {
		return 0, 0, fmt.Errorf("扩展长度格式非法: %02X", nextMarker)
	}
	size := 1 << (nextMarker & 0x0F)
	if off+2+size > len(p.buf) {
		return 0, 0, fmt.Errorf("扩展长度字节越界")
	}
	length = readBigEndianN(p.buf[off+2 : off+2+size])
	hdrLen = 2 + size
	return
}

// readObjectRefs 从 pos 开始读 count 个对象引用（每个 objectRefSize 字节）
func (p *parser) readObjectRefs(pos, count int) ([]int, error) {
	end := pos + count*p.objectRefSize
	if end > len(p.buf) {
		return nil, fmt.Errorf("对象引用越界")
	}
	refs := make([]int, count)
	for i := 0; i < count; i++ {
		refs[i] = readBigEndianN(p.buf[pos+i*p.objectRefSize : pos+(i+1)*p.objectRefSize])
	}
	return refs, nil
}

// readBigEndianN 读 n 字节无符号大端整数（n ≤ 8）
func readBigEndianN(b []byte) int {
	v := 0
	for _, c := range b {
		v = (v << 8) | int(c)
	}
	return v
}

// readBigEndianSigned 读带符号大端整数（bplist int 是这么定义的：1/2/4 字节无符号，8 字节可为带符号）
func readBigEndianSigned(b []byte) int64 {
	if len(b) == 8 {
		return int64(binary.BigEndian.Uint64(b))
	}
	return int64(readBigEndianN(b))
}

// ---------- 便捷访问 ----------

// GetString 从 dict 里拿指定 key 的字符串；缺失或类型不对返回 ""。
func (v *Value) GetString(key string) string {
	if v == nil || v.Kind != KindDict {
		return ""
	}
	item := v.Dict[key]
	if item == nil || item.Kind != KindString {
		return ""
	}
	return item.String
}

// GetBool dict 里拿 bool；缺失返回默认值。
func (v *Value) GetBool(key string, dflt bool) bool {
	if v == nil || v.Kind != KindDict {
		return dflt
	}
	item := v.Dict[key]
	if item == nil || item.Kind != KindBool {
		return dflt
	}
	return item.Bool
}

// GetInt dict 里拿 int。
func (v *Value) GetInt(key string) (int64, bool) {
	if v == nil || v.Kind != KindDict {
		return 0, false
	}
	item := v.Dict[key]
	if item == nil || item.Kind != KindInt {
		return 0, false
	}
	return item.Int, true
}

// GetData dict 里拿 data。
func (v *Value) GetData(key string) []byte {
	if v == nil || v.Kind != KindDict {
		return nil
	}
	item := v.Dict[key]
	if item == nil || item.Kind != KindData {
		return nil
	}
	return item.Data
}

// GetDict 拿子 dict。
func (v *Value) GetDict(key string) *Value {
	if v == nil || v.Kind != KindDict {
		return nil
	}
	item := v.Dict[key]
	if item == nil || item.Kind != KindDict {
		return nil
	}
	return item
}
