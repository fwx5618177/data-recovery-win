package ios

// ============================================================================
// bplist00 反向写入
//
// 镜像 bplist.go 的 reader 路径：把 *Value 树编码回 Apple binary plist 字节流。
//
// 用途：取证报告里 manifest.plist / 自定义 metadata 用 bplist 比 XML 更兼容
// macOS 工具链（plutil / Apple Configurator / Magnet AXIOM / R-Studio Mac）
// 直接吃 binary plist 不需要先转换。
//
// 实现策略：
//   1. DFS 线性化所有 Value → 分配 idx（每个子 Value 算独立对象，不去重）
//   2. 计算 objectRefSize（根据对象数）
//   3. 编码每个对象到中间 buffer，记录 offset
//   4. 计算 offsetIntSize（根据最大 offset）
//   5. 写完整 bplist00：magic + objects + offset table + trailer (32B)
//
// 不实现的部分（与 reader 对应；扫描 / 写回路径都不需要）：
//   - bplist1x（v15/v16，Apple 内部格式，开源工具普遍不支持）
//   - 对象去重（writes are functional but produce slightly larger files）
//   - set 类型（marker 0xC，iOS 备份不用）
// ============================================================================

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// encodePlan 是 EncodePlist 的内部规划：
// objects[] 是线性化的对象列表，idx 是 *Value → 对应 idx，
// dictKeyOrder 给每个 dict 记录它的 key *Value 列表（顺序与 dict value 列表对齐）。
type encodePlan struct {
	objects      []*Value
	idx          map[*Value]int
	dictKeyOrder map[*Value][]*Value
}

// EncodePlist 把 *Value 编码成 bplist00 二进制字节流。
//
// 错误条件：
//   - root == nil
//   - 整数超出 64-bit 范围（不会发生：Value.Int 已是 int64）
func EncodePlist(root *Value) ([]byte, error) {
	if root == nil {
		return nil, fmt.Errorf("EncodePlist: root 为 nil")
	}

	plan := &encodePlan{
		idx:          make(map[*Value]int),
		dictKeyOrder: make(map[*Value][]*Value),
	}
	var collect func(v *Value)
	collect = func(v *Value) {
		plan.idx[v] = len(plan.objects)
		plan.objects = append(plan.objects, v)
		switch v.Kind {
		case KindArray:
			for _, item := range v.Array {
				collect(item)
			}
		case KindDict:
			// 字典序保证稳定 + 与 plutil 输出一致
			keys := make([]string, 0, len(v.Dict))
			for k := range v.Dict {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			// 先收集所有 key Value（独立对象），存到 dictKeyOrder
			keyVals := make([]*Value, len(keys))
			for i, k := range keys {
				kv := &Value{Kind: KindString, String: k}
				keyVals[i] = kv
				collect(kv)
			}
			plan.dictKeyOrder[v] = keyVals
			// 再收集所有 value（顺序与 keys 对齐）
			for _, k := range keys {
				collect(v.Dict[k])
			}
		}
	}
	collect(root)

	numObjects := len(plan.objects)
	objectRefSize := minBytesFor(uint64(numObjects))
	if objectRefSize < 1 {
		objectRefSize = 1
	}

	// 编码每个对象到中间 buffer，记录 offset
	body := []byte("bplist00")
	offsets := make([]int, numObjects)

	for i, o := range plan.objects {
		offsets[i] = len(body)
		enc, err := encodeObject(o, objectRefSize, plan)
		if err != nil {
			return nil, fmt.Errorf("编码对象 #%d (kind=%v): %w", i, o.Kind, err)
		}
		body = append(body, enc...)
	}

	// 4) 决定 offsetIntSize（根据最大 offset = body 末尾位置）
	maxOff := uint64(len(body))
	offsetIntSize := minBytesFor(maxOff)
	if offsetIntSize < 1 {
		offsetIntSize = 1
	}

	// 5) 写 offset table
	offsetTableOffset := len(body)
	for _, off := range offsets {
		body = appendBigEndianN(body, uint64(off), offsetIntSize)
	}

	// 6) 写 32B trailer
	trailer := make([]byte, 32)
	// [0..5] reserved (zeros)
	// [5] sortVersion = 0
	// [6] offsetIntSize
	trailer[6] = byte(offsetIntSize)
	// [7] objectRefSize
	trailer[7] = byte(objectRefSize)
	// [8..16] numObjects
	binary.BigEndian.PutUint64(trailer[8:16], uint64(numObjects))
	// [16..24] topObject (root 是 objects[0])
	binary.BigEndian.PutUint64(trailer[16:24], 0)
	// [24..32] offsetTableOffset
	binary.BigEndian.PutUint64(trailer[24:32], uint64(offsetTableOffset))
	body = append(body, trailer...)

	return body, nil
}

// encodeObject 把单个 Value 编码成它在 bplist body 里的字节序列。
// 子对象引用通过 plan.idx 查到 objectRef 后写 objectRefSize 字节。
func encodeObject(v *Value, objectRefSize int, plan *encodePlan) ([]byte, error) {
	switch v.Kind {
	case KindNull:
		return []byte{0x00}, nil
	case KindBool:
		if v.Bool {
			return []byte{0x09}, nil
		}
		return []byte{0x08}, nil
	case KindInt:
		return encodeInt(v.Int), nil
	case KindReal:
		// 8 字节 IEEE 754 double
		var buf [9]byte
		buf[0] = 0x23 // marker 0x2 + size index 3 (= 2^3 = 8 字节)
		binary.BigEndian.PutUint64(buf[1:], math.Float64bits(v.Real))
		return buf[:], nil
	case KindDate:
		// 8 字节 double，自 2001-01-01 UTC 起秒数
		base := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		secs := v.Time.Sub(base).Seconds()
		var buf [9]byte
		buf[0] = 0x33 // date marker 固定 0x33
		binary.BigEndian.PutUint64(buf[1:], math.Float64bits(secs))
		return buf[:], nil
	case KindData:
		hdr := encodeMarkerLen(0x40, len(v.Data))
		out := make([]byte, 0, len(hdr)+len(v.Data))
		out = append(out, hdr...)
		out = append(out, v.Data...)
		return out, nil
	case KindString:
		return encodeString(v.String), nil
	case KindUID:
		return encodeUID(v.UID), nil
	case KindArray:
		hdr := encodeMarkerLen(0xA0, len(v.Array))
		out := make([]byte, 0, len(hdr)+len(v.Array)*objectRefSize)
		out = append(out, hdr...)
		for _, item := range v.Array {
			ref, ok := plan.idx[item]
			if !ok {
				return nil, fmt.Errorf("array 子项未在 idx 表里")
			}
			out = appendBigEndianN(out, uint64(ref), objectRefSize)
		}
		return out, nil
	case KindDict:
		keyVals := plan.dictKeyOrder[v]
		// 与 collect() 同样的字典序拿 value，与 keyVals 顺序对齐
		keys := make([]string, 0, len(v.Dict))
		for k := range v.Dict {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) != len(keyVals) {
			return nil, fmt.Errorf("dict keyVals 数 (%d) 与 keys 数 (%d) 不一致 —— collect() 状态损坏", len(keyVals), len(keys))
		}
		hdr := encodeMarkerLen(0xD0, len(keys))
		out := make([]byte, 0, len(hdr)+2*len(keys)*objectRefSize)
		out = append(out, hdr...)

		// 先全部 key refs（指向 collect 时收集的临时 keyVal 对象）
		for _, kv := range keyVals {
			ref, ok := plan.idx[kv]
			if !ok {
				return nil, fmt.Errorf("dict key Value 未在 idx 表里")
			}
			out = appendBigEndianN(out, uint64(ref), objectRefSize)
		}
		// 再全部 value refs
		for _, k := range keys {
			val := v.Dict[k]
			ref, ok := plan.idx[val]
			if !ok {
				return nil, fmt.Errorf("dict value Value (key=%q) 未在 idx 表里", k)
			}
			out = appendBigEndianN(out, uint64(ref), objectRefSize)
		}
		return out, nil
	}
	return nil, fmt.Errorf("未知 Kind: %v", v.Kind)
}

// encodeInt 按值大小选最小字节宽度
func encodeInt(n int64) []byte {
	switch {
	case n >= 0 && n <= 0xFF:
		return []byte{0x10, byte(n)}
	case n >= 0 && n <= 0xFFFF:
		var buf [3]byte
		buf[0] = 0x11
		binary.BigEndian.PutUint16(buf[1:], uint16(n))
		return buf[:]
	case n >= 0 && n <= 0xFFFFFFFF:
		var buf [5]byte
		buf[0] = 0x12
		binary.BigEndian.PutUint32(buf[1:], uint32(n))
		return buf[:]
	default:
		// 64-bit（含负数）
		var buf [9]byte
		buf[0] = 0x13
		binary.BigEndian.PutUint64(buf[1:], uint64(n))
		return buf[:]
	}
}

// encodeString ASCII 走 marker 0x5；含非 ASCII 走 UTF-16BE marker 0x6
func encodeString(s string) []byte {
	if isASCII(s) {
		hdr := encodeMarkerLen(0x50, len(s))
		out := make([]byte, 0, len(hdr)+len(s))
		out = append(out, hdr...)
		out = append(out, s...)
		return out
	}
	// UTF-16BE
	runes := []rune(s)
	u := utf16.Encode(runes)
	hdr := encodeMarkerLen(0x60, len(u))
	out := make([]byte, 0, len(hdr)+len(u)*2)
	out = append(out, hdr...)
	for _, c := range u {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], c)
		out = append(out, b[:]...)
	}
	return out
}

// encodeUID 1..8 字节 BE
func encodeUID(u uint64) []byte {
	n := minBytesFor(u)
	if n < 1 {
		n = 1
	}
	out := make([]byte, 1+n)
	out[0] = 0x80 | byte(n-1) // 0x80 + (n-1) per spec
	for i := n - 1; i >= 0; i-- {
		out[1+i] = byte(u & 0xFF)
		u >>= 8
	}
	return out
}

// encodeMarkerLen 写 markerHi (0x4 / 0x5 / 0x6 / 0xA / 0xD 的高 4 位 + 0)
// + 长度。length < 15 直接塞 lo nibble；≥15 用 0xF + int 跟在后面
func encodeMarkerLen(markerHi byte, length int) []byte {
	if length < 15 {
		return []byte{markerHi | byte(length)}
	}
	// 0xF 后跟 int 对象（marker 0x1n + bytes）
	intBytes := encodeInt(int64(length))
	out := make([]byte, 0, 1+len(intBytes))
	out = append(out, markerHi|0x0F)
	out = append(out, intBytes...)
	return out
}

// appendBigEndianN 把 v 按 n 字节大端追加到 buf
func appendBigEndianN(buf []byte, v uint64, n int) []byte {
	for i := n - 1; i >= 0; i-- {
		buf = append(buf, byte((v>>(uint(i)*8))&0xFF))
	}
	return buf
}

// minBytesFor 返回容纳 v 所需的最小字节数（1..8）
func minBytesFor(v uint64) int {
	switch {
	case v <= 0xFF:
		return 1
	case v <= 0xFFFF:
		return 2
	case v <= 0xFFFFFFFF:
		return 4
	default:
		return 8
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return utf8.ValidString(s)
}
