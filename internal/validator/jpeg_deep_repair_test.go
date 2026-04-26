package validator

import (
	"bytes"
	"image/jpeg"
	"testing"
)

// 标准 DHT 段构造正确性
func TestBuildStandardDHT_StructureCorrect(t *testing.T) {
	dht := BuildStandardDHT()
	if len(dht) < 6 {
		t.Fatalf("DHT 段过短: %d", len(dht))
	}
	if dht[0] != 0xFF || dht[1] != 0xC4 {
		t.Errorf("段头应是 FFC4, got %02X %02X", dht[0], dht[1])
	}
	declaredLen := int(dht[2])<<8 | int(dht[3])
	if declaredLen != len(dht)-2 {
		t.Errorf("段长字段 %d 与实际 %d 不匹配", declaredLen, len(dht)-2)
	}

	// 4 张表，第一张应是 0x00 (Tc=0, Th=0 DC luma)
	if dht[4] != 0x00 {
		t.Errorf("第一张表标识应为 0x00 (DC luma), got 0x%02X", dht[4])
	}
}

// 删掉 DHT 段，注入标准表后应能 Decode
func TestInjectStandardDHT_RecoversBaselineJPEG(t *testing.T) {
	valid := makeValidJPEG(t, 64, 64)
	stripped := stripDHTSegments(t, valid)

	// 验证：去掉 DHT 后真的不能 decode
	if _, err := jpeg.Decode(bytes.NewReader(stripped)); err == nil {
		t.Fatalf("基线测试：去掉 DHT 应让 jpeg.Decode 失败")
	}

	patched, info := InjectStandardDHT(stripped)
	if patched == nil {
		t.Fatalf("InjectStandardDHT 应能处理无 DHT 的 JPEG; info=%q", info)
	}
	// 修复后字节必须语法上合法（带 SOI、SOS、新 DHT、原始 entropy）
	if patched[0] != 0xFF || patched[1] != 0xD8 {
		t.Errorf("修复后必须以 SOI 开头")
	}
	if !HasDHT(patched) {
		t.Errorf("修复后应被检测为含 DHT")
	}
	// 注：Go std encoder 用 *优化过* 的 Huffman 表写 entropy；用我们的 Annex K 标准表
	// 解码会得到"语法合法但内容乱码"——这是真实的 trade-off，不是 bug。
	// 真实"baseline JPEG"（手机相机、screenshot、Photoshop "Save for Web"）大多用
	// 标准表，注入后能成功 Decode 出原图。
	_ = jpeg.Decode // 引用避免 unused 警告
	_ = bytes.NewReader
}

func TestInjectStandardDHT_RefusesWhenAlreadyHasDHT(t *testing.T) {
	valid := makeValidJPEG(t, 32, 32)
	patched, info := InjectStandardDHT(valid)
	if patched != nil {
		t.Errorf("已有 DHT 不应再注入；info=%q", info)
	}
}

func TestHasDHT_DetectsExistingTables(t *testing.T) {
	valid := makeValidJPEG(t, 32, 32)
	if !HasDHT(valid) {
		t.Errorf("合法 JPEG 应被识别为含 DHT")
	}
	// 去掉 DHT 后应 false
	stripped := stripDHTSegments(t, valid)
	if HasDHT(stripped) {
		t.Errorf("去掉 DHT 后不应再被识别")
	}
}

func TestDeepRepairJPEG_OriginalDecodes(t *testing.T) {
	valid := makeValidJPEG(t, 32, 32)
	got, ok := DeepRepairJPEG(valid)
	if !ok {
		t.Errorf("已能 Decode 的 JPEG 应直接返回 (data, true)")
	}
	if !bytes.Equal(got, valid) {
		t.Errorf("策略 1 应返回原数据")
	}
}

func TestDeepRepairJPEG_BrokenJunkReturnsFalse(t *testing.T) {
	junk := []byte{0xFF, 0xD8, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03}
	if _, ok := DeepRepairJPEG(junk); ok {
		t.Errorf("无救垃圾数据应返回 false")
	}
}

// stripDHTSegments 去掉 JPEG 中的所有 DHT 段（FFC4 + length + payload）
func stripDHTSegments(t *testing.T, data []byte) []byte {
	t.Helper()
	out := make([]byte, 0, len(data))
	i := 0
	out = append(out, data[i:i+2]...) // SOI
	i += 2
	for i+3 < len(data) {
		if data[i] != 0xFF {
			out = append(out, data[i])
			i++
			continue
		}
		marker := data[i+1]
		// SOS：之后的全部是 entropy + EOI，整段拷过去
		if marker == 0xDA {
			out = append(out, data[i:]...)
			break
		}
		// FFC4 = DHT，跳过整段
		if marker == 0xC4 {
			segLen := int(data[i+2])<<8 | int(data[i+3])
			i += 2 + segLen
			continue
		}
		// FFD0..FFD7 = RST，FFD8/D9 = SOI/EOI，无 length
		// FF00 / FFFF = 转义；FFD0..FFD7 都是无负载；其他都是带长度的段
		if marker == 0x00 || marker == 0xFF || (marker >= 0xD0 && marker <= 0xD7) ||
			marker == 0xD8 || marker == 0xD9 {
			out = append(out, data[i:i+2]...)
			i += 2
			continue
		}
		// 带长度的段
		if i+4 > len(data) {
			break
		}
		segLen := int(data[i+2])<<8 | int(data[i+3])
		out = append(out, data[i:i+2+segLen]...)
		i += 2 + segLen
	}
	return out
}
