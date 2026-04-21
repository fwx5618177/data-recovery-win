package bitlocker

import (
	"bytes"
	"testing"
)

func TestParseRecoveryPassword_ValidExamples(t *testing.T) {
	// 这些 key 都是手工构造的：每组数字 / 11 = < 65536 的整数。
	// 用 FormatRecoveryPassword 的逆函数验证 round-trip。
	cases := []struct {
		name string
		raw  string
	}{
		// 全零（每组 = 0，能被 11 整除）
		{"all-zero", "000000-000000-000000-000000-000000-000000-000000-000000"},
		// 验算：100958/11=9178、067419/11=6129、080553/11=7323、145618/11=13238
		// 321024/11=29184、720885/11=65535（最大允许值）、000011/11=1、000022/11=2
		{"sample-1", "100958-067419-080553-145618-321024-720885-000011-000022"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := ParseRecoveryPassword(c.raw)
			if err != nil {
				t.Fatalf("ParseRecoveryPassword(%q): %v", c.raw, err)
			}
			// round-trip
			back := FormatRecoveryPassword(key)
			if back != c.raw {
				t.Errorf("round-trip 失败:\n  in  %s\n  out %s", c.raw, back)
			}
		})
	}
}

func TestParseRecoveryPassword_FormatTolerance(t *testing.T) {
	// 各组都 < 720896 且能被 11 整除：
	// 111111/11=10101, 222222/11=20202, 333333/11=30303, 444444/11=40404,
	// 555555/11=50505, 666666/11=60606, 100100/11=9100, 200200/11=18200
	canonical := "111111-222222-333333-444444-555555-666666-100100-200200"
	// 校验：111111 / 11 = 10101 ✓；222222 / 11 = 20202 ✓ 等等
	expected, err := ParseRecoveryPassword(canonical)
	if err != nil {
		t.Fatalf("canonical 解析失败: %v", err)
	}

	variants := []string{
		"111111 222222 333333 444444 555555 666666 100100 200200",   // 空格
		"111111222222333333444444555555666666100100200200",          // 无分隔符
		"111111-222222-333333-444444-555555-666666-100100-200200\n", // 尾部换行
	}
	for _, v := range variants {
		got, err := ParseRecoveryPassword(v)
		if err != nil {
			t.Errorf("variant %q 解析失败: %v", v, err)
			continue
		}
		if !bytes.Equal(got[:], expected[:]) {
			t.Errorf("variant 解出来不一致")
		}
	}
}

func TestParseRecoveryPassword_RejectsBadChecksum(t *testing.T) {
	// 100959 / 11 = 9178.09... 非整除
	bad := "100959-067419-080553-145620-321024-720896-000011-000022"
	if _, err := ParseRecoveryPassword(bad); err == nil {
		t.Error("不能被 11 整除的组应被拒")
	}
}

func TestParseRecoveryPassword_RejectsBadLength(t *testing.T) {
	cases := []string{
		"111111-222222",     // 太短
		"111111-2222222-333333-444444-555555-666666-777777-888888", // 7 位组
		"",
		"abcdef-111111",
	}
	for _, c := range cases {
		if _, err := ParseRecoveryPassword(c); err == nil {
			t.Errorf("非法格式 %q 应被拒", c)
		}
	}
}

func TestParseRecoveryPassword_RejectsOverflow(t *testing.T) {
	// 720907 / 11 = 65537，超出 16 位
	bad := "720907-000000-000000-000000-000000-000000-000000-000000"
	if _, err := ParseRecoveryPassword(bad); err == nil {
		t.Error("商超出 16 位应被拒")
	}
}
