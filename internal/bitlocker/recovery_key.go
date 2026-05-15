package bitlocker

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// BitLocker 恢复密钥（Recovery Password）的标准格式：
//
//	48 个十进制数字，分成 8 组，每组 6 位，组间用 '-' 连接：
//	  XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
//
// 每 6 位数字的 / 11 = 一个 16 位无符号整数（< 65536），剩余即校验位（必须能被 11 整除）。
// 8 个 16-bit 整数按小端拼接 = 128-bit 中间密钥（intermediate key）。
//
// 这个 128-bit key 不直接用，要再走 stretch key 算法（SHA-256 迭代 1M 次 + salt）
// 才能得到能解 VMK 的实际 256-bit 密钥。
//
// 算法源：Microsoft [MS-FVE] § 3.2.4 + dislocker 源码 src/accesses/rp/recovery_password.c

// ParseRecoveryPassword 校验 + 转换 48 位恢复密钥为 16 字节中间密钥。
//
// 输入接受多种格式：
//
//	"111111-222222-333333-444444-555555-666666-777777-888888"
//	"111111 222222 ..."（空格代替连字符）
//	"111111222222...888888"（无分隔符）
//
// 校验包括：
//   - 必须刚好 48 个十进制数字
//   - 每 6 位数字必须能被 11 整除（Microsoft 校验位规则）
//   - 商必须 < 65536
func ParseRecoveryPassword(input string) ([16]byte, error) {
	var out [16]byte

	// 提取所有数字（容忍 -/空格/其他分隔符）
	var digits []byte
	for _, c := range input {
		if c >= '0' && c <= '9' {
			digits = append(digits, byte(c))
		}
	}
	if len(digits) != 48 {
		return out, fmt.Errorf("recovery key 应有 48 位数字，实际 %d", len(digits))
	}

	for i := 0; i < 8; i++ {
		group := string(digits[i*6 : (i+1)*6])
		// 解析 6 位数字
		var n uint64
		for _, c := range []byte(group) {
			n = n*10 + uint64(c-'0')
		}
		// Microsoft checksum：必须能被 11 整除
		if n%11 != 0 {
			return out, fmt.Errorf("第 %d 组 (%s) 不能被 11 整除（校验失败）", i+1, group)
		}
		quotient := n / 11
		if quotient >= 65536 {
			return out, fmt.Errorf("第 %d 组 (%s) 商 %d 超出 16 位范围", i+1, group, quotient)
		}
		// 小端写入
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], uint16(quotient))
	}

	return out, nil
}

// FormatRecoveryPassword 把 16 字节中间密钥逆转回标准 48 位 + 连字符的 recovery key。
// 仅供测试 / debug；生产用户不需要。
func FormatRecoveryPassword(key [16]byte) string {
	var groups []string
	for i := 0; i < 8; i++ {
		quotient := uint64(binary.LittleEndian.Uint16(key[i*2 : i*2+2]))
		original := quotient * 11
		groups = append(groups, fmt.Sprintf("%06d", original))
	}
	return strings.Join(groups, "-")
}
