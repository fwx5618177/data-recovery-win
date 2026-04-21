package apfs

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
)

// AES Key Wrap (RFC 3394) —— 把一个对称密钥用另一把对称密钥包/解包。
//
// FileVault 解密链：
//
//	user_password → PBKDF2 → derived_key
//	    ↓ AES-KeyUnwrap
//	wrapped_KEK  →  KEK
//	    ↓ AES-KeyUnwrap
//	wrapped_VEK  →  VEK   ← 真正的 AES-XTS 卷密钥
//
// RFC 3394 算法非常紧凑：6 轮、每轮 N 个 64-bit 块的混合 + 最终 IV (0xA6A6A6A6A6A6A6A6) 校验。

// KeyWrapDefaultIV 是 RFC 3394 的"unwrap 后必须看到"的固定 IV。
// 看不到 = 密钥不对 / 数据损坏。
var KeyWrapDefaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// AESKeyUnwrap 用 KEK 解开 wrapped key（长度通常 wrapped = key + 8）。
//
// 输入：
//
//	kek      解包密钥（16 / 24 / 32 字节）
//	wrapped  被包装的密钥（min 24 字节，必须 8 的倍数）
//
// 输出：原始 key（wrapped 长度 - 8 字节）；IV 不匹配返回 ErrIntegrityCheckFailed。
func AESKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("wrapped 长度无效: %d", len(wrapped))
	}
	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("AES init: %w", err)
	}
	n := len(wrapped)/8 - 1 // 数据块数

	// 初始化 A | R[1..n] = wrapped
	a := make([]byte, 8)
	copy(a, wrapped[0:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], wrapped[8+i*8:8+(i+1)*8])
	}

	// 6 轮 j=5..0；每轮 i=n..1
	block := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			// A ^= t  （t 按 64-bit big-endian 与 A XOR）
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)
			for k := 0; k < 8; k++ {
				a[k] ^= tBytes[k]
			}
			// 解密 (A | R[i])
			copy(block[0:8], a)
			copy(block[8:16], r[i-1])
			cipher.Decrypt(block, block)
			// 拆回去
			copy(a, block[0:8])
			copy(r[i-1], block[8:16])
		}
	}

	// 校验 IV
	for i := 0; i < 8; i++ {
		if a[i] != KeyWrapDefaultIV[i] {
			return nil, fmt.Errorf("AES KeyUnwrap IV 校验失败（密钥不对或数据损坏）")
		}
	}
	out := make([]byte, n*8)
	for i := 0; i < n; i++ {
		copy(out[i*8:(i+1)*8], r[i])
	}
	return out, nil
}

// AESKeyWrap RFC 3394 加密路径（仅给单元测试 round-trip 用）
func AESKeyWrap(kek, plain []byte) ([]byte, error) {
	if len(plain)%8 != 0 || len(plain) < 16 {
		return nil, fmt.Errorf("plain 长度必须 8 的倍数且 >=16: %d", len(plain))
	}
	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plain) / 8
	a := make([]byte, 8)
	copy(a, KeyWrapDefaultIV)
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plain[i*8:(i+1)*8])
	}
	block := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(block[0:8], a)
			copy(block[8:16], r[i-1])
			cipher.Encrypt(block, block)
			copy(a, block[0:8])
			copy(r[i-1], block[8:16])
			t := uint64(n*j + i)
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)
			for k := 0; k < 8; k++ {
				a[k] ^= tBytes[k]
			}
		}
	}
	out := make([]byte, (n+1)*8)
	copy(out[0:8], a)
	for i := 0; i < n; i++ {
		copy(out[8+i*8:16+i*8], r[i])
	}
	return out, nil
}
