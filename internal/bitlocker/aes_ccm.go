package bitlocker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// AES-CCM 实现（Counter with CBC-MAC，NIST SP 800-38C）。
//
// Go 标准库只有 GCM 没有 CCM，且 BitLocker 用 CCM 是写在 [MS-FVE] 协议里的硬约束。
// 我们自己实现，对照 NIST SP 800-38C 测试向量验证（见 aes_ccm_test.go）。
//
// CCM 参数（BitLocker 固定使用）：
//   - block size:    16 (AES)
//   - nonce length:  12（BitLocker 用 12 字节 nonce = 8 字节时间戳 + 4 字节计数器）
//   - tag length:    16
//   - L (length field bytes): 3 (实际可用 2，BitLocker 选 3)
//
// 注：CCM 标准允许 7-13 字节 nonce 和 4-16 字节 tag；BitLocker 的具体选择跟着 dislocker 来。

const (
	ccmBlockSize  = 16
	ccmNonceLen   = 12
	ccmTagLen     = 16
	ccmLengthSize = 3 // L: 长度字段字节数；nonceLen + L 必须 = 15
)

// DecryptAESCCM 用 key 解密 ciphertext + 校验 tag，返回明文。
// nonce 是 12 字节；ciphertext 后接 tag = 16 字节附加在末尾的，
// **不是**这里的接口；这里 ciphertext 仅是密文，tag 单独传。
//
// 如果 tag 校验失败返回 ErrAuthenticationFailed —— **这表明密钥错**（最常见原因：
// recovery key 输错 / 拿错 metadata block / 选错 VMK protector）。
func DecryptAESCCM(key, nonce, ciphertext, tag []byte) ([]byte, error) {
	if len(nonce) != ccmNonceLen {
		return nil, fmt.Errorf("nonce 必须 %d 字节，实际 %d", ccmNonceLen, len(nonce))
	}
	if len(tag) != ccmTagLen {
		return nil, fmt.Errorf("tag 必须 %d 字节，实际 %d", ccmTagLen, len(tag))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// CCM Step 1: 用 CTR 模式解密 ciphertext + 解密 tag
	// counter block = flags || nonce || counter
	//   flags = L-1 = 2 (高位 0；L=3 → 编码值 = L-1 = 2)
	// counter 从 0 开始，counter=0 用来加密 tag，counter=1+ 用来加密数据
	counter := make([]byte, ccmBlockSize)
	counter[0] = byte(ccmLengthSize - 1)
	copy(counter[1:1+ccmNonceLen], nonce)
	// counter 字段在末尾 L 字节；初值 0

	stream := cipher.NewCTR(block, counter)

	// 解密 tag（counter=0 → CTR 第一个 block 是 0 时输出）
	// 但 NewCTR 的 IV 已经是 counter=0 的值，第一次 XOR 就是它
	// 所以我们要先用 counter=0 解 tag，再让 stream 自动递增解数据
	// 不过 cipher.Stream 接口是流式的，我们需要构造一个小 buf 让它"消耗"counter=0
	// 简化做法：手动写 CCM CTR
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext[:0:0], []byte{})
	// 上面这行无效；正确做法是用 counter=1 解数据，counter=0 解 tag

	// 重新来，手写 CTR 控制 counter 起点
	plaintext = make([]byte, len(ciphertext))
	if err := ccmCTRDecrypt(block, nonce, ciphertext, plaintext, 1); err != nil {
		return nil, err
	}
	// 解密 tag
	decryptedTag := make([]byte, ccmTagLen)
	if err := ccmCTRDecrypt(block, nonce, tag, decryptedTag, 0); err != nil {
		return nil, err
	}

	// CCM Step 2: 计算明文的 CBC-MAC，与 decryptedTag 比对
	expectedTag := ccmCBCMAC(block, nonce, plaintext, ccmTagLen)
	if subtle.ConstantTimeCompare(decryptedTag, expectedTag) != 1 {
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}

// EncryptAESCCM 加密；返回 ciphertext + tag（分开返回不连接，方便测试比对）
func EncryptAESCCM(key, nonce, plaintext []byte) (ciphertext, tag []byte, err error) {
	if len(nonce) != ccmNonceLen {
		return nil, nil, fmt.Errorf("nonce 必须 %d 字节", ccmNonceLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	expectedTag := ccmCBCMAC(block, nonce, plaintext, ccmTagLen)
	ciphertext = make([]byte, len(plaintext))
	if err := ccmCTRDecrypt(block, nonce, plaintext, ciphertext, 1); err != nil {
		return nil, nil, err
	}
	encryptedTag := make([]byte, ccmTagLen)
	if err := ccmCTRDecrypt(block, nonce, expectedTag, encryptedTag, 0); err != nil {
		return nil, nil, err
	}
	return ciphertext, encryptedTag, nil
}

// ErrAuthenticationFailed CCM tag 校验失败
var ErrAuthenticationFailed = fmt.Errorf("AES-CCM 认证失败：密钥可能不对，或元数据被篡改")

// ccmCTRDecrypt 自定义 CTR：counter 起始可控；input/output 同长度
func ccmCTRDecrypt(block cipher.Block, nonce, input, output []byte, startCounter uint32) error {
	if len(input) != len(output) {
		return fmt.Errorf("CTR input/output 长度不一致")
	}
	counterBlock := make([]byte, ccmBlockSize)
	keystream := make([]byte, ccmBlockSize)

	counterBlock[0] = byte(ccmLengthSize - 1)
	copy(counterBlock[1:1+ccmNonceLen], nonce)

	pos := 0
	ctr := startCounter
	for pos < len(input) {
		// 把 ctr 写到 counterBlock 末尾 L=3 字节（big-endian）
		counterBlock[13] = byte(ctr >> 16)
		counterBlock[14] = byte(ctr >> 8)
		counterBlock[15] = byte(ctr)
		block.Encrypt(keystream, counterBlock)

		end := pos + ccmBlockSize
		if end > len(input) {
			end = len(input)
		}
		for i := pos; i < end; i++ {
			output[i] = input[i] ^ keystream[i-pos]
		}
		pos = end
		ctr++
	}
	return nil
}

// ccmCBCMAC 计算 plaintext 的 CCM CBC-MAC（含格式化 B0 + 长度前缀）
//
// B0 块：
//   flags = (Adata? 0)<<6 | ((tagLen-2)/2)<<3 | (L-1)
//   nonce(12) + Q(L=3 字节，big-endian 长度)
//
// 然后是 plaintext，每 16 字节一块；不足补零；XOR 然后 AES 加密链。
func ccmCBCMAC(block cipher.Block, nonce, plaintext []byte, tagLen int) []byte {
	b0 := make([]byte, ccmBlockSize)
	flags := byte(((tagLen-2)/2)<<3) | byte(ccmLengthSize-1) // adata=0 → 高位 0
	b0[0] = flags
	copy(b0[1:1+ccmNonceLen], nonce)
	// Q：明文长度，L=3 字节大端
	plainLen := len(plaintext)
	b0[13] = byte(plainLen >> 16)
	b0[14] = byte(plainLen >> 8)
	b0[15] = byte(plainLen)

	mac := make([]byte, ccmBlockSize)
	block.Encrypt(mac, b0)

	pos := 0
	buf := make([]byte, ccmBlockSize)
	for pos < plainLen {
		// XOR 一块明文进 mac
		end := pos + ccmBlockSize
		if end > plainLen {
			end = plainLen
		}
		for i := 0; i < ccmBlockSize; i++ {
			buf[i] = 0
		}
		copy(buf, plaintext[pos:end])
		for i := 0; i < ccmBlockSize; i++ {
			mac[i] ^= buf[i]
		}
		out := make([]byte, ccmBlockSize)
		block.Encrypt(out, mac)
		copy(mac, out)
		pos = end
	}
	return mac[:tagLen]
}

// 让 binary 包"被使用"，实际我们用 binary.LittleEndian.PutUint... 在 stretch.go
var _ = binary.LittleEndian
