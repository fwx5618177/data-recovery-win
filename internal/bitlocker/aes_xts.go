package bitlocker

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AES-XTS 实现（IEEE Std 1619-2007 / NIST SP 800-38E）。
//
// XTS = "XEX-based Tweaked codeBook with ciphertext Stealing"。
// 用于全盘加密：每个扇区独立加密，扇区号是 tweak。
//
// 密钥结构：
//   - K1（数据加密密钥）：AES-128 用 16 字节 / AES-256 用 32 字节
//   - K2（tweak 加密密钥）：同样长度
//   - 总密钥长度 = 32 字节（AES-XTS-128）或 64 字节（AES-XTS-256）
//
// BitLocker 用法（每扇区一个独立"data unit"）：
//   - sector size = 512 字节（默认）
//   - sector_number 当 tweak 编码进 16 字节小端整数
//   - 每 16 字节 AES 块独立处理：cipherBlock = AES_K1(plainBlock XOR T) XOR T
//     其中 T 起始 = AES_K2(sector_number)，每块乘以 α (= 2 在 GF(2^128))
//
// BitLocker 还有"512-byte 边界对齐"特殊处理：
//   - sector_size 必须是 16 字节倍数（512 是 OK）
//   - 数据长度恰好是 sector_size 时，不需要做密文窃取（ciphertext stealing），
//     最后一块也是规整 16 字节
//
// 我们的 BitLocker 用法只会用 512 字节 sector，所以**不实现 ciphertext stealing**；
// 输入长度必须是 16 的倍数 + 不少于 16 字节。

const (
	xtsBlockSize  = 16
	xtsSectorSize = 512 // BitLocker 默认；AES-XTS 标准允许 16-(2^20) 字节
)

// XTSCipher 用于解密一个 BitLocker 卷里的所有扇区。一次构造，多次复用。
type XTSCipher struct {
	dataCipher  cipher.Block // AES_K1
	tweakCipher cipher.Block // AES_K2
	sectorSize  int
}

// NewXTSCipher 用 BitLocker FVEK 构造 XTSCipher。
//
// fvek 长度必须是 32 字节（AES-XTS-128，K1+K2 各 16）或 64 字节（AES-XTS-256，K1+K2 各 32）。
// sectorSize 通常 512。
func NewXTSCipher(fvek []byte, sectorSize int) (*XTSCipher, error) {
	if sectorSize <= 0 || sectorSize%xtsBlockSize != 0 {
		return nil, fmt.Errorf("sectorSize 必须是 16 的正倍数，实际 %d", sectorSize)
	}
	switch len(fvek) {
	case 32: // AES-128
	case 64: // AES-256
	default:
		return nil, fmt.Errorf("FVEK 长度必须 32 或 64 字节，实际 %d", len(fvek))
	}

	half := len(fvek) / 2
	k1, err := aes.NewCipher(fvek[:half])
	if err != nil {
		return nil, fmt.Errorf("K1 AES 构造失败: %w", err)
	}
	k2, err := aes.NewCipher(fvek[half:])
	if err != nil {
		return nil, fmt.Errorf("K2 AES 构造失败: %w", err)
	}

	return &XTSCipher{
		dataCipher:  k1,
		tweakCipher: k2,
		sectorSize:  sectorSize,
	}, nil
}

// SectorSize 返回构造时指定的扇区大小
func (x *XTSCipher) SectorSize() int { return x.sectorSize }

// DecryptSector 解密单个扇区。
//
//	dst, src 长度必须 == sectorSize
//	sectorNumber 是 0-based 扇区号（XTS 标准的 "data unit number"）
//
// dst 与 src 可以相同（in-place）。
func (x *XTSCipher) DecryptSector(dst, src []byte, sectorNumber uint64) error {
	if len(src) != x.sectorSize || len(dst) != x.sectorSize {
		return fmt.Errorf("XTS sector 长度必须 == sectorSize=%d", x.sectorSize)
	}

	// 1. 计算初始 tweak T = AES_K2(sectorNumber-as-128bit-LE)
	var tweakInput [xtsBlockSize]byte
	tweakInput[0] = byte(sectorNumber)
	tweakInput[1] = byte(sectorNumber >> 8)
	tweakInput[2] = byte(sectorNumber >> 16)
	tweakInput[3] = byte(sectorNumber >> 24)
	tweakInput[4] = byte(sectorNumber >> 32)
	tweakInput[5] = byte(sectorNumber >> 40)
	tweakInput[6] = byte(sectorNumber >> 48)
	tweakInput[7] = byte(sectorNumber >> 56)
	// 高 8 字节是 0（sector 号 < 2^64 完全够用）

	var tweak [xtsBlockSize]byte
	x.tweakCipher.Encrypt(tweak[:], tweakInput[:])

	// 2. 逐 16 字节块处理
	tmp := make([]byte, xtsBlockSize)
	for off := 0; off < x.sectorSize; off += xtsBlockSize {
		// XOR src with current tweak
		for i := 0; i < xtsBlockSize; i++ {
			tmp[i] = src[off+i] ^ tweak[i]
		}
		// AES decrypt with K1
		x.dataCipher.Decrypt(tmp, tmp)
		// XOR tweak again
		for i := 0; i < xtsBlockSize; i++ {
			dst[off+i] = tmp[i] ^ tweak[i]
		}
		// 为下一块更新 tweak: T = T * α (GF(2^128))
		gfMulAlpha(&tweak)
	}
	return nil
}

// EncryptSector 加密单个扇区（仅供测试用，BitLocker 是只读场景）
func (x *XTSCipher) EncryptSector(dst, src []byte, sectorNumber uint64) error {
	if len(src) != x.sectorSize || len(dst) != x.sectorSize {
		return fmt.Errorf("XTS sector 长度必须 == sectorSize=%d", x.sectorSize)
	}

	var tweakInput [xtsBlockSize]byte
	tweakInput[0] = byte(sectorNumber)
	tweakInput[1] = byte(sectorNumber >> 8)
	tweakInput[2] = byte(sectorNumber >> 16)
	tweakInput[3] = byte(sectorNumber >> 24)
	tweakInput[4] = byte(sectorNumber >> 32)
	tweakInput[5] = byte(sectorNumber >> 40)
	tweakInput[6] = byte(sectorNumber >> 48)
	tweakInput[7] = byte(sectorNumber >> 56)

	var tweak [xtsBlockSize]byte
	x.tweakCipher.Encrypt(tweak[:], tweakInput[:])

	tmp := make([]byte, xtsBlockSize)
	for off := 0; off < x.sectorSize; off += xtsBlockSize {
		for i := 0; i < xtsBlockSize; i++ {
			tmp[i] = src[off+i] ^ tweak[i]
		}
		x.dataCipher.Encrypt(tmp, tmp)
		for i := 0; i < xtsBlockSize; i++ {
			dst[off+i] = tmp[i] ^ tweak[i]
		}
		gfMulAlpha(&tweak)
	}
	return nil
}

// gfMulAlpha 在 GF(2^128) 上把 tweak 乘 α（即左移 1 位，溢出时 XOR 0x87）。
//
// 不可约多项式：x^128 + x^7 + x^2 + x + 1 → 反映成 0x87
// 实际操作：当作 little-endian 128 位整数左移 1，bit 127 溢出 → XOR 0x87 到 byte 0
func gfMulAlpha(t *[xtsBlockSize]byte) {
	var carry byte
	for i := 0; i < xtsBlockSize; i++ {
		next := t[i] >> 7
		t[i] = (t[i] << 1) | carry
		carry = next
	}
	if carry != 0 {
		t[0] ^= 0x87
	}
}
