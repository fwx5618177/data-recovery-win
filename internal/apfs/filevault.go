package apfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"golang.org/x/crypto/pbkdf2"
)

// FileVault（APFS 卷加密）解密骨架。
//
// FileVault 在 APFS 上的真实流程极其复杂（KEK / VEK / Wrapped KEK chain / KeyBag 多版本，
// 以及 Recovery Partition 上的 PreBoot / Personal Recovery Key 等）。完整实现是一个独立
// 项目级工作量。本文件实现"已知 VEK 的情况下" + "AES-XTS 扇区解密"两层 ——
// 这两层是协议的下游、与具体上游协议无关。
//
// 给上层的 API：
//   1. NewFileVaultCipher(vek []byte, sectorSize int) — VEK 32 bytes (XTS-128) 或 64 bytes (XTS-256)
//   2. DecryptSector(dst, src []byte, blockNum uint64) — APFS 加密以 logical_block_addr 为 tweak
//
// 派生 VEK 的辅助：DeriveKEKFromPassword（PBKDF2-HMAC-SHA256 + UTF-16LE 编码 password），
// 模拟 macOS Recovery 模式输入用户密码后的派生路径。完整 KEK → VEK 解 wrap 还需要从 keybag
// 解出 wrapped key + AES-KeyWrap（RFC 3394）；本实现暂提供 PBKDF2 这一步 + 一个 stub 注释。
//
// 调用方：当用户能从 Apple Recovery / 取证工具拿到明文 VEK 时，本骨架可直接解扇区。
// 完整流程（用户密码 → keybag → KEK → VEK）需要 keybag parser，单独 PR。

// FileVaultXTSCipher 实现 SectorCipher 风格接口（不直接 import bitlocker.SectorCipher
// 是为了避免循环依赖；签名一致即可）
type FileVaultXTSCipher struct {
	dataCipher  cipher.Block
	tweakCipher cipher.Block
	sectorSize  int
}

// NewFileVaultCipher 用 32 / 64 字节的 VEK 构造 cipher。
// VEK 含 K1（数据加密）+ K2（tweak 派生），与 BitLocker XTS 完全一致。
func NewFileVaultCipher(vek []byte, sectorSize int) (*FileVaultXTSCipher, error) {
	if sectorSize <= 0 || sectorSize%16 != 0 {
		return nil, fmt.Errorf("sectorSize 必须是 16 倍数: %d", sectorSize)
	}
	var keyLen int
	switch len(vek) {
	case 32:
		keyLen = 16
	case 64:
		keyLen = 32
	default:
		return nil, fmt.Errorf("VEK 长度必须 32 或 64，得到 %d", len(vek))
	}
	dc, err := aes.NewCipher(vek[0:keyLen])
	if err != nil {
		return nil, fmt.Errorf("VEK K1 AES init: %w", err)
	}
	tc, err := aes.NewCipher(vek[keyLen : 2*keyLen])
	if err != nil {
		return nil, fmt.Errorf("VEK K2 AES init: %w", err)
	}
	return &FileVaultXTSCipher{
		dataCipher:  dc,
		tweakCipher: tc,
		sectorSize:  sectorSize,
	}, nil
}

func (c *FileVaultXTSCipher) SectorSize() int { return c.sectorSize }

// DecryptSector 用 AES-XTS 解一个扇区。tweak 计算与 BitLocker XTS 相同，唯一差别是
// "扇区编号"在 APFS 里是 logical_block_addr（容器内 4KB 块号）。
func (c *FileVaultXTSCipher) DecryptSector(dst, src []byte, blockNum uint64) error {
	if len(src) != c.sectorSize || len(dst) != c.sectorSize {
		return fmt.Errorf("扇区大小不一致")
	}
	// 初始 tweak = AES_K2(blockNum_LE_uint128)
	var tweak [16]byte
	binary.LittleEndian.PutUint64(tweak[0:8], blockNum)
	c.tweakCipher.Encrypt(tweak[:], tweak[:])

	for i := 0; i < c.sectorSize; i += 16 {
		// XOR tweak → AES decrypt → XOR tweak
		var blk [16]byte
		for j := 0; j < 16; j++ {
			blk[j] = src[i+j] ^ tweak[j]
		}
		c.dataCipher.Decrypt(blk[:], blk[:])
		for j := 0; j < 16; j++ {
			dst[i+j] = blk[j] ^ tweak[j]
		}
		// tweak 乘 α (GF(2^128))
		gfMulAlphaFV(&tweak)
	}
	return nil
}

// EncryptSector 加密反向（仅给测试 round-trip 用）
func (c *FileVaultXTSCipher) EncryptSector(dst, src []byte, blockNum uint64) error {
	if len(src) != c.sectorSize || len(dst) != c.sectorSize {
		return fmt.Errorf("扇区大小不一致")
	}
	var tweak [16]byte
	binary.LittleEndian.PutUint64(tweak[0:8], blockNum)
	c.tweakCipher.Encrypt(tweak[:], tweak[:])
	for i := 0; i < c.sectorSize; i += 16 {
		var blk [16]byte
		for j := 0; j < 16; j++ {
			blk[j] = src[i+j] ^ tweak[j]
		}
		c.dataCipher.Encrypt(blk[:], blk[:])
		for j := 0; j < 16; j++ {
			dst[i+j] = blk[j] ^ tweak[j]
		}
		gfMulAlphaFV(&tweak)
	}
	return nil
}

// gfMulAlphaFV 与 bitlocker.gfMulAlpha 相同算法（GF(2^128) 乘 α，溢出 ^= 0x87）；
// 本包独立一份避免循环依赖
func gfMulAlphaFV(t *[16]byte) {
	carry := byte(0)
	for i := 0; i < 16; i++ {
		newCarry := t[i] >> 7
		t[i] = (t[i] << 1) | carry
		carry = newCarry
	}
	if carry != 0 {
		t[0] ^= 0x87
	}
}

// =====================================================================
// PBKDF2 用户密码派生（KeyBag 解 wrap 的第一步）
//
// macOS Recovery 模式下输入用户密码后：
//   1. password → UTF-16LE
//   2. PBKDF2-HMAC-SHA256(password, salt_from_keybag, iter_from_keybag, 32) → derived_key
//   3. AES-KeyWrap(RFC 3394, derived_key, wrapped_kek_from_keybag) → KEK
//   4. AES-KeyWrap(KEK, wrapped_vek_from_keybag) → VEK
//
// 本函数只覆盖步骤 1+2；步骤 3/4 等 keybag parser 完成后再串起来。
// =====================================================================

// DeriveKeyFromPassword 模拟 macOS Recovery 的 password → derived_key 派生。
// 用 UTF-16LE 编码（注意是 LE，和 BitLocker password 用的 LE 编码一样）。
func DeriveKeyFromPassword(password string, salt []byte, iter, keyLen int) []byte {
	utf16Codes := utf16.Encode([]rune(password))
	buf := make([]byte, 2*len(utf16Codes))
	for i, c := range utf16Codes {
		binary.LittleEndian.PutUint16(buf[2*i:2*i+2], c)
	}
	return pbkdf2.Key(buf, salt, iter, keyLen, sha256.New)
}
