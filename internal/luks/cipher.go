package luks

// ============================================================================
// LUKS keyslot 区域加密 / 全卷数据加密的 cipher 实现
//
// 当前覆盖：
//   - aes-xts-plain64       (LUKS1/2 现代默认)
//   - aes-cbc-essiv:sha256  (LUKS1 老默认)
//   - aes-cbc-plain         (极少见但还在用)
//
// 不实现：
//   - twofish / serpent / camellia 等非 AES（< 1% 用户）
//   - hash-algo != sha256 的 essiv 变体
//
// 业界事实：cryptsetup --version 调查显示 95%+ LUKS 卷是 aes-xts-plain64。
// 我们在不支持的 cipher 上明确报错，让用户用 cryptsetup luksOpen 解开后再扫挂载点。
// ============================================================================

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/xts"
)

// SectorCipher 抽象了"按 N 字节扇区做 in-place 加解密"的能力。
// LUKS 把 keyslot 区域和 payload 区域都当成一个个固定大小的扇区流，
// 每个扇区单独 IV/tweak。N 由具体 cipher 实例决定：
//   - LUKS1 / 老 LUKS2 卷：512
//   - 现代 LUKS2 + Advanced Format / NVMe 4K 原生盘：4096
type SectorCipher interface {
	// DecryptSector 把 buf 视为一个完整扇区做就地解密，
	// sectorIndex 是相对该 cipher 区域起点的扇区号（0, 1, 2, ...）。
	// buf 长度必须等于 SectorSize()。
	DecryptSector(buf []byte, sectorIndex uint64) error
	// SectorSize 返回扇区粒度（512 或 4096）
	SectorSize() int
}

// NewSectorCipher 按 cipherName/cipherMode 装配一个 512B sector cipher。
// 等价于 NewSectorCipherWithSize(name, mode, key, 512)。
func NewSectorCipher(cipherName, cipherMode string, key []byte) (SectorCipher, error) {
	return NewSectorCipherWithSize(cipherName, cipherMode, key, 512)
}

// NewSectorCipherWithSize 装配一个指定 sector size 的 cipher。
//
// sectorSize 必须是 512 或 4096（LUKS2 spec 允许的两种值）。
// 其它值（1024 / 2048 / 8192）spec 上允许但 cryptsetup 不写、本工具一律拒绝。
func NewSectorCipherWithSize(cipherName, cipherMode string, key []byte, sectorSize int) (SectorCipher, error) {
	if sectorSize != 512 && sectorSize != 4096 {
		return nil, fmt.Errorf("不支持的 sector_size %d（仅支持 512 / 4096）", sectorSize)
	}
	cn := strings.ToLower(strings.TrimSpace(cipherName))
	cm := strings.ToLower(strings.TrimSpace(cipherMode))
	if cn != "aes" {
		return nil, fmt.Errorf("不支持的 cipher: %q（仅支持 aes）", cipherName)
	}

	switch {
	case cm == "xts-plain64":
		// XTS 要求 key 是 cipher-key + tweak-key 拼接（256-bit cipher → 512-bit total）
		c, err := xts.NewCipher(aes.NewCipher, key)
		if err != nil {
			return nil, fmt.Errorf("XTS init: %w", err)
		}
		return &xtsPlain64Cipher{c: c, sectorSize: sectorSize}, nil

	case cm == "cbc-essiv:sha256":
		// CBC-ESSIV：sector_iv = AES-encrypt(salt-key, sector_no_le)，salt-key = SHA256(master_key)
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES key: %w", err)
		}
		saltKey := sha256.Sum256(key)
		ivBlock, err := aes.NewCipher(saltKey[:])
		if err != nil {
			return nil, fmt.Errorf("ESSIV salt key: %w", err)
		}
		return &cbcESSIVCipher{block: block, ivBlock: ivBlock, sectorSize: sectorSize}, nil

	case cm == "cbc-plain", cm == "cbc-plain64":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES key: %w", err)
		}
		return &cbcPlainCipher{block: block, mode64: cm == "cbc-plain64", sectorSize: sectorSize}, nil
	}

	return nil, fmt.Errorf("不支持的 cipher 模式: %q（支持 xts-plain64 / cbc-essiv:sha256 / cbc-plain）", cipherMode)
}

// ----------------------------------------------------------------------------
// xts-plain64
// ----------------------------------------------------------------------------

type xtsPlain64Cipher struct {
	c          *xts.Cipher
	sectorSize int
}

func (x *xtsPlain64Cipher) DecryptSector(buf []byte, sectorIndex uint64) error {
	if len(buf) != x.sectorSize {
		return fmt.Errorf("xts 扇区必须 %dB, got %d", x.sectorSize, len(buf))
	}
	x.c.Decrypt(buf, buf, sectorIndex)
	return nil
}

func (x *xtsPlain64Cipher) SectorSize() int { return x.sectorSize }

// ----------------------------------------------------------------------------
// cbc-essiv:sha256
// ----------------------------------------------------------------------------

type cbcESSIVCipher struct {
	block      cipher.Block // 数据 block (aes-256)
	ivBlock    cipher.Block // ESSIV salt-key block (aes-256, key=SHA256(MK))
	sectorSize int
}

func (c *cbcESSIVCipher) DecryptSector(buf []byte, sectorIndex uint64) error {
	if len(buf) != c.sectorSize {
		return fmt.Errorf("cbc 扇区必须 %dB, got %d", c.sectorSize, len(buf))
	}
	// IV = AES-ECB(salt-key, sector_no LE in 16B)
	var sectorBlock [16]byte
	binary.LittleEndian.PutUint64(sectorBlock[0:8], sectorIndex)
	var iv [16]byte
	c.ivBlock.Encrypt(iv[:], sectorBlock[:])

	mode := cipher.NewCBCDecrypter(c.block, iv[:])
	mode.CryptBlocks(buf, buf)
	return nil
}

func (c *cbcESSIVCipher) SectorSize() int { return c.sectorSize }

// ----------------------------------------------------------------------------
// cbc-plain / cbc-plain64
// ----------------------------------------------------------------------------

type cbcPlainCipher struct {
	block      cipher.Block
	mode64     bool // true = cbc-plain64 (8B sector_no)，false = cbc-plain (4B)
	sectorSize int
}

func (c *cbcPlainCipher) DecryptSector(buf []byte, sectorIndex uint64) error {
	if len(buf) != c.sectorSize {
		return fmt.Errorf("cbc 扇区必须 %dB, got %d", c.sectorSize, len(buf))
	}
	var iv [16]byte
	if c.mode64 {
		binary.LittleEndian.PutUint64(iv[0:8], sectorIndex)
	} else {
		// cbc-plain：低 32 位写入，截断 sector index
		binary.LittleEndian.PutUint32(iv[0:4], uint32(sectorIndex))
	}
	mode := cipher.NewCBCDecrypter(c.block, iv[:])
	mode.CryptBlocks(buf, buf)
	return nil
}

func (c *cbcPlainCipher) SectorSize() int { return c.sectorSize }

// ----------------------------------------------------------------------------

// ErrUnsupportedCipher 暴露给 UI：让用户明确知道是 cipher 选项不支持
var ErrUnsupportedCipher = errors.New("LUKS 容器使用了本工具不支持的 cipher / mode（请用 cryptsetup luksOpen 解开后再扫挂载点）")
