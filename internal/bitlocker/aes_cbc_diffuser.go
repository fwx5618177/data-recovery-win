package bitlocker

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// AES-CBC + Elephant Diffuser 是 Windows Vista / Win 7 默认 的 BitLocker 扇区加密模式。
// 协议参考 [MS-FVE] 3.1.4 / dislocker `src/encryption/diffuser.c`。
//
// 算法（解密路径，每扇区独立）：
//
//	1. 计算 sector IV：
//	     IV = AES-ECB( K_TweakKey, sector_number_LE_u128 )
//	2. 反转 Diffuser B（5 轮）+ Diffuser A（3 轮）
//	3. XOR sector_key（来自 K_SectorKey 派生的 16/32 字节）
//	4. AES-CBC-Decrypt( K_DataKey, IV, ciphertext )
//
// 加密时反过来：CBC-Encrypt → XOR sector_key → DiffuserA → DiffuserB。
//
// FVEK 长度按 method 分：
//   - AES-CBC-128 (no diffuser)      32 bytes  = K_Data(16) + K_Tweak(16)
//   - AES-CBC-128 + diffuser         48 bytes  = K_Data(16) + K_Tweak(16) + K_SectorKey(16)
//   - AES-CBC-256 (no diffuser)      64 bytes  = K_Data(32) + K_Tweak(32)
//   - AES-CBC-256 + diffuser         96 bytes  = K_Data(32) + K_Tweak(32) + K_SectorKey(32)
//
// CBCDiffuserCipher 实现 SectorCipher 接口，可以替换 XTSCipher 喂给 DecryptingReader。

const cbcBlockSize = 16

// CBCDiffuserCipher 持有 AES-CBC + 可选 Elephant Diffuser 的解密器。
type CBCDiffuserCipher struct {
	dataCipher  cipher.Block
	tweakCipher cipher.Block
	sectorKey   []byte // 当 useDiffuser=false 时可为 nil
	useDiffuser bool
	sectorSize  int
	keyLen      int // 16 (AES-128) 或 32 (AES-256)
}

// NewCBCDiffuserCipher 按 BitLocker EncryptionMethod 构造 cipher。
//
// fvek 必须按 method 长度提供：
//   - EncryptionAESCBC128       32 bytes
//   - EncryptionAESCBC256       64 bytes
//   - EncryptionAESCBCDiff128   48 bytes
//   - EncryptionAESCBCDiff256   96 bytes
func NewCBCDiffuserCipher(fvek []byte, method uint16, sectorSize int) (*CBCDiffuserCipher, error) {
	if sectorSize <= 0 || sectorSize%cbcBlockSize != 0 {
		return nil, fmt.Errorf("sectorSize 必须是 16 的倍数: %d", sectorSize)
	}

	var keyLen int
	var useDiffuser bool
	switch method {
	case EncryptionAESCBC128:
		keyLen = 16
		useDiffuser = false
	case EncryptionAESCBC256:
		keyLen = 32
		useDiffuser = false
	case EncryptionAESCBCDiff128:
		keyLen = 16
		useDiffuser = true
	case EncryptionAESCBCDiff256:
		keyLen = 32
		useDiffuser = true
	default:
		return nil, fmt.Errorf("不支持的 method: 0x%04X", method)
	}

	want := keyLen * 2
	if useDiffuser {
		want += keyLen
	}
	if len(fvek) < want {
		return nil, fmt.Errorf("FVEK 长度不足: %d（需要 %d）", len(fvek), want)
	}

	dataKey := fvek[0:keyLen]
	tweakKey := fvek[keyLen : 2*keyLen]
	dc, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, fmt.Errorf("AES dataKey: %w", err)
	}
	tc, err := aes.NewCipher(tweakKey)
	if err != nil {
		return nil, fmt.Errorf("AES tweakKey: %w", err)
	}
	c := &CBCDiffuserCipher{
		dataCipher:  dc,
		tweakCipher: tc,
		useDiffuser: useDiffuser,
		sectorSize:  sectorSize,
		keyLen:      keyLen,
	}
	if useDiffuser {
		c.sectorKey = make([]byte, keyLen)
		copy(c.sectorKey, fvek[2*keyLen:3*keyLen])
	}
	return c, nil
}

// SectorSize 返回构造时指定的扇区大小（满足 SectorCipher 接口）。
func (c *CBCDiffuserCipher) SectorSize() int { return c.sectorSize }

// computeIV 算扇区 IV：把 sector_number 编码成 16 字节 LE，AES-ECB 加密一次。
func (c *CBCDiffuserCipher) computeIV(sectorNumber uint64) [cbcBlockSize]byte {
	var ivPlain [cbcBlockSize]byte
	binary.LittleEndian.PutUint64(ivPlain[0:8], sectorNumber)
	// 高 8 字节是 0
	var iv [cbcBlockSize]byte
	c.tweakCipher.Encrypt(iv[:], ivPlain[:])
	return iv
}

// computeSectorKey 用 K_SectorKey 派生本扇区的 XOR mask（与扇区一样长）：
//
//	mask[block_i] = AES-ECB( K_SectorKey, sector_number_LE | counter_i )
//	  其中 counter_i = i（扇区内第 i 个 16 字节块编号），编码到 byte[12:16]
func (c *CBCDiffuserCipher) computeSectorKey(sectorNumber uint64) []byte {
	if !c.useDiffuser {
		return nil
	}
	// 用 sectorKey 临时构造 AES cipher（每扇区一次；AES setup 很轻）
	skCipher, _ := aes.NewCipher(c.sectorKey)
	mask := make([]byte, c.sectorSize)
	var blk [cbcBlockSize]byte
	binary.LittleEndian.PutUint64(blk[0:8], sectorNumber)
	for i := 0; i < c.sectorSize/cbcBlockSize; i++ {
		// 12-13 字节填 counter（按 dislocker 实现：byte 12 是 high byte，会随长扇区滚动）
		blk[12] = byte(i & 0xFF)
		blk[13] = byte((i >> 8) & 0xFF)
		skCipher.Encrypt(mask[i*cbcBlockSize:(i+1)*cbcBlockSize], blk[:])
	}
	return mask
}

// DecryptSector in-place 解密一个扇区。
func (c *CBCDiffuserCipher) DecryptSector(dst, src []byte, sectorNumber uint64) error {
	if len(src) != c.sectorSize || len(dst) != c.sectorSize {
		return fmt.Errorf("dst/src 长度必须等于 sectorSize=%d", c.sectorSize)
	}
	// 按解密方向：先反转 diffuser B → A → XOR sector key → CBC decrypt
	// 注意 diffuser 是对 ciphertext 做的，所以先把 src 拷一份到 dst 上再原地变形
	if &dst[0] != &src[0] {
		copy(dst, src)
	}

	if c.useDiffuser {
		mask := c.computeSectorKey(sectorNumber)
		// 先反转 Diffuser B
		diffuserBDecrypt(dst)
		// 再反转 Diffuser A
		diffuserADecrypt(dst)
		// 然后 XOR sector key
		for i := 0; i < len(dst); i++ {
			dst[i] ^= mask[i]
		}
	}

	// CBC 解密
	iv := c.computeIV(sectorNumber)
	mode := cipher.NewCBCDecrypter(c.dataCipher, iv[:])
	mode.CryptBlocks(dst, dst)
	return nil
}

// EncryptSector 加密反向：CBC encrypt → XOR sector key → diffuser A → diffuser B。
// 仅供测试 round-trip 用，运行时只解密。
func (c *CBCDiffuserCipher) EncryptSector(dst, src []byte, sectorNumber uint64) error {
	if len(src) != c.sectorSize || len(dst) != c.sectorSize {
		return fmt.Errorf("dst/src 长度必须等于 sectorSize=%d", c.sectorSize)
	}
	if &dst[0] != &src[0] {
		copy(dst, src)
	}
	iv := c.computeIV(sectorNumber)
	mode := cipher.NewCBCEncrypter(c.dataCipher, iv[:])
	mode.CryptBlocks(dst, dst)

	if c.useDiffuser {
		mask := c.computeSectorKey(sectorNumber)
		for i := 0; i < len(dst); i++ {
			dst[i] ^= mask[i]
		}
		diffuserAEncrypt(dst)
		diffuserBEncrypt(dst)
	}
	return nil
}

// =====================================================================
// Elephant Diffuser
//
// 数据按 32-bit little-endian word 视图操作；Diffuser A/B 各做几轮针对邻居 word 的
// 自反 XOR + cycle-shift。Microsoft 的设计目标：让单个密文字节变化扩散到整个扇区，
// 防止 attacker 对 CBC 做 bit-flip。
//
// 直接照 [MS-FVE] § 3.1.4.4 + dislocker `src/encryption/diffuser.c` 实现。
//
// 旋转约定（左循环 R_a[k] = ((x << k) | (x >> (32-k))) mask 32）：
//   Diffuser A 顺序加密：
//     A0=9, A1=0, A2=13, A3=0, A4=11, A5=0
//     5 轮：
//       for i := n-1 down to 0:
//         d[i] += d[i-2 mod n] ^ rotL(d[i-5 mod n], A0)   // 4 个 sub-step 用 A0..A4
//   Diffuser A 解密 = Encrypt 的逆：从 0..n-1 顺序，每步用 -=
//
// Diffuser B 类似但 shift table 不同。
//
// 实现按 dislocker 测试通过的常量：
//   A_SHIFTS = {9, 0, 13, 0}  共 4 个 sub-step ×5 rounds = 20 步
//   B_SHIFTS = {0, 10, 0, 25} 共 4 个 sub-step ×3 rounds = 12 步
// =====================================================================

func rotL(x uint32, k uint) uint32 {
	k &= 31
	return (x << k) | (x >> (32 - k))
}

// asWords / fromWords：把字节切片转成 32-bit LE word 切片再转回去
func asWords(b []byte) []uint32 {
	n := len(b) / 4
	w := make([]uint32, n)
	for i := 0; i < n; i++ {
		w[i] = binary.LittleEndian.Uint32(b[4*i : 4*i+4])
	}
	return w
}

func fromWords(b []byte, w []uint32) {
	for i, x := range w {
		binary.LittleEndian.PutUint32(b[4*i:4*i+4], x)
	}
}

// Diffuser A 加密：5 轮
func diffuserAEncrypt(buf []byte) {
	w := asWords(buf)
	n := uint32(len(w))
	if n == 0 {
		return
	}
	for round := 0; round < 5; round++ {
		for i := uint32(0); i < n; i++ {
			j2 := (i - 2 + n) % n
			j5 := (i - 5 + n) % n
			w[i] += w[j2] ^ rotL(w[j5], 9)
			i++
			if i >= n {
				break
			}
			j2 = (i - 2 + n) % n
			j5 = (i - 5 + n) % n
			w[i] += w[j2] ^ w[j5] // shift 0
			i++
			if i >= n {
				break
			}
			j2 = (i - 2 + n) % n
			j5 = (i - 5 + n) % n
			w[i] += w[j2] ^ rotL(w[j5], 13)
			i++
			if i >= n {
				break
			}
			j2 = (i - 2 + n) % n
			j5 = (i - 5 + n) % n
			w[i] += w[j2] ^ w[j5] // shift 0
		}
	}
	fromWords(buf, w)
}

// Diffuser A 解密：和加密反向（顺序倒过来 + 用 -= 替代 +=）
func diffuserADecrypt(buf []byte) {
	w := asWords(buf)
	n := uint32(len(w))
	if n == 0 {
		return
	}
	for round := 0; round < 5; round++ {
		// 反向遍历
		i := n
		for i > 0 {
			i--
			// 倒序的 4 sub-step：先 shift 0、再 13、再 0、再 9
			j2 := (i - 2 + n) % n
			j5 := (i - 5 + n) % n
			w[i] -= w[j2] ^ w[j5] // shift 0
			if i == 0 {
				break
			}
			i--
			j2 = (i - 2 + n) % n
			j5 = (i - 5 + n) % n
			w[i] -= w[j2] ^ rotL(w[j5], 13)
			if i == 0 {
				break
			}
			i--
			j2 = (i - 2 + n) % n
			j5 = (i - 5 + n) % n
			w[i] -= w[j2] ^ w[j5] // shift 0
			if i == 0 {
				break
			}
			i--
			j2 = (i - 2 + n) % n
			j5 = (i - 5 + n) % n
			w[i] -= w[j2] ^ rotL(w[j5], 9)
		}
	}
	fromWords(buf, w)
}

// Diffuser B 加密：3 轮，shift table {0, 10, 0, 25}
func diffuserBEncrypt(buf []byte) {
	w := asWords(buf)
	n := uint32(len(w))
	if n == 0 {
		return
	}
	for round := 0; round < 3; round++ {
		for i := uint32(0); i < n; i++ {
			j2 := (i + 2) % n
			j5 := (i + 5) % n
			w[i] += w[j2] ^ w[j5] // shift 0
			i++
			if i >= n {
				break
			}
			j2 = (i + 2) % n
			j5 = (i + 5) % n
			w[i] += w[j2] ^ rotL(w[j5], 10)
			i++
			if i >= n {
				break
			}
			j2 = (i + 2) % n
			j5 = (i + 5) % n
			w[i] += w[j2] ^ w[j5] // shift 0
			i++
			if i >= n {
				break
			}
			j2 = (i + 2) % n
			j5 = (i + 5) % n
			w[i] += w[j2] ^ rotL(w[j5], 25)
		}
	}
	fromWords(buf, w)
}

// Diffuser B 解密：反向
func diffuserBDecrypt(buf []byte) {
	w := asWords(buf)
	n := uint32(len(w))
	if n == 0 {
		return
	}
	for round := 0; round < 3; round++ {
		i := n
		for i > 0 {
			i--
			j2 := (i + 2) % n
			j5 := (i + 5) % n
			w[i] -= w[j2] ^ rotL(w[j5], 25)
			if i == 0 {
				break
			}
			i--
			j2 = (i + 2) % n
			j5 = (i + 5) % n
			w[i] -= w[j2] ^ w[j5] // shift 0
			if i == 0 {
				break
			}
			i--
			j2 = (i + 2) % n
			j5 = (i + 5) % n
			w[i] -= w[j2] ^ rotL(w[j5], 10)
			if i == 0 {
				break
			}
			i--
			j2 = (i + 2) % n
			j5 = (i + 5) % n
			w[i] -= w[j2] ^ w[j5] // shift 0
		}
	}
	fromWords(buf, w)
}
