package veracrypt

// Kuznyechik (GOST R 34.12-2015) —— 俄国国标分组密码，128-bit block / 256-bit key / 10 轮。
//
// 参考规范：
//   - GOST R 34.12-2015 "Информационная технология. Криптографическая защита
//     информации. Блочные шифры"（俄文原版）
//   - IETF RFC 7801 "GOST R 34.12-2015: Block Cipher 'Kuznyechik'"（英文等价）
//   - VeraCrypt 1.21+ 默认 cipher 列表里包含 Kuznyechik 单 cipher / 与 AES/Serpent
//     的 2-3 cipher cascade
//
// 算法结构（每轮）：
//   1. X[K]: state ⊕ round_subkey
//   2. S: 对 16 字节做 byte-wise S-box (π)
//   3. L: 16-byte 线性变换（Galois(2^8) 多项式 x^8+x^7+x^6+x+1 上的 LFSR）
//
// 10 轮总流程：(LSX)^9 (X)；最后一轮无 L 变换。
// Decryption 是反向：先 X[K10]，然后 (X[Ki] L^{-1} S^{-1})^9
//
// Key schedule：从 256-bit key 派生 10 个 128-bit round subkey，
// 用 Feistel-like 8-round 网络生成（C1..C8 常量也是 LSX 派生）。
//
// **算法事实不受版权保护**；本实现是 RFC 7801 spec 的直接 Go 移植，
// 用 RFC 附录 A 的官方测试向量验证（见 kuznyechik_test.go）。

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const (
	kuznyechikBlockSize = 16
	kuznyechikKeySize   = 32
)

// piTable 是 GOST R 34.12-2015 Section 4.1.1 定义的 S-box (Pi)，256 字节。
//
// 这个 SBOX 是俄国 FSB 公布的，无 nothing-up-my-sleeve 文档；多年密码分析
// 没找到实际可利用结构（GOST 团队声称是用某种 finite-field 构造，但未公开）。
var piTable = [256]uint8{
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
	233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
	249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
	5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
	235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
	181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
	21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
	223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
	224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
	167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
	173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
	7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
	225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
	32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
	89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
}

// piInvTable 是 piTable 的逆，用于 decryption。
var piInvTable [256]uint8

// lConstants 是 L 变换里的 16 个 GF(2^8) 系数（GOST 多项式 x^8+x^7+x^6+x+1 = 0x1c3）
//
//	148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
var lConstants = [16]uint8{
	148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
}

func init() {
	for i := 0; i < 256; i++ {
		piInvTable[piTable[i]] = uint8(i)
	}
}

// gostMul 在 GF(2^8) 上做乘法，模多项式 x^8+x^7+x^6+x+1 = 0xC3（带高位 0x100 = 0x1C3）
//
// 注意 GOST 用的多项式是 0xC3（不含最高位），与 AES 的 0x1B 不同。
func gostMul(a, b uint8) uint8 {
	var p uint8
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}
		highBit := a & 0x80
		a <<= 1
		if highBit != 0 {
			a ^= 0xC3
		}
		b >>= 1
	}
	return p
}

// lFunc 单步：把 16 字节 state 看成 GF(2^8)^16 列向量，
// 输出 = sum_{i=0..15} lConstants[i] * state[i]，结果作为 state[15]，
// 然后把 state 整体右移 1 byte（state[i+1] → state[i]）。
//
// 这是 LFSR 一步；L 变换是 16 次 lFunc 复合。
func lFunc(state []uint8) {
	var x uint8
	for i := 15; i >= 0; i-- {
		if i < 15 {
			state[i+1] = state[i]
		}
		x ^= gostMul(state[i], lConstants[i])
	}
	state[0] = x
}

// lFuncInv 是 lFunc 的逆：state 整体左移，state[15] = old state[0]，
// 然后把"反向"的 LFSR sum 应用到 state[15]。
func lFuncInv(state []uint8) {
	var x uint8
	x = state[0]
	for i := 0; i < 15; i++ {
		state[i] = state[i+1]
	}
	state[15] = x
	x = 0
	for i := 0; i < 16; i++ {
		x ^= gostMul(state[i], lConstants[i])
	}
	state[15] = x
}

// applyL 16 次 lFunc，等价于 spec 的 L 变换
func applyL(state []uint8) {
	for i := 0; i < 16; i++ {
		lFunc(state)
	}
}

// applyLInv 16 次 lFuncInv
func applyLInv(state []uint8) {
	for i := 0; i < 16; i++ {
		lFuncInv(state)
	}
}

// applyS S-box (π) byte-wise
func applyS(state []uint8) {
	for i, b := range state {
		state[i] = piTable[b]
	}
}

// applySInv 逆 S-box
func applySInv(state []uint8) {
	for i, b := range state {
		state[i] = piInvTable[b]
	}
}

// xorBlock state ⊕ key
func xorBlock(dst, a, b []uint8) {
	for i := 0; i < 16; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

// kuznyechikCipher 实现 crypto/cipher.Block 接口
type kuznyechikCipher struct {
	roundKeys [10][16]uint8
}

// NewKuznyechikCipher 用 256-bit key 构造 Kuznyechik cipher
func NewKuznyechikCipher(key []byte) (cipher.Block, error) {
	if len(key) != kuznyechikKeySize {
		return nil, fmt.Errorf("kuznyechik: key 必须 32 字节, got %d", len(key))
	}
	c := &kuznyechikCipher{}
	c.expandKey(key)
	return c, nil
}

func (k *kuznyechikCipher) BlockSize() int { return kuznyechikBlockSize }

func (k *kuznyechikCipher) Encrypt(dst, src []byte) {
	if len(src) < 16 || len(dst) < 16 {
		panic("kuznyechik: block 必须 16 字节")
	}
	var state [16]uint8
	copy(state[:], src[:16])

	// rounds 0..8: X[K] L S
	for i := 0; i < 9; i++ {
		xorBlock(state[:], state[:], k.roundKeys[i][:])
		applyS(state[:])
		applyL(state[:])
	}
	// round 9: X[K10]（无 L S）
	xorBlock(state[:], state[:], k.roundKeys[9][:])
	copy(dst[:16], state[:])
}

func (k *kuznyechikCipher) Decrypt(dst, src []byte) {
	if len(src) < 16 || len(dst) < 16 {
		panic("kuznyechik: block 必须 16 字节")
	}
	var state [16]uint8
	copy(state[:], src[:16])

	// inverse: 先 X[K10]，然后 9 轮 (X[Ki] L^{-1} S^{-1})
	xorBlock(state[:], state[:], k.roundKeys[9][:])
	for i := 8; i >= 0; i-- {
		applyLInv(state[:])
		applySInv(state[:])
		xorBlock(state[:], state[:], k.roundKeys[i][:])
	}
	copy(dst[:16], state[:])
}

// expandKey 派生 10 个 128-bit round subkey
//
// Spec：
//
//	K1 = key[0..16]
//	K2 = key[16..32]
//	for i = 1..4:
//	  (K_{2i+1}, K_{2i+2}) = F[C_{8(i-1)+1}] ... F[C_{8(i-1)+8}] (K_{2i-1}, K_{2i})
//	其中 C_j = L(j 当作 16 字节小端 LE)
//	F[C](a, b) = (LS(a ⊕ C) ⊕ b, a)  (Feistel 1 步)
func (k *kuznyechikCipher) expandKey(key []byte) {
	var k1, k2 [16]uint8
	copy(k1[:], key[:16])
	copy(k2[:], key[16:32])

	k.roundKeys[0] = k1
	k.roundKeys[1] = k2

	// 32 个 round constant C[1..32]，每 8 个一组
	var c [32][16]uint8
	for j := 0; j < 32; j++ {
		// C[j+1] = L(j+1 作为 16-byte 状态，[15] = j+1 其余 0)
		var v [16]uint8
		v[15] = uint8(j + 1)
		applyL(v[:])
		c[j] = v
	}

	a, b := k1, k2
	for i := 0; i < 4; i++ {
		// 8 步 Feistel
		for s := 0; s < 8; s++ {
			var temp [16]uint8
			xorBlock(temp[:], a[:], c[8*i+s][:])
			applyS(temp[:])
			applyL(temp[:])
			xorBlock(temp[:], temp[:], b[:])
			b = a
			a = temp
		}
		k.roundKeys[2*i+2] = a
		k.roundKeys[2*i+3] = b
	}
}

// kuznyechikXTSCipher 实现 luks.SectorCipher（512B sector）—— 用于 VC 数据区
type kuznyechikXTSCipher struct {
	dataKey  cipher.Block
	tweakKey cipher.Block
}

// newKuznyechikXTSCipher 构造 Kuznyechik-XTS（兼容 VC layout：64B key = 32B data + 32B tweak）
//
// 注意：标准 xts 包要求 cipher.Block 为 128-bit block size，正好匹配 Kuznyechik。
func newKuznyechikXTSCipher(key []byte) (*kuznyechikXTSCipher, error) {
	if len(key) < 64 {
		return nil, fmt.Errorf("kuznyechik-XTS 需要 64 字节 key, got %d", len(key))
	}
	dk, err := NewKuznyechikCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("kuznyechik data key: %w", err)
	}
	tk, err := NewKuznyechikCipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("kuznyechik tweak key: %w", err)
	}
	return &kuznyechikXTSCipher{dataKey: dk, tweakKey: tk}, nil
}

func (kx *kuznyechikXTSCipher) DecryptSector(buf []byte, sectorIndex uint64) error {
	if len(buf) != 512 {
		return fmt.Errorf("kuznyechik-XTS 扇区必须 512B, got %d", len(buf))
	}
	// XTS-128 mode: 32 个 16-byte blocks per 512B sector
	// IEEE 1619 XTS：T = E_K2(IV)，cipher = E_K1(P ⊕ T) ⊕ T；解密 P = D_K1(C ⊕ T) ⊕ T
	// IV 是小端 sector index 填到 16 字节，再用 alpha-multiplied 推进每 block
	var tweak [16]uint8
	binary.LittleEndian.PutUint64(tweak[:8], sectorIndex)
	// tweak 的高 8 字节按 IEEE 1619 是 0
	kx.tweakKey.Encrypt(tweak[:], tweak[:])

	for i := 0; i < 32; i++ {
		off := i * 16
		var block [16]uint8
		// C ⊕ T
		for j := 0; j < 16; j++ {
			block[j] = buf[off+j] ^ tweak[j]
		}
		// D_K1
		kx.dataKey.Decrypt(block[:], block[:])
		// ⊕ T
		for j := 0; j < 16; j++ {
			buf[off+j] = block[j] ^ tweak[j]
		}
		// alpha-multiply tweak (GF(2^128) 多项式 x^128+x^7+x^2+x+1)
		gf128Mul2(tweak[:])
	}
	return nil
}

func (kx *kuznyechikXTSCipher) SectorSize() int { return 512 }

// gf128Mul2 在 GF(2^128) 上 ×x（即左移 1 位 + 反馈），按 IEEE 1619 spec
func gf128Mul2(t []uint8) {
	var carry uint8
	for i := 0; i < 16; i++ {
		next := t[i] >> 7
		t[i] = (t[i] << 1) | carry
		carry = next
	}
	if carry != 0 {
		t[0] ^= 0x87 // GF(2^128) 多项式低 byte 的反馈值
	}
}
