package veracrypt

// VC 数据区 SectorCipher：实现 luks.SectorCipher 接口，让 luks.DecryptedReader
// 能直接消费。Twofish-XTS 走自己的 wrapper（luks 包当前只支持 aes name）；
// AES-XTS 仍复用 luks 包的 SectorCipher 实现。

import (
	"crypto/cipher"
	"fmt"

	"data-recovery/internal/luks"

	"github.com/aead/serpent"
	// 必须支持 Twofish 才能解锁用 Twofish 创建的 VeraCrypt 卷。
	// staticcheck SA1019：Twofish 是 legacy cipher——对，但取证恢复处理 *老存量*，
	// 没得选；同 ripemd160 / RIPEMD-160 路径同理。
	//lint:ignore SA1019 legacy VC compatibility
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xts"
)

// twofishXTSCipher 实现 luks.SectorCipher（512B sector）。
// 内部用 golang.org/x/crypto/xts.NewCipher(twofish.NewCipher, key)。
type twofishXTSCipher struct {
	c *xts.Cipher
}

func newTwofishXTSCipher(key []byte) (*twofishXTSCipher, error) {
	if len(key) < 64 {
		return nil, fmt.Errorf("twofish-XTS 需要 64 字节 key, got %d", len(key))
	}
	c, err := xts.NewCipher(func(k []byte) (cipher.Block, error) {
		return twofish.NewCipher(k)
	}, key[:64])
	if err != nil {
		return nil, err
	}
	return &twofishXTSCipher{c: c}, nil
}

func (t *twofishXTSCipher) DecryptSector(buf []byte, sectorIndex uint64) error {
	if len(buf) != 512 {
		return fmt.Errorf("twofish-XTS 扇区必须 512B, got %d", len(buf))
	}
	t.c.Decrypt(buf, buf, sectorIndex)
	return nil
}

func (t *twofishXTSCipher) SectorSize() int { return 512 }

// serpentXTSCipher 实现 luks.SectorCipher（512B sector），用 github.com/aead/serpent。
// Serpent 是 AES 决赛 5 强之一（1998 NIST 提交，Anderson/Biham/Knudsen），
// 256-bit key + 128-bit block + 32 rounds，安全裕度比 AES 大但慢 2-3×。
// VeraCrypt 默认 cipher 选项之一，~3% VC 用户用 Serpent 单 cipher 或 cascade。
type serpentXTSCipher struct {
	c *xts.Cipher
}

func newSerpentXTSCipher(key []byte) (*serpentXTSCipher, error) {
	if len(key) < 64 {
		return nil, fmt.Errorf("serpent-XTS 需要 64 字节 key, got %d", len(key))
	}
	c, err := xts.NewCipher(func(k []byte) (cipher.Block, error) {
		return serpent.NewCipher(k)
	}, key[:64])
	if err != nil {
		return nil, err
	}
	return &serpentXTSCipher{c: c}, nil
}

func (s *serpentXTSCipher) DecryptSector(buf []byte, sectorIndex uint64) error {
	if len(buf) != 512 {
		return fmt.Errorf("serpent-XTS 扇区必须 512B, got %d", len(buf))
	}
	s.c.Decrypt(buf, buf, sectorIndex)
	return nil
}

func (s *serpentXTSCipher) SectorSize() int { return 512 }

// buildDataCipher 按 cipherName 返回 luks.SectorCipher 实例。
// AES 复用 luks 包的实现（已经过 IEEE 1619 KAT 验证）；Twofish 走本地 wrapper；
// cascade 走 cascadeXTSCipher 多层 wrapper。
func buildDataCipher(cipherName string, masterKey []byte) (luks.SectorCipher, error) {
	switch cipherName {
	case "aes":
		return luks.NewSectorCipher("aes", "xts-plain64", masterKey[:64])
	case "twofish":
		return newTwofishXTSCipher(masterKey[:64])
	case "serpent":
		return newSerpentXTSCipher(masterKey[:64])
	case "aes-twofish":
		return buildCascade2(masterKey, "aes", "twofish")
	case "twofish-serpent":
		return buildCascade2(masterKey, "twofish", "serpent")
	case "serpent-aes":
		return buildCascade2(masterKey, "serpent", "aes")
	case "aes-twofish-serpent":
		return buildCascade3(masterKey, "aes", "twofish", "serpent")
	case "serpent-twofish-aes":
		return buildCascade3(masterKey, "serpent", "twofish", "aes")
	}
	return nil, fmt.Errorf("不支持的数据 cipher: %q", cipherName)
}

// buildSingleSubCipher 按 cipherName 构造单 cipher 的 SectorCipher (使用 64B key)
func buildSingleSubCipher(name string, key []byte) (luks.SectorCipher, error) {
	switch name {
	case "aes":
		return luks.NewSectorCipher("aes", "xts-plain64", key)
	case "twofish":
		return newTwofishXTSCipher(key)
	case "serpent":
		return newSerpentXTSCipher(key)
	}
	return nil, fmt.Errorf("buildSingleSubCipher: 不支持 %q", name)
}

// buildCascade2 构造 2-cipher cascade
//   - Name "A-B" 加密顺序 = pt → A → B → ct
//   - Key 布局（按加密顺序）: [0..64) = A, [64..128) = B
//   - 解密 layers 顺序: [B, A]
func buildCascade2(masterKey []byte, a, b string) (luks.SectorCipher, error) {
	if len(masterKey) < 128 {
		return nil, fmt.Errorf("%s-%s cascade 需要 128 字节 master key, got %d", a, b, len(masterKey))
	}
	ac, err := buildSingleSubCipher(a, masterKey[:64])
	if err != nil {
		return nil, fmt.Errorf("cascade %s 子层: %w", a, err)
	}
	bc, err := buildSingleSubCipher(b, masterKey[64:128])
	if err != nil {
		return nil, fmt.Errorf("cascade %s 子层: %w", b, err)
	}
	return &cascadeXTSCipher{layers: []luks.SectorCipher{bc, ac}}, nil // 解密顺序 reverse
}

// buildCascade3 构造 3-cipher cascade
//   - Name "A-B-C" 加密顺序 = pt → A → B → C → ct
//   - Key 布局: [0..64)=A, [64..128)=B, [128..192)=C
//   - 解密 layers 顺序: [C, B, A]
func buildCascade3(masterKey []byte, a, b, c string) (luks.SectorCipher, error) {
	if len(masterKey) < 192 {
		return nil, fmt.Errorf("%s-%s-%s cascade 需要 192 字节 master key, got %d", a, b, c, len(masterKey))
	}
	ac, err := buildSingleSubCipher(a, masterKey[:64])
	if err != nil {
		return nil, fmt.Errorf("cascade %s 子层: %w", a, err)
	}
	bc, err := buildSingleSubCipher(b, masterKey[64:128])
	if err != nil {
		return nil, fmt.Errorf("cascade %s 子层: %w", b, err)
	}
	cc, err := buildSingleSubCipher(c, masterKey[128:192])
	if err != nil {
		return nil, fmt.Errorf("cascade %s 子层: %w", c, err)
	}
	return &cascadeXTSCipher{layers: []luks.SectorCipher{cc, bc, ac}}, nil // reverse
}

// cascadeXTSCipher 是把多个 luks.SectorCipher 按解密顺序串联起来的 wrapper。
// 解密时按 layers 顺序依次解每层；加密相反。
//
// VeraCrypt cascade 名 "A-B" 代表加密顺序 A→B；解密顺序 B→A，所以构造时
// layers 应当 = [B, A]（外层先解）。
type cascadeXTSCipher struct {
	layers []luks.SectorCipher
}

func (c *cascadeXTSCipher) DecryptSector(buf []byte, sectorIndex uint64) error {
	if len(buf) != 512 {
		return fmt.Errorf("cascade XTS 扇区必须 512B, got %d", len(buf))
	}
	for _, l := range c.layers {
		if err := l.DecryptSector(buf, sectorIndex); err != nil {
			return err
		}
	}
	return nil
}

func (c *cascadeXTSCipher) SectorSize() int { return 512 }
