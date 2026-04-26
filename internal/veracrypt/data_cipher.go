package veracrypt

// VC 数据区 SectorCipher：实现 luks.SectorCipher 接口，让 luks.DecryptedReader
// 能直接消费。Twofish-XTS 走自己的 wrapper（luks 包当前只支持 aes name）；
// AES-XTS 仍复用 luks 包的 SectorCipher 实现。

import (
	"crypto/cipher"
	"fmt"

	"data-recovery/internal/luks"

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

// buildDataCipher 按 cipherName 返回 luks.SectorCipher 实例。
// AES 复用 luks 包的实现（已经过 IEEE 1619 KAT 验证）；Twofish 走本地 wrapper；
// cascade 走 cascadeXTSCipher 多层 wrapper。
func buildDataCipher(cipherName string, masterKey []byte) (luks.SectorCipher, error) {
	switch cipherName {
	case "aes":
		return luks.NewSectorCipher("aes", "xts-plain64", masterKey[:64])
	case "twofish":
		return newTwofishXTSCipher(masterKey[:64])
	case "aes-twofish":
		// "AES-Twofish" cascade：加密顺序 pt → AES → Twofish → ct
		// Key 布局（按加密顺序）: [0..64) = AES, [64..128) = Twofish
		// 解密顺序与加密反向：先 Twofish 解后 AES 解
		if len(masterKey) < 128 {
			return nil, fmt.Errorf("aes-twofish cascade 需要 128 字节 master key, got %d", len(masterKey))
		}
		aesC, err := luks.NewSectorCipher("aes", "xts-plain64", masterKey[:64])
		if err != nil {
			return nil, fmt.Errorf("cascade AES 子层: %w", err)
		}
		twoC, err := newTwofishXTSCipher(masterKey[64:128])
		if err != nil {
			return nil, fmt.Errorf("cascade Twofish 子层: %w", err)
		}
		// layers 按 *解密* 顺序排：先 Twofish 后 AES
		return &cascadeXTSCipher{layers: []luks.SectorCipher{twoC, aesC}}, nil
	}
	return nil, fmt.Errorf("不支持的数据 cipher: %q", cipherName)
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
