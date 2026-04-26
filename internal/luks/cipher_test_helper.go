package luks

// 这个文件只在测试时用：暴露 XTS 加密能力给 fixture 构造器。
// 生产代码（cipher.go）的 SectorCipher 接口只允许 Decrypt——加密能力只对
// "我们正在写一个新的 LUKS 容器" 有意义，本工具永远不写。

import (
	"crypto/aes"

	"golang.org/x/crypto/xts"
)

// xtsCipher 是测试用的 wrapper，暴露 Encrypt
type xtsCipher struct {
	c *xts.Cipher
}

func makeXTSCipher(key []byte) (*xtsCipher, error) {
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, err
	}
	return &xtsCipher{c: c}, nil
}

func (x *xtsCipher) Encrypt(dst, src []byte, sectorIdx uint64) {
	x.c.Encrypt(dst, src, sectorIdx)
}

func (x *xtsCipher) Decrypt(dst, src []byte, sectorIdx uint64) {
	x.c.Decrypt(dst, src, sectorIdx)
}
