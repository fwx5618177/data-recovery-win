package ios

import (
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

// pbkdf2HelperSingle 是 keybag_test.go 专用的 PBKDF2-SHA1 便捷包装（单层）。
// 生产代码用 golang.org/x/crypto/pbkdf2.Key 内联在 Keybag.Unlock 里。
func pbkdf2HelperSingle(password, salt []byte, iter, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iter, keyLen, sha1.New)
}
