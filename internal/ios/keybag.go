package ios

// ============================================================================
// iOS Backup Keybag 解析 + 从用户密码派生出每 class 的 unwrap key
//
// Keybag 的 binary 格式（出现在 Manifest.plist 的 BackupKeyBag data 字段）：
//   [FOUR_CC "TYPE"] [uint32 BE length] [value ...]
// 重复直到 blob 结束。常见 TLV：
//   VERS  keybag version (uint32)
//   TYPE  keybag type (uint32); 1 = Backup
//   UUID  16 字节 keybag 唯一 ID
//   HMCK  HMAC check key (32 字节)
//   WRAP  wrap 版本 (uint32)
//   SALT  PBKDF2-SHA1 salt (20 字节)
//   ITER  PBKDF2-SHA1 iterations (uint32)
//   DPSL  double-PBKDF2 salt (iOS 10.2+；32 字节)
//   DPIC  double-PBKDF2 iterations (uint32)
//
// 之后是一系列 class 段（每个 class 一组 TLV）：
//   CLAS  class number (uint32)     1..11
//   WRAP  class 级 wrap 类型 (uint32)
//   KTYP  key type (uint32)         0 = AES
//   WPKY  wrapped class key (40 字节 = 8 字节 IV + 32 字节 wrapped)
//   PBKY  public key (某些 class 有，忽略)
//
// 用户密码 → class key 的流程（iOS 10.2+ "double PBKDF2"）：
//   step1 = PBKDF2-SHA256(password, DPSL, DPIC, 32)
//   step2 = PBKDF2-SHA1(step1, SALT, ITER, 32)      ← 这就是 unlock-key
//   class_key = AES-KeyUnwrap(step2, WPKY)           ← RFC 3394
//
// iOS 10 之前只有单层 PBKDF2-SHA1，我们兼容两种路径：若没有 DPSL/DPIC 就跳过 step1。
// ============================================================================

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// Keybag 一个已解析好的 keybag 结构（未 unlock 前）
type Keybag struct {
	Version uint32
	Type    uint32
	UUID    []byte

	// PBKDF2 参数
	Salt []byte
	Iter uint32

	// iOS 10.2+ double-PBKDF2 参数（iOS 10.2 之前是 nil）
	DPSalt []byte
	DPIter uint32

	Classes []KeybagClass
}

// KeybagClass 一个 class 段（每个 class 对应一种文件保护等级）
type KeybagClass struct {
	Class      uint32 // 1..11
	WrapType   uint32
	KeyType    uint32 // 0 = AES
	WrappedKey []byte // 40 字节 wrapped key
}

// ParseKeybag 从 Manifest.plist BackupKeyBag data 解析出 Keybag 结构。
func ParseKeybag(data []byte) (*Keybag, error) {
	kb := &Keybag{}
	var currentClass *KeybagClass
	pos := 0

	for pos+8 <= len(data) {
		tag := string(data[pos : pos+4])
		length := int(binary.BigEndian.Uint32(data[pos+4 : pos+8]))
		if pos+8+length > len(data) {
			return nil, fmt.Errorf("keybag TLV %s 长度越界", tag)
		}
		val := data[pos+8 : pos+8+length]
		pos += 8 + length

		// 遇到 CLAS 开启一个新 class 段；其它 class 级 TLV 填当前 class
		switch tag {
		case "VERS":
			kb.Version = readBE32(val)
		case "TYPE":
			kb.Type = readBE32(val)
		case "UUID":
			kb.UUID = dup(val)
		case "SALT":
			kb.Salt = dup(val)
		case "ITER":
			kb.Iter = readBE32(val)
		case "DPSL":
			kb.DPSalt = dup(val)
		case "DPIC":
			kb.DPIter = readBE32(val)
		case "CLAS":
			if currentClass != nil {
				kb.Classes = append(kb.Classes, *currentClass)
			}
			currentClass = &KeybagClass{Class: readBE32(val)}
		case "WRAP":
			if currentClass != nil {
				currentClass.WrapType = readBE32(val)
			}
		case "KTYP":
			if currentClass != nil {
				currentClass.KeyType = readBE32(val)
			}
		case "WPKY":
			if currentClass != nil {
				currentClass.WrappedKey = dup(val)
			}
		}
	}
	if currentClass != nil {
		kb.Classes = append(kb.Classes, *currentClass)
	}

	if len(kb.Salt) == 0 || kb.Iter == 0 {
		return nil, fmt.Errorf("keybag 缺少 SALT/ITER，可能不是 backup keybag")
	}
	return kb, nil
}

// Unlock 用用户密码解出每个 class 的明文 class key。
// 返回 map[classNumber]classKey（每个 32 字节）。
//
// 失败原因通常是：密码错（class key unwrap 失败）。
func (k *Keybag) Unlock(password string) (map[uint32][]byte, error) {
	if k == nil {
		return nil, errors.New("keybag 为 nil")
	}
	pwd := []byte(password)

	// step1：iOS 10.2+ 的 PBKDF2-SHA256
	var unlockKey []byte
	if len(k.DPSalt) > 0 && k.DPIter > 0 {
		step1 := pbkdf2.Key(pwd, k.DPSalt, int(k.DPIter), 32, sha256.New)
		unlockKey = pbkdf2.Key(step1, k.Salt, int(k.Iter), 32, sha1.New)
	} else {
		unlockKey = pbkdf2.Key(pwd, k.Salt, int(k.Iter), 32, sha1.New)
	}

	out := make(map[uint32][]byte)
	for _, c := range k.Classes {
		if len(c.WrappedKey) != 40 {
			continue // 某些 class 没有 AES key（public-key wrapped），跳过
		}
		unwrapped, err := AESKeyUnwrap(unlockKey, c.WrappedKey)
		if err != nil {
			continue // 单 class unwrap 失败不代表整个 keybag 错；继续其他 class
		}
		out[c.Class] = unwrapped
	}

	if len(out) == 0 {
		return nil, errors.New("所有 class key 都 unwrap 失败：密码可能错误")
	}
	return out, nil
}

// ============================================================================
// AES Key Wrap (RFC 3394)
//
// 为什么自己写：标准库 crypto/aes 只给 block primitive；KeyWrap 算法 50 行纯
// Go 就能写清楚，引第三方（比如 github.com/NickBall/go-aes-key-wrap）反而不值。
// ============================================================================

// aesKWIV 是 RFC 3394 固定的 A 初始值
var aesKWIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// AESKeyWrap 用 RFC 3394 把 plaintext（必须是 8 字节倍数，通常 32 字节）包装成 plaintext+8 字节。
// 主要用于单元测试 / 调试；本项目运行时只用 Unwrap。
func AESKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 || len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext 必须是 8 字节倍数，got %d", len(plaintext))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plaintext) / 8
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = dup(plaintext[i*8 : (i+1)*8])
	}
	a := dup(aesKWIV)
	var buf [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i-1])
			block.Encrypt(buf[:], buf[:])
			// t = n*j + i
			t := uint64(n*j + i)
			for b := 7; b >= 0; b-- {
				buf[b] ^= byte(t)
				t >>= 8
			}
			copy(a, buf[:8])
			r[i-1] = dup(buf[8:])
		}
	}
	out := make([]byte, 0, 8+len(plaintext))
	out = append(out, a...)
	for _, seg := range r {
		out = append(out, seg...)
	}
	return out, nil
}

// AESKeyUnwrap 是 RFC 3394 的逆；对 iOS backup 的 wrapped class key (40 字节 → 32 字节) 和
// 单文件 wrapped key (40 字节 → 32 字节) 都适用。
//
// 校验：若解包后 A != IV，返回 error（典型：密码/KEK 错）。
func AESKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 || len(wrapped) < 16 {
		return nil, fmt.Errorf("wrapped 必须是 8 字节倍数且 >= 16，got %d", len(wrapped))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("AES-KW kek 不是合法 AES 密钥: %w", err)
	}
	n := len(wrapped)/8 - 1
	a := dup(wrapped[:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = dup(wrapped[8+i*8 : 8+(i+1)*8])
	}
	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// t = n*j + i
			t := uint64(n*j + i)
			for b := 7; b >= 0; b-- {
				a[b] ^= byte(t)
				t >>= 8
			}
			copy(buf[:8], a)
			copy(buf[8:], r[i-1])
			block.Decrypt(buf[:], buf[:])
			copy(a, buf[:8])
			r[i-1] = dup(buf[8:])
		}
	}
	for i := range a {
		if a[i] != aesKWIV[i] {
			return nil, errors.New("AES-KW 完整性检查失败（密码或 KEK 错误）")
		}
	}
	out := make([]byte, 0, n*8)
	for _, seg := range r {
		out = append(out, seg...)
	}
	return out, nil
}

// ---- 辅助 ----

func readBE32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func dup(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
