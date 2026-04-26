package android

// ============================================================================
// Android `.ab` 加密备份解密
//
// AOSP BackupManagerService.java 的 unpack 流程，用 Go 复刻：
//
//   user_key      = PBKDF2-SHA1(password, user_password_salt, rounds, 32 字节)
//   blob_plain    = AES-256-CBC-decrypt(user_key, user_key_iv, master_key_blob)
//   blob_plain 的内部布局（all length-prefixed bytes）：
//     [1B] master_iv_len           （通常 16）
//     [N ] master_iv
//     [1B] master_key_len          （通常 32）
//     [N ] master_key
//     [1B] checksum_len            （通常 32）
//     [N ] checksum
//
//   校验 master_key：
//     v3+      ：encoded_master_key = encode_master_key_to_chars(master_key)
//                computed_checksum  = PBKDF2-SHA1(encoded_master_key, checksum_salt, rounds, 32B)
//     v1/v2    ：computed_checksum  = PBKDF2-SHA1(master_key       , checksum_salt, rounds, 32B)
//   两者比对，相等 → 密码正确，否则 → 拒绝。
//
// 之后 payload 用 (master_key, master_iv) 做 AES-256-CBC 解密。
//
// 关键陷阱：v3+ 的 encode_master_key_to_chars 是 Java 的 char[] → String → bytes 转换，
// 每个字节按 Unicode codepoint 处理后用 UTF-8 编码。abe.jar 等开源工具的实现都验证过此路径。
// ============================================================================

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"

	// Android `.ab` 备份格式从 Android 4.0 起用 PBKDF2-SHA1 + AES-CBC 派生 master
	// key（AOSP src/com/android/server/backup/PasswordBasedFileBackupHelper.java）。
	// 读老 .ab 备份只能用 SHA-1；只读取证用途无攻击面。
	// #nosec G505 -- Android `.ab` 备份格式硬性约束，纯只读
	"crypto/sha1"

	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// MasterKey 是从加密 .ab header 中解出的明文容器
type MasterKey struct {
	IV       []byte // 16B AES-CBC IV，用于解 payload
	Key      []byte // 32B AES-256 master key
	Checksum []byte // 32B 校验值（已经验证过；保留以便日志）
}

// DeriveAndDecryptMasterKey 跑完整的"密码 → master key"链路。
//
// 失败原因典型：
//   - 密码错（最终 checksum 比对不一致）
//   - blob 截断
//   - 格式版本错（v1/v2/v3+ encode 路径不同）
//
// 返回的 MasterKey.Key + IV 直接喂给 DecryptPayloadStream。
func DeriveAndDecryptMasterKey(h *ABHeader, password string) (*MasterKey, error) {
	if h == nil || !h.IsEncrypted() {
		return nil, errors.New("非加密 backup 不需要派生 master key")
	}
	if password == "" {
		return nil, errors.New("加密 backup 必须提供密码")
	}

	// 1) 派生 user key
	userKey := pbkdf2.Key(
		[]byte(password),
		h.UserPasswordSalt,
		h.PBKDF2Rounds,
		32, // AES-256
		sha1.New,
	)

	// 2) AES-CBC 解密 master key blob
	if len(h.MasterKeyBlob) == 0 || len(h.MasterKeyBlob)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("master_key_blob 长度非法: %d", len(h.MasterKeyBlob))
	}
	block, err := aes.NewCipher(userKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	dec := cipher.NewCBCDecrypter(block, h.UserKeyIV)
	plain := make([]byte, len(h.MasterKeyBlob))
	dec.CryptBlocks(plain, h.MasterKeyBlob)
	plain, err = pkcs7Unpad(plain)
	if err != nil {
		// padding 错通常意味着密码错（解出来的 plain 是垃圾）
		return nil, fmt.Errorf("master key blob 解密失败（密码可能错）: %w", err)
	}

	// 3) 解析 length-prefixed blob
	mk, err := parseMasterKeyBlob(plain)
	if err != nil {
		return nil, err
	}

	// 4) 校验 checksum
	expected := computeMasterKeyChecksum(mk.Key, h.MasterKeyChecksumSalt, h.PBKDF2Rounds, h.Version)
	if subtle.ConstantTimeCompare(expected, mk.Checksum) != 1 {
		// v3+ 走 encoded 路径；老备份 / 双语言客户端可能跨用，再尝试另一种
		alt := computeMasterKeyChecksum(mk.Key, h.MasterKeyChecksumSalt, h.PBKDF2Rounds, fallbackVersion(h.Version))
		if subtle.ConstantTimeCompare(alt, mk.Checksum) != 1 {
			return nil, errors.New("master key checksum 校验失败（密码错误）")
		}
	}

	return mk, nil
}

// parseMasterKeyBlob 拆 [1B len][N B value] × 3 组
func parseMasterKeyBlob(p []byte) (*MasterKey, error) {
	mk := &MasterKey{}
	pos := 0
	read := func(name string) ([]byte, error) {
		if pos >= len(p) {
			return nil, fmt.Errorf("blob 截断（读 %s 时）", name)
		}
		ln := int(p[pos])
		pos++
		if pos+ln > len(p) {
			return nil, fmt.Errorf("%s 长度 %d 越界", name, ln)
		}
		v := make([]byte, ln)
		copy(v, p[pos:pos+ln])
		pos += ln
		return v, nil
	}
	var err error
	if mk.IV, err = read("master_iv"); err != nil {
		return nil, err
	}
	if mk.Key, err = read("master_key"); err != nil {
		return nil, err
	}
	if mk.Checksum, err = read("checksum"); err != nil {
		return nil, err
	}
	if len(mk.IV) != 16 {
		return nil, fmt.Errorf("master_iv 长度 %d (期望 16)", len(mk.IV))
	}
	if len(mk.Key) != 32 {
		return nil, fmt.Errorf("master_key 长度 %d (期望 32)", len(mk.Key))
	}
	return mk, nil
}

// computeMasterKeyChecksum 重算 master key 校验值。
//
// 版本差异（AOSP BackupManagerService 的 makeKeyChecksum）：
//   v1, v2:  PBKDF2(master_key 字节, salt, rounds) — 直接拿原始字节当 password
//   v3+:     先把 master_key 每字节当成 Unicode codepoint，转成 Java char[]，
//            然后 String 化、UTF-8 编码，再喂 PBKDF2。
//   这是 AOSP 的历史包袱：原本以为会用 char[]，但 PBKDF2 实现实际接收 byte[]，
//   导致两种编码并存。Android 9+ 默认 v3，但旧手机/旧客户端备份可能是 v1/v2。
func computeMasterKeyChecksum(masterKey, salt []byte, rounds, version int) []byte {
	var pwd []byte
	if version >= 3 {
		pwd = encodeMasterKeyAsChars(masterKey)
	} else {
		pwd = masterKey
	}
	return pbkdf2.Key(pwd, salt, rounds, 32, sha1.New)
}

// fallbackVersion 给"checksum 不匹配"时的第二次尝试用：v3 ↔ v1/v2 互换
func fallbackVersion(v int) int {
	if v >= 3 {
		return 1
	}
	return 3
}

// encodeMasterKeyAsChars 复刻 AOSP 的：
//
//   for byte b in masterKey:
//       chars.append((char) b)        // 字节扩成 Java char（U+0000..U+00FF）
//   bytes = String(chars).getBytes("UTF-8")
//
// 即每字节 b ∈ [0..255] → Unicode codepoint U+00b → UTF-8 编码：
//   b ≤ 0x7F：1 字节
//   b ≥ 0x80：2 字节（11xxxxxx 10xxxxxx）
func encodeMasterKeyAsChars(in []byte) []byte {
	var out bytes.Buffer
	for _, b := range in {
		r := rune(b)
		// 标准 UTF-8 编码：ASCII 1B、其余 2B（rune ≤ 0xFF 时）
		if r < 0x80 {
			out.WriteByte(byte(r))
		} else {
			// 2-byte UTF-8: 110xxxxx 10xxxxxx
			out.WriteByte(0xC0 | byte(r>>6))
			out.WriteByte(0x80 | (byte(r) & 0x3F))
		}
	}
	return out.Bytes()
}

// pkcs7Unpad 去 AES-CBC 的 PKCS7 padding；非法时报错（不静默截断）。
func pkcs7Unpad(in []byte) ([]byte, error) {
	if len(in) == 0 {
		return nil, errors.New("空数据无法去 padding")
	}
	pad := int(in[len(in)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, fmt.Errorf("非法 PKCS7 pad: %d", pad)
	}
	if pad > len(in) {
		return nil, fmt.Errorf("pad 长度 %d 超过数据 %d", pad, len(in))
	}
	for i := len(in) - pad; i < len(in); i++ {
		if int(in[i]) != pad {
			return nil, errors.New("PKCS7 padding 字节不一致")
		}
	}
	return in[:len(in)-pad], nil
}
