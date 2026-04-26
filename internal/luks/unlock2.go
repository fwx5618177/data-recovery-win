package luks

// ============================================================================
// LUKS2 解锁链：JSON metadata → keyslot key（Argon2id / PBKDF2）→ AFmerge → MK
// ============================================================================

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"data-recovery/internal/disk"

	"golang.org/x/crypto/argon2"
)

// UnlockLUKS2 用密码尝试解锁 LUKS2 容器。
// 与 UnlockLUKS1 对称，区别：
//   - keyslot KDF 多了 Argon2id（默认）/ Argon2i / PBKDF2
//   - keyslot area 的 cipher 由 area.encryption 指定（不是 phdr 字段）
//   - 摘要校验在 JSON 的 digests 里查，按 keyslot id 匹配
func UnlockLUKS2(reader disk.DiskReader, volStart int64, bin *LUKS2BinHeader, meta *LUKS2Metadata, password string) ([]byte, string, error) {
	if bin == nil || meta == nil {
		return nil, "", errors.New("header 或 metadata 为 nil")
	}
	if password == "" {
		return nil, "", errors.New("密码为空")
	}

	for slotID, ks := range meta.Keyslots {
		if ks == nil {
			continue
		}
		// 只处理 luks2 类型的 keyslot；reencrypt / token 等非 password 类跳过
		if ks.Type != "luks2" {
			continue
		}
		mk, ok := tryUnlockKeyslot2(reader, volStart, slotID, ks, password)
		if !ok {
			continue
		}

		// 找 digest 校验
		if d := findDigestForKeyslot(meta.Digests, slotID); d != nil {
			if !verifyLUKS2Digest(mk, d) {
				continue
			}
		}
		// 没找到对应 digest 时不强制——少见但合法（cryptsetup 老版本）
		return mk, slotID, nil
	}
	return nil, "", ErrWrongPassword
}

func tryUnlockKeyslot2(reader disk.DiskReader, volStart int64, slotID string, ks *LUKS2Keyslot, password string) ([]byte, bool) {
	mkLen := ks.KeySize
	if mkLen <= 0 || mkLen > 128 {
		return nil, false
	}

	// 1) 派生 keyslot_key
	kdfSalt, err := base64.StdEncoding.DecodeString(ks.KDF.Salt)
	if err != nil {
		return nil, false
	}
	areaKeyLen := ks.Area.KeySize
	if areaKeyLen <= 0 {
		areaKeyLen = mkLen // 兜底
	}

	keyslotKey, err := deriveLUKS2KDF([]byte(password), kdfSalt, areaKeyLen, &ks.KDF)
	if err != nil {
		return nil, false
	}

	// 2) 读 keyslot area
	areaOff, err := strconv.ParseInt(ks.Area.Offset, 10, 64)
	if err != nil || areaOff <= 0 {
		return nil, false
	}
	areaSize, err := strconv.ParseInt(ks.Area.Size, 10, 64)
	if err != nil || areaSize <= 0 {
		return nil, false
	}
	stripes := ks.AF.Stripes
	if stripes <= 0 {
		stripes = luks1DefaultStripes
	}
	stripeBytes := mkLen * stripes

	encrypted := make([]byte, areaSize)
	if _, err := reader.ReadAt(encrypted, volStart+areaOff); err != nil {
		return nil, false
	}

	// 3) 解密 keyslot area
	cipherName, cipherMode, err := splitEncryption(ks.Area.Encryption)
	if err != nil {
		return nil, false
	}
	c, err := NewSectorCipher(cipherName, cipherMode, keyslotKey)
	if err != nil {
		return nil, false
	}
	for off := int64(0); off+512 <= areaSize; off += 512 {
		if err := c.DecryptSector(encrypted[off:off+512], uint64(off/512)); err != nil {
			return nil, false
		}
	}

	// 4) AFmerge
	if int64(stripeBytes) > areaSize {
		return nil, false
	}
	afHash := ks.AF.Hash
	if afHash == "" {
		afHash = "sha256"
	}
	hashFn, err := HashFn(afHash)
	if err != nil {
		return nil, false
	}
	mk, err := AFmerge(encrypted[:stripeBytes], mkLen, stripes, hashFn)
	if err != nil {
		return nil, false
	}
	if isAllZero(mk) {
		return nil, false
	}
	return mk, true
}

// deriveLUKS2KDF 按 KDF 类型派生 keyslot_key
func deriveLUKS2KDF(password, salt []byte, keyLen int, k *LUKS2KDF) ([]byte, error) {
	switch strings.ToLower(k.Type) {
	case "argon2id":
		// Argon2id：time = passes, memory = KB, cpus = parallelism
		return argon2.IDKey(password, salt, uint32(k.Time), uint32(k.Memory), uint8(k.CPUs), uint32(keyLen)), nil
	case "argon2i":
		return argon2.Key(password, salt, uint32(k.Time), uint32(k.Memory), uint8(k.CPUs), uint32(keyLen)), nil
	case "pbkdf2":
		return derivePBKDF2(password, salt, k.Iterations, keyLen, k.Hash)
	default:
		return nil, fmt.Errorf("不支持的 LUKS2 KDF: %q", k.Type)
	}
}

// findDigestForKeyslot 找到把当前 keyslot id 列入的那条 digest
func findDigestForKeyslot(digests map[string]*LUKS2Digest, slotID string) *LUKS2Digest {
	for _, d := range digests {
		if d == nil {
			continue
		}
		for _, s := range d.Keyslots {
			if s == slotID {
				return d
			}
		}
	}
	return nil
}

// verifyLUKS2Digest 用 master key 重新算摘要，对照 d.Digest
func verifyLUKS2Digest(mk []byte, d *LUKS2Digest) bool {
	if strings.ToLower(d.Type) != "pbkdf2" {
		// 不支持的摘要算法 → 保守通过（防止真密码被错误拒绝）
		// 真正的安全性由后续解出来的 fs 是否能 mount 兜底
		return true
	}
	salt, err := base64.StdEncoding.DecodeString(d.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(d.Digest)
	if err != nil {
		return false
	}
	got, err := derivePBKDF2(mk, salt, d.Iterations, len(want), d.Hash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// splitEncryption 把 "aes-xts-plain64" 拆成 ("aes", "xts-plain64")
func splitEncryption(enc string) (string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(enc), "-", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("encryption 字段无法拆分: %q", enc)
	}
	return parts[0], parts[1], nil
}
