package luks

// ============================================================================
// LUKS1 完整解锁链：密码 → master_key
//
// 入口：UnlockLUKS1(reader, header, password)
//   1. 对每个 active keyslot，按其独立的 PBKDF2(salt, iter) 派生 keyslot_key
//   2. 用 phdr 的 cipher 配置（典型 aes-cbc-essiv:sha256）解密 keyslot 区域
//   3. AFmerge 得到候选 master_key
//   4. PBKDF2(MK, mk_digest_salt, mk_digest_iter) == mk_digest？通过则 OK
//   5. 任何 keyslot 通过都返回 master_key；全部失败则密码错。
//
// 这是和 cryptsetup `luksOpen` 等价的密码 → MK 链；之后调用方拿 MK 装到
// payload 区的 SectorCipher 就能"虚拟解密"全卷。
// ============================================================================

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"

	"data-recovery/internal/disk"
)

// ErrWrongPassword 当所有 active keyslot 都解不开时返回
var ErrWrongPassword = errors.New("密码错误（所有 active keyslot 均无法解锁）")

// UnlockLUKS1 用密码尝试解锁 LUKS1 容器，成功时返回 master key + 命中的 keyslot 索引。
//
// reader   是 LUKS 卷的"原始磁盘"读取器（offset 0 = LUKS1 phdr）
// volStart 是 LUKS 卷在该 reader 上的起始字节偏移（一般 0）
//
// 性能：每个 keyslot 跑一次 PBKDF2（典型 4 万轮 sha256，1-3 秒）；最坏情况
// 密码错时跑 8 个 keyslot ≈ 24 秒。可接受。
func UnlockLUKS1(reader disk.DiskReader, volStart int64, h *LUKS1Header, password string) ([]byte, int, error) {
	if h == nil {
		return nil, -1, errors.New("header 为 nil")
	}
	if password == "" {
		return nil, -1, errors.New("密码为空")
	}

	mkLen := int(h.KeyBytes)
	digestFn, err := HashFn(h.HashSpec)
	if err != nil {
		return nil, -1, err
	}

	for i, ks := range h.Keyslots {
		if !ks.Active {
			continue
		}
		mk, ok := tryUnlockKeyslot1(reader, volStart, h, &ks, password)
		if !ok {
			continue
		}
		// 验证 master key digest
		expected, err := derivePBKDF2(mk, h.MKDigestSalt[:], int(h.MKDigestIter), 20, h.HashSpec)
		if err != nil {
			return nil, -1, err
		}
		if subtle.ConstantTimeCompare(expected, h.MKDigest[:]) == 1 {
			_ = mkLen
			_ = digestFn
			return mk, i, nil
		}
	}
	return nil, -1, ErrWrongPassword
}

// tryUnlockKeyslot1 尝试用密码解一个 keyslot；失败/出错都返回 (nil, false)。
// 不报错的原因：上层会顺序试 8 个 keyslot，单个失败是预期。
func tryUnlockKeyslot1(reader disk.DiskReader, volStart int64, h *LUKS1Header, ks *LUKS1Keyslot, password string) ([]byte, bool) {
	mkLen := int(h.KeyBytes)

	// 1) 派生 keyslot_key
	keyslotKey, err := derivePBKDF2(
		[]byte(password),
		ks.Salt[:],
		int(ks.Iterations),
		mkLen,
		h.HashSpec,
	)
	if err != nil {
		return nil, false
	}

	// 2) 读 keyslot 加密区域（mkLen * stripes 字节，按 512B 扇区对齐到下一个边界）
	areaBytes := mkLen * int(ks.Stripes)
	// LUKS1 把 keyslot area 圆整到 4096 字节边界（cryptsetup 实现细节，但读多了不要紧）
	roundedBytes := (areaBytes + 4095) &^ 4095
	areaStart := volStart + int64(ks.KeyMaterialOffset)*512

	encrypted := make([]byte, roundedBytes)
	if _, err := reader.ReadAt(encrypted, areaStart); err != nil {
		return nil, false
	}

	// 3) 用 keyslot_key 解密 area（按 512B 扇区，sectorIndex 从 0 开始）
	cipher, err := NewSectorCipher(h.CipherName, h.CipherMode, keyslotKey)
	if err != nil {
		return nil, false
	}
	for off := 0; off < areaBytes; off += 512 {
		end := off + 512
		if end > areaBytes {
			// 不到一个扇区的尾巴：按规范 area 应该是 sector 对齐，但 cryptsetup 实测不会
			// 给非对齐 area —— 直接复制不解密
			break
		}
		if err := cipher.DecryptSector(encrypted[off:end], uint64(off/512)); err != nil {
			return nil, false
		}
	}

	// 4) AFmerge 得到候选 mk
	stripeBuf := encrypted[:areaBytes]
	digestFn, err := HashFn(h.HashSpec)
	if err != nil {
		return nil, false
	}
	mk, err := AFmerge(stripeBuf, mkLen, int(ks.Stripes), digestFn)
	if err != nil {
		return nil, false
	}

	// 简单防御：全 0 mk 一律拒绝（PBKDF2 命中全 0 几乎不可能）
	if isAllZero(mk) {
		return nil, false
	}
	return mk, true
}

func isAllZero(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}

// 只用来压制"未引用"的伪报警；真正的错误消息引用见 ErrUnsupportedCipher。
var _ = fmt.Errorf
