package luks

// ============================================================================
// LUKS1 on-disk format（cryptsetup-luks1 spec）
//
// LUKS1 phdr (Partition Header) 布局，所有整数 big-endian：
//   off  size  field
//   0    6     magic = "LUKS\xba\xbe"
//   6    2     version (1)
//   8    32    cipher_name      e.g. "aes\0..."
//   40   32    cipher_mode      e.g. "xts-plain64\0..."
//   72   32    hash_spec        e.g. "sha256\0..."
//   104  4     payload_offset   单位：512B 扇区
//   108  4     key_bytes        master key 长度（XTS 用 32 = 64 字节）
//   112  20    mk_digest        PBKDF2(MK) 摘要（用于 unlock 后校验）
//   132  32    mk_digest_salt
//   164  4     mk_digest_iter
//   168  40    uuid (ASCII)
//   208       reserved up to keyslot table
//   keyslot[i] @ off 208 + i*48, i=0..7：
//      0   4   active        0 = inactive, 0x00AC71F3 = active
//      4   4   iterations    PBKDF2 的轮数（每个 keyslot 独立）
//      8   32  salt
//      40  4   key_material_offset  单位 512B 扇区
//      44  4   stripes              AFsplitter 条数（默认 4000）
//
// keyslot 区域内容是经 AFsplitter 分散的 master_key（长度 = keyBytes * stripes），
// 用 keyslot_key (PBKDF2(password, salt, iter, keyBytes)) 通过 cipher 加密。
//
// 解锁流程：
//   1) 派生 keyslot_key
//   2) 解密 keyslot 区域（用同样的 cipher_name + cipher_mode + 全 0 IV 起步，
//      或者按 cipher_mode 指定的 IV 模式 —— LUKS1 keyslot 用 "cbc-essiv:sha256"
//      或 "xts-plain64"，由 phdr.cipher_mode 决定，但通常 key area 用 ECB 链按
//      512B 扇区跑 —— 实际 cryptsetup 里是按"sector index 0 起递增的扇区号" 走 IV）
//   3) AFmerge → master key
//   4) PBKDF2(MK, mk_digest_salt, mk_digest_iter) == mk_digest？过则成功
// ============================================================================

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	luks1KeyslotCount   = 8
	luks1KeyslotSize    = 48
	luks1KeyslotOffset  = 208
	luks1KeyslotActive  = 0x00AC71F3
	luks1KeyslotDisable = 0x0000DEAD

	// cryptsetup 默认值
	luks1DefaultStripes = 4000
)

// LUKS1Header 完整解析后的 LUKS1 partition header
type LUKS1Header struct {
	Version       uint16
	CipherName    string // "aes" 等
	CipherMode    string // "xts-plain64", "cbc-essiv:sha256" 等
	HashSpec      string // "sha256" / "sha1" / "sha512" / "ripemd160"
	PayloadOffset uint32 // 扇区单位（512B）
	KeyBytes      uint32 // master key 字节数
	MKDigest      [20]byte
	MKDigestSalt  [32]byte
	MKDigestIter  uint32
	UUID          string
	Keyslots      [luks1KeyslotCount]LUKS1Keyslot
}

// LUKS1Keyslot 一个 keyslot 的元数据
type LUKS1Keyslot struct {
	Active             bool
	Iterations         uint32
	Salt               [32]byte
	KeyMaterialOffset  uint32 // 扇区
	Stripes            uint32
}

// ParseLUKS1Header 把 LUKS1 phdr 字节解析成结构化数据。
// 输入 buf 必须 >= 1024 字节（LUKS1 phdr 不超过 592 字节，但 1024 是 cryptsetup 的写入对齐单位）。
func ParseLUKS1Header(buf []byte) (*LUKS1Header, error) {
	if len(buf) < 592 {
		return nil, fmt.Errorf("LUKS1 buf 太短: %d", len(buf))
	}
	if !startsWith(buf, luksMagic) {
		return nil, errors.New("不是 LUKS1 (magic 不匹配)")
	}
	ver := binary.BigEndian.Uint16(buf[6:8])
	if ver != 1 {
		return nil, fmt.Errorf("非 LUKS1 版本: %d", ver)
	}
	h := &LUKS1Header{
		Version:       1,
		CipherName:    trimNul(string(buf[8:40])),
		CipherMode:    trimNul(string(buf[40:72])),
		HashSpec:      trimNul(string(buf[72:104])),
		PayloadOffset: binary.BigEndian.Uint32(buf[104:108]),
		KeyBytes:      binary.BigEndian.Uint32(buf[108:112]),
		MKDigestIter:  binary.BigEndian.Uint32(buf[164:168]),
		UUID:          trimNul(string(buf[168:208])),
	}
	copy(h.MKDigest[:], buf[112:132])
	copy(h.MKDigestSalt[:], buf[132:164])

	// 防御：keyBytes 应在合理范围
	if h.KeyBytes < 16 || h.KeyBytes > 64 {
		return nil, fmt.Errorf("LUKS1 key_bytes 异常: %d", h.KeyBytes)
	}

	for i := 0; i < luks1KeyslotCount; i++ {
		off := luks1KeyslotOffset + i*luks1KeyslotSize
		if off+luks1KeyslotSize > len(buf) {
			return nil, fmt.Errorf("keyslot[%d] 越界", i)
		}
		ks := &h.Keyslots[i]
		state := binary.BigEndian.Uint32(buf[off : off+4])
		ks.Active = state == luks1KeyslotActive
		ks.Iterations = binary.BigEndian.Uint32(buf[off+4 : off+8])
		copy(ks.Salt[:], buf[off+8:off+40])
		ks.KeyMaterialOffset = binary.BigEndian.Uint32(buf[off+40 : off+44])
		ks.Stripes = binary.BigEndian.Uint32(buf[off+44 : off+48])
	}

	return h, nil
}

// HashFn 返回对应名称的 hash.Hash 构造器（PBKDF2 用）。
// 不支持的 hash 返回 (nil, error) —— 我们故意不支持冷门 hash（whirlpool 等），
// 现代 LUKS1 99% 用 sha256；老备份可能 sha1 / sha512 / ripemd160（本工具不支持后者）。
func HashFn(name string) (func() hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("不支持的 hash 算法: %q（仅支持 sha1/sha256/sha512）", name)
	}
}

// derivePBKDF2 用指定 hash 派生 keyslot_key
func derivePBKDF2(password, salt []byte, iter int, keyLen int, hashName string) ([]byte, error) {
	h, err := HashFn(hashName)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(password, salt, iter, keyLen, h), nil
}
