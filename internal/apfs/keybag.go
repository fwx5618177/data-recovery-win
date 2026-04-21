package apfs

import (
	"encoding/binary"
	"fmt"

	"data-recovery/internal/disk"
)

// FileVault keybag 解析。
//
// keybag 是 APFS 容器/卷里"存储 wrapped key + recovery info" 的小数据结构。
// 容器超块 nx_keylocker / 卷 apfs_keybag_loc 指向它。每个 keybag 是一个 kb_locker
// 包着若干 keybag entry（kb_entry）。
//
// **kb_locker (32 字节头)**：
//
//	+0x00 obj_phys (32 bytes - 已被外层读出来；这里直接 skip)
//	+0x20 kl_version uint16   = 2
//	+0x22 kl_nkeys   uint16   entry 个数
//	+0x24 kl_nbytes  uint32   entries 总字节数
//	+0x28 reserved (8 bytes 0)
//	+0x30 entries[]
//
// **kb_entry**：
//
//	+0x00 ke_uuid    16 bytes UUID    （volume UUID 或 user UUID）
//	+0x10 ke_tag     uint16           1=wrapped VEK, 2=password hint, 3=wrapped KEK
//	+0x12 ke_keylen  uint16           keydata 字节数
//	+0x14 padding    4 bytes
//	+0x18 keydata[]                   按 tag 解释
//
// **wrapped KEK 的 keydata**：是一个 BLOB，含 wrapped_kek_data + 可选 metadata：
// 我们只取 wrapped data（前 40 字节左右就是 RFC 3394 wrapped 的 32-byte KEK）。
// 真实格式还含 PBKDF2 salt + iter，但布局在不同 macOS 版本变化大；
// 调用方可能需要从 entry 之外的 PreBoot 卷拿 salt/iter。
//
// 本实现给出"keybag 字节级 parser + 找匹配 UUID 的 wrapped key entry"的能力，
// 上层用 PBKDF2 + AESKeyUnwrap 完成解密链。

const (
	KeyBagTagReserved        uint16 = 0
	KeyBagTagWrappedVEK      uint16 = 2
	KeyBagTagPasswordHint    uint16 = 3
	KeyBagTagWrappedKEK      uint16 = 4
	KeyBagTagPolicy          uint16 = 5
	KeyBagTagInfo            uint16 = 0xFFFE
)

// KeyBagEntry 是 keybag 里一条 (UUID, tag) 记录。
type KeyBagEntry struct {
	UUID    [16]byte
	Tag     uint16
	KeyData []byte // 原始字节；调用方按 tag 自行解
}

// KeyBag 是解析后的 kb_locker。
type KeyBag struct {
	Version uint16
	Entries []KeyBagEntry
}

// ParseKeyBag 把 kb_locker 整块字节解开。
// buf 应该是从容器/卷里读出来的整个 keybag 块（通常 1 个 block_size，4096 字节）。
// 整块前 32 字节是 obj_phys；调用方传完整块即可，本函数自动 skip。
func ParseKeyBag(buf []byte) (*KeyBag, error) {
	const objPhysLen = 32
	if len(buf) < objPhysLen+0x10 {
		return nil, fmt.Errorf("keybag block 太短: %d", len(buf))
	}
	body := buf[objPhysLen:]
	kb := &KeyBag{
		Version: binary.LittleEndian.Uint16(body[0:2]),
	}
	if kb.Version != 2 {
		return nil, fmt.Errorf("不支持的 keybag version: %d", kb.Version)
	}
	nKeys := binary.LittleEndian.Uint16(body[2:4])
	nBytes := binary.LittleEndian.Uint32(body[4:8])
	if int(8+8+nBytes) > len(body) {
		return nil, fmt.Errorf("keybag nbytes %d 越界", nBytes)
	}
	entries := body[0x10 : 0x10+int(nBytes)]

	pos := 0
	for i := 0; i < int(nKeys); i++ {
		if pos+24 > len(entries) {
			break
		}
		var e KeyBagEntry
		copy(e.UUID[:], entries[pos:pos+16])
		e.Tag = binary.LittleEndian.Uint16(entries[pos+16 : pos+18])
		keyLen := int(binary.LittleEndian.Uint16(entries[pos+18 : pos+20]))
		// padding 4 字节
		dataStart := pos + 24
		if dataStart+keyLen > len(entries) {
			break
		}
		e.KeyData = make([]byte, keyLen)
		copy(e.KeyData, entries[dataStart:dataStart+keyLen])
		kb.Entries = append(kb.Entries, e)
		// 下一条 entry 8-byte 对齐
		pos = dataStart + keyLen
		if pos%8 != 0 {
			pos += 8 - (pos % 8)
		}
	}
	return kb, nil
}

// FindEntry 在 keybag 里找匹配 UUID + tag 的 entry。
func (kb *KeyBag) FindEntry(uuid [16]byte, tag uint16) *KeyBagEntry {
	for i := range kb.Entries {
		if kb.Entries[i].Tag == tag && kb.Entries[i].UUID == uuid {
			return &kb.Entries[i]
		}
	}
	return nil
}

// ReadKeyBagFromContainer 用容器级 nx_keylocker 把 keybag 字节读出来再解。
//
// nx_keylocker 是一个连续 prange — 多块的话拼起来。只对真正启用了 FileVault
// 的容器才非空（IsZero=true 表示这容器不需要 keybag）。
//
// 读到字节后调用 ParseKeyBag 返回 *KeyBag。
func ReadKeyBagFromContainer(reader disk.DiskReader, container *Container) (*KeyBag, error) {
	if container == nil {
		return nil, fmt.Errorf("nil container")
	}
	if container.KeyLocker.IsZero() {
		return nil, fmt.Errorf("此容器没有 keybag (FileVault 未启用)")
	}
	return readKeyBagFromPRange(reader, container.Offset, container.BlockSize, container.KeyLocker)
}

// ReadKeyBagFromVolume 用卷级 apfs_keybag_loc 读 keybag。
// 卷级 keybag 含该卷的 wrapped VEK + 关联用户的 wrapped KEK。
func ReadKeyBagFromVolume(reader disk.DiskReader, container *Container, volume *Volume) (*KeyBag, error) {
	if container == nil || volume == nil {
		return nil, fmt.Errorf("nil container / volume")
	}
	if volume.KeybagLoc.IsZero() {
		return nil, fmt.Errorf("卷没有 keybag (未加密 / 未启用 FileVault)")
	}
	return readKeyBagFromPRange(reader, container.Offset, container.BlockSize, volume.KeybagLoc)
}

// readKeyBagFromPRange 把 prange 描述的多块物理区域字节读出来再解。
func readKeyBagFromPRange(reader disk.DiskReader, containerOffset int64, blockSize uint32, pr PRange) (*KeyBag, error) {
	if pr.IsZero() {
		return nil, fmt.Errorf("PRange 为空")
	}
	totalBytes := int64(pr.BlockCount) * int64(blockSize)
	// keybag 通常 1 块够，超大也极少 > 64KB；这里给个上限防恶意 metadata 撑爆内存
	if totalBytes <= 0 || totalBytes > 4*1024*1024 {
		return nil, fmt.Errorf("keybag 长度异常: %d 字节", totalBytes)
	}
	buf := make([]byte, totalBytes)
	absOff := containerOffset + int64(pr.StartPAddr)*int64(blockSize)
	n, err := reader.ReadAt(buf, absOff)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("读 keybag @0x%X 失败: %w", absOff, err)
	}
	return ParseKeyBag(buf[:n])
}

// UnwrapVEKWithPassword 把 FileVault 解密链一次性串起来：
//
//	password → PBKDF2(salt, iter) → derived_key
//	    → AESKeyUnwrap(wrapped_kek) → KEK
//	    → AESKeyUnwrap(wrapped_vek) → VEK
//
// salt / iter 来自 PreBoot 卷的 SecureToken / EncryptedRoot.plist —— 这部分 macOS
// 版本差异极大且 plist 里有多种格式，本工具不解；调用方自行从 PreBoot / Recovery
// 提供 salt/iter；或者用户从 macOS Recovery 直接读出 derived_key 传进来跳过 PBKDF2 步。
//
// derivedKey 32 字节即可（PBKDF2-HMAC-SHA256 输出）。
func UnwrapVEKWithDerivedKey(derivedKey, wrappedKEK, wrappedVEK []byte) ([]byte, error) {
	kek, err := AESKeyUnwrap(derivedKey, wrappedKEK)
	if err != nil {
		return nil, fmt.Errorf("解 KEK 失败（密码 / salt / iter 不对？）: %w", err)
	}
	vek, err := AESKeyUnwrap(kek, wrappedVEK)
	if err != nil {
		return nil, fmt.Errorf("解 VEK 失败（KEK 不对？）: %w", err)
	}
	return vek, nil
}
