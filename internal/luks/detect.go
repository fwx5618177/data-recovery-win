// Package luks 检测 LUKS / LUKS2 加密容器（Linux dm-crypt 标准）。
//
// LUKS1 header @ offset 0：
//
//	magic   "LUKS\xba\xbe"  (6 bytes)
//	version uint16 BE
//	cipher_name [32]byte
//	cipher_mode [32]byte
//	hash_spec   [32]byte
//	payload_offset uint32 BE
//	key_bytes      uint32 BE
//	...
//	uuid       [40]byte
//
// LUKS2 header @ offset 0:
//
//	magic    "LUKS\xba\xbe" 同样
//	version  2
//	header_size uint64
//	seqid       uint64
//	label    [48]byte
//	csum_alg [32]byte
//	...
//	JSON 区域在第 4KB 起，含完整 keyslot / segment / digest 配置
//
// 本包识别 magic 并解出 version + UUID/label + cipher 信息；
// **不实现 PBKDF2 / Argon2id 用户密码 → MK 解锁链** —— 那需要支持 4 种 KDF + 3 种 AEAD，
// 工作量等同 cryptsetup 项目本身。给用户的提示：装 cryptsetup 后用
// `cryptsetup luksOpen` 解开容器再扫挂载点。
package luks

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

var luksMagic = []byte{'L', 'U', 'K', 'S', 0xBA, 0xBE}

// Header 是解析后的 LUKS 头
type Header struct {
	Offset        int64
	Version       uint16 // 1 或 2
	UUID          string // LUKS1 才直接有；LUKS2 在 JSON 区域
	Label         string // LUKS2 才有
	CipherName    string // LUKS1 才直接有
	CipherMode    string
	PayloadOffset uint32 // 加密区起始（block 单位）
}

func Detect(reader disk.DiskReader, volStart int64) (*Header, error) {
	buf := make([]byte, 1024)
	n, err := reader.ReadAt(buf, volStart)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 LUKS header: %w", err)
	}
	if n < 64 {
		return nil, nil
	}
	if !startsWith(buf, luksMagic) {
		return nil, nil
	}
	h := &Header{
		Offset:  volStart,
		Version: binary.BigEndian.Uint16(buf[6:8]),
	}
	switch h.Version {
	case 1:
		h.CipherName = trimNul(string(buf[8:40]))
		h.CipherMode = trimNul(string(buf[40:72]))
		h.PayloadOffset = binary.BigEndian.Uint32(buf[104:108])
		// UUID @ +168，40 字节 ASCII
		if n >= 168+40 {
			h.UUID = trimNul(string(buf[168 : 168+40]))
		}
	case 2:
		// label @ +24，48 字节
		if n >= 24+48 {
			h.Label = trimNul(string(buf[24 : 24+48]))
		}
		// LUKS2 完整解需 4KB JSON 区域 + Argon2id；本工具仅识别
	default:
		return nil, nil
	}
	return h, nil
}

func startsWith(buf, prefix []byte) bool {
	if len(buf) < len(prefix) {
		return false
	}
	for i := range prefix {
		if buf[i] != prefix[i] {
			return false
		}
	}
	return true
}

func trimNul(s string) string {
	for i, c := range s {
		if c == 0 {
			return s[:i]
		}
	}
	return s
}
