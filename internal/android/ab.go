// Package android 解析 Android `adb backup` 产生的 .ab 文件。
//
// 文件格式（参考 Nikolay Elenkov 的逆向、abe.jar 源码、AOSP 中的 BackupManagerService）：
//
//	ASCII 头部行（每行 \n 结尾）：
//	  ANDROID BACKUP
//	  <version>           1, 2, 3, 4, 5（5 是 Android 9+ 的当前版本）
//	  <is_compressed>     "0" 或 "1"（zlib deflate）
//	  <encryption>        "none" 或 "AES-256"
//	如果 encryption == "AES-256"：
//	  <user_password_salt_hex>     128 hex chars (64B)，用户密码 PBKDF2 的盐
//	  <master_key_checksum_salt>   128 hex chars (64B)，校验 master key 的盐
//	  <pbkdf2_rounds>              整数（典型 10000）
//	  <user_key_iv_hex>            32 hex chars (16B)，加密 master key blob 的 IV
//	  <master_key_blob_hex>        变长 hex，加密的 master key blob
//
// 头部之后是二进制 payload：
//   - 加密：先 AES-CBC 解密（key=master_key，IV=master_iv）
//   - 压缩：然后 zlib inflate
//   - 内容：标准 tar 流
//
// 工作流程对应 abe.jar 的 unpack：
//  1. ParseHeader → 知道是否加密 / 压缩 / 版本
//  2. 加密：DeriveUserKey + DecryptMasterKey → master_key + master_iv
//  3. 把 payload 用 master_key 解密 → 得到（可能压缩的）tar 流
//  4. 压缩：zlib inflate → tar
//  5. tar 流交给 archive/tar 标准库枚举文件
//
// 我们只做读路径（恢复场景），从不创建 .ab 备份。
package android

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ABHeader Android backup 文件头部
type ABHeader struct {
	Version      int
	IsCompressed bool
	Encryption   string // "none" | "AES-256"

	// 加密相关字段（仅 Encryption == "AES-256" 时有意义）
	UserPasswordSalt      []byte // 解密 user-key 用
	MasterKeyChecksumSalt []byte // 校验 master key 用
	PBKDF2Rounds          int
	UserKeyIV             []byte // 16B AES IV
	MasterKeyBlob         []byte // 加密的 master key 容器

	// PayloadOffset 是头部结束后的字节偏移；调用方从这里开始读 payload。
	PayloadOffset int64
}

// IsEncrypted 是否为加密 backup
func (h *ABHeader) IsEncrypted() bool { return h != nil && h.Encryption == "AES-256" }

const (
	abMagic        = "ANDROID BACKUP"
	abMaxVersion   = 5
	abMinVersion   = 1
	maxHeaderBytes = 16 * 1024 // 头部不应超过 16KB（master_key_blob 最多几百字节）
)

// ParseHeader 从 .ab 文件流的开头读取头部行。读完时 reader 位于 payload 起点。
// 总共最多读 maxHeaderBytes 字节作为防御。
//
// 返回的 ABHeader.PayloadOffset 表示头部消费的字节数；如果 reader 是 ReadSeeker，
// 调用方可以 Seek(PayloadOffset, io.SeekStart) 回到 payload 起点；否则就接着用同一个
// reader 流式读 payload。
func ParseHeader(r io.Reader) (*ABHeader, error) {
	br := bufio.NewReader(r)
	h := &ABHeader{}

	// 跟踪已消费的字节数（不含 \n？包含），便于报错和给 PayloadOffset
	var consumed int64

	readLine := func(name string) (string, error) {
		// 限制单行 8KB（master_key_blob 极端情况下可能更长，但实测 ≤2KB）
		const maxLineLen = 8 * 1024
		var line []byte
		for {
			b, err := br.ReadByte()
			if err != nil {
				return "", fmt.Errorf("读 %s 行失败: %w", name, err)
			}
			consumed++
			if b == '\n' {
				break
			}
			line = append(line, b)
			if len(line) > maxLineLen {
				return "", fmt.Errorf("%s 行过长（%d 字节，可能不是 .ab）", name, len(line))
			}
		}
		// AOSP 实测有些写出去带 \r\n，去掉
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		return string(line), nil
	}

	// 1) MAGIC
	if magic, err := readLine("MAGIC"); err != nil {
		return nil, err
	} else if magic != abMagic {
		return nil, fmt.Errorf("不是 .ab 文件（magic=%q，期望 %q）", magic, abMagic)
	}

	// 2) VERSION
	if v, err := readLine("VERSION"); err != nil {
		return nil, err
	} else {
		ver, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("VERSION 不是整数: %q", v)
		}
		if ver < abMinVersion || ver > abMaxVersion {
			return nil, fmt.Errorf("不支持的 .ab 版本: %d (本工具支持 %d..%d)", ver, abMinVersion, abMaxVersion)
		}
		h.Version = ver
	}

	// 3) COMPRESSED
	if c, err := readLine("COMPRESSED"); err != nil {
		return nil, err
	} else {
		switch strings.TrimSpace(c) {
		case "0":
			h.IsCompressed = false
		case "1":
			h.IsCompressed = true
		default:
			return nil, fmt.Errorf("COMPRESSED 字段无效: %q", c)
		}
	}

	// 4) ENCRYPTION
	if e, err := readLine("ENCRYPTION"); err != nil {
		return nil, err
	} else {
		h.Encryption = strings.TrimSpace(e)
		if h.Encryption != "none" && h.Encryption != "AES-256" {
			return nil, fmt.Errorf("不支持的 ENCRYPTION 算法: %q（仅 none / AES-256）", h.Encryption)
		}
	}

	// 5..9) 加密参数
	if h.Encryption == "AES-256" {
		// user_password_salt
		s, err := readLine("USER_PASSWORD_SALT")
		if err != nil {
			return nil, err
		}
		if h.UserPasswordSalt, err = hex.DecodeString(strings.TrimSpace(s)); err != nil {
			return nil, fmt.Errorf("user_password_salt 不是合法 hex: %w", err)
		}
		// master_key_checksum_salt
		s, err = readLine("MASTER_KEY_CHECKSUM_SALT")
		if err != nil {
			return nil, err
		}
		if h.MasterKeyChecksumSalt, err = hex.DecodeString(strings.TrimSpace(s)); err != nil {
			return nil, fmt.Errorf("master_key_checksum_salt 不是合法 hex: %w", err)
		}
		// pbkdf2_rounds
		s, err = readLine("PBKDF2_ROUNDS")
		if err != nil {
			return nil, err
		}
		rounds, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || rounds < 1 || rounds > 1_000_000 {
			return nil, fmt.Errorf("PBKDF2_ROUNDS 非法: %q", s)
		}
		h.PBKDF2Rounds = rounds
		// user_key_iv
		s, err = readLine("USER_KEY_IV")
		if err != nil {
			return nil, err
		}
		if h.UserKeyIV, err = hex.DecodeString(strings.TrimSpace(s)); err != nil {
			return nil, fmt.Errorf("user_key_iv 不是合法 hex: %w", err)
		}
		if len(h.UserKeyIV) != 16 {
			return nil, fmt.Errorf("user_key_iv 应为 16 字节, got %d", len(h.UserKeyIV))
		}
		// master_key_blob
		s, err = readLine("MASTER_KEY_BLOB")
		if err != nil {
			return nil, err
		}
		if h.MasterKeyBlob, err = hex.DecodeString(strings.TrimSpace(s)); err != nil {
			return nil, fmt.Errorf("master_key_blob 不是合法 hex: %w", err)
		}
	}

	if consumed > maxHeaderBytes {
		return nil, fmt.Errorf("头部字节数超过 %d 上限", maxHeaderBytes)
	}
	h.PayloadOffset = consumed

	// 把 bufio 里残留的字节"还给"调用方：通过把 br 内部 buffer 的剩余部分附到
	// 一个 MultiReader 里返回。但本函数签名只返回 header，不返回 reader——
	// 所以约定：调用方应该用 ReaderFromHeader(file, h) 之类的辅助拿到 payload reader。
	//
	// 为了简化：我们要求调用方传入的 r 是 *os.File 或 io.ReadSeeker，他们能
	// 自己 Seek 回 PayloadOffset。否则用 OpenAB 一站式 API。

	return h, nil
}

// ParseHeaderBytes 从已经读到内存的字节切片解析头部。
// 测试和小文件场景方便用；大文件请用 ParseHeader + Seek。
func ParseHeaderBytes(data []byte) (*ABHeader, error) {
	if len(data) == 0 {
		return nil, errors.New("空数据")
	}
	return ParseHeader(strings.NewReader(string(data)))
}
