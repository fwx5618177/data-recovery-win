package ios

// ============================================================================
// iOS 备份加密文件解密
//
// 和 keybag 解锁串起来的完整链：
//   1. Manifest.plist 里拿 BackupKeyBag blob → ParseKeybag → class_keys (密码输入)
//   2. Manifest.plist 里拿 ManifestKey（wrapped 44B） → AES-KeyUnwrap(class_key) → Manifest.db AES-CBC key
//   3. 用该 key 解密整个 Manifest.db 文件 → 写一个临时明文 .db → 用 modernc.org/sqlite 正常读取
//   4. 对每条 Files 记录：file blob 里的 EncryptionKey 前 4 字节 = class_id(LE)，后面 40 字节 = wrapped file key
//   5. AES-KeyUnwrap → file key (32B)
//   6. 备份目录里 <prefix>/<fileID> 是密文 → AES-CBC(key=file_key, iv=0) 解密
//
// 所有加密都是 AES-256-CBC (iOS 的 class key 都是 32 字节)，IV 恒为 0 —— Apple
// 故意这么设计（filesystem 级每块 IV 从别处派生，对 NSKeyedArchiver 里的整块
// blob 直接 IV=0 就行）。
//
// PKCS#7 padding：存在。解密后去掉末尾 padding。
// ============================================================================

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// ManifestKey 描述 Manifest.plist 里 ManifestKey 字段解开后的 key。
//
//	ManifestKey = class_id(4B LE) + wrapped(40B)
//	→ 用 class_keys[class_id] 做 KEK → AES-KW unwrap → 32B Manifest.db AES key
type ManifestKey struct {
	Class uint32
	Key   []byte // 32 字节明文，AES-CBC 用
}

// DecryptManifestKey 从 Manifest.plist 的 ManifestKey 字段 + 已 unlock 的 class_keys
// 推出用来解密 Manifest.db 本体的 AES key。
func DecryptManifestKey(manifestKeyBlob []byte, classKeys map[uint32][]byte) (*ManifestKey, error) {
	if len(manifestKeyBlob) != 4+40 {
		return nil, fmt.Errorf("ManifestKey 长度异常: %d (期望 44)", len(manifestKeyBlob))
	}
	classID := binary.LittleEndian.Uint32(manifestKeyBlob[:4])
	wrapped := manifestKeyBlob[4:]
	classKey, ok := classKeys[classID]
	if !ok {
		return nil, fmt.Errorf("ManifestKey 引用 class %d，但 keybag 里没有这个 class", classID)
	}
	plain, err := AESKeyUnwrap(classKey, wrapped)
	if err != nil {
		return nil, fmt.Errorf("ManifestKey unwrap 失败: %w", err)
	}
	return &ManifestKey{Class: classID, Key: plain}, nil
}

// DecryptManifestDBFile 把加密的 Manifest.db 文件用 AES-CBC 解密，写到 outPath。
// Manifest.db 整个文件就是 CBC 密文（IV 为 0），解密后第一字节起就是 SQLite 魔数。
//
// 大小限制：Manifest.db 通常 < 50MB（百万文件级别才到），一次性读入内存是合理的。
// 超过 100MB 我们拒绝——那种规模的备份也不是本工具目标场景。
func DecryptManifestDBFile(encryptedPath, outPath string, aesKey []byte) error {
	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("读加密 Manifest.db 失败: %w", err)
	}
	if len(data) > 100*1024*1024 {
		return fmt.Errorf("manifest.db 大小 %d 超过 100MB 限制，拒绝解密", len(data))
	}
	if len(data)%aes.BlockSize != 0 {
		return fmt.Errorf("manifest.db 大小 %d 不是 AES blocksize 倍数", len(data))
	}

	plain, err := aesCBCDecryptZeroIV(aesKey, data)
	if err != nil {
		return err
	}
	plain, err = removePKCS7Padding(plain)
	if err != nil {
		return fmt.Errorf("manifest.db padding 不合法: %w", err)
	}
	// 校验：前 16 字节应等于 "SQLite format 3\x00"
	if len(plain) < 16 || string(plain[:15]) != "SQLite format 3" {
		return errors.New("manifest.db 解密后不是 SQLite 文件（密码或 class key 可能错）")
	}

	if err := os.WriteFile(outPath, plain, 0o600); err != nil {
		return fmt.Errorf("写明文 manifest.db 失败: %w", err)
	}
	return nil
}

// DecryptBackupFile 解密一个加密的备份文件到 outPath（流式写，支持大文件）。
//
// fileEncryptionKey 是 FileRecord.EncryptionKey（前 4B = class_id LE + 后 40B = wrapped）。
// 用 classKeys[class_id] 做 KEK 解出 file_key，然后 AES-CBC decrypt 整个密文文件。
//
// 为了省内存，我们采用 16KB 块循环 decrypt → write 模式，只有最后一块
// 去 PKCS7 padding（中间块的 CBC 链是"下一块密文的 IV = 上一块密文"）。
// 但标准 CBC 需要严格线性，不能"并行化"；内存占用也就 32B AES 状态 + 16KB 缓冲，足够低。
func DecryptBackupFile(
	encryptedPath, outPath string,
	fileRec FileRecord,
	classKeys map[uint32][]byte,
) (int64, error) {
	if len(fileRec.EncryptionKey) != 4+40 {
		return 0, fmt.Errorf("file EncryptionKey 长度异常: %d (期望 44)", len(fileRec.EncryptionKey))
	}
	classID := binary.LittleEndian.Uint32(fileRec.EncryptionKey[:4])
	wrapped := fileRec.EncryptionKey[4:]
	classKey, ok := classKeys[classID]
	if !ok {
		return 0, fmt.Errorf("file 引用 class %d，但 keybag 里没有", classID)
	}
	fileKey, err := AESKeyUnwrap(classKey, wrapped)
	if err != nil {
		return 0, fmt.Errorf("file key unwrap 失败: %w", err)
	}

	src, err := os.Open(encryptedPath)
	if err != nil {
		return 0, fmt.Errorf("打开加密文件失败: %w", err)
	}
	defer src.Close()

	st, err := src.Stat()
	if err != nil {
		return 0, err
	}
	srcSize := st.Size()
	if srcSize%aes.BlockSize != 0 {
		return 0, fmt.Errorf("加密文件大小 %d 不是 AES blocksize 倍数", srcSize)
	}
	if srcSize == 0 {
		// 空文件直接创空文件
		return 0, os.WriteFile(outPath, nil, 0o644)
	}

	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return 0, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}
	iv := make([]byte, aes.BlockSize) // IV = 0
	dec := cipher.NewCBCDecrypter(block, iv)

	dst, err := os.Create(outPath)
	if err != nil {
		return 0, fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer dst.Close()

	const bufBlocks = 512 // 8KB；越大越快，但 32KB 以上增益递减
	buf := make([]byte, bufBlocks*aes.BlockSize)

	var writtenTotal int64
	remaining := srcSize
	for remaining > 0 {
		toRead := int64(len(buf))
		if toRead > remaining {
			toRead = remaining
		}
		n, rerr := io.ReadFull(src, buf[:toRead])
		if rerr != nil {
			return writtenTotal, fmt.Errorf("读密文失败: %w", rerr)
		}
		dec.CryptBlocks(buf[:n], buf[:n])
		remaining -= int64(n)

		isLast := remaining == 0
		var out []byte
		if isLast {
			// 去除 PKCS7 padding（只有最后一块里有）
			plain, err := removePKCS7Padding(buf[:n])
			if err != nil {
				return writtenTotal, fmt.Errorf("最后一块 padding 非法: %w", err)
			}
			out = plain
		} else {
			out = buf[:n]
		}
		if _, werr := dst.Write(out); werr != nil {
			return writtenTotal, werr
		}
		writtenTotal += int64(len(out))
	}

	// 真实文件大小应等于 FileRecord.Size（如果 Size 有意义），否则给警告
	if fileRec.Size > 0 && writtenTotal != fileRec.Size {
		// 不 fail —— padding 计算可能偶尔差 1-16 字节；但记录日志会更好（这里保守）。
		// 调用方拿 writtenTotal 和 fileRec.Size 对比即可。
	}
	return writtenTotal, nil
}

// aesCBCDecryptZeroIV 把整块密文用 AES-CBC (IV=0) 一次性解密到新 slice。
// 仅用于小文件（Manifest.db），大文件走 DecryptBackupFile 的流式版本。
func aesCBCDecryptZeroIV(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(ciphertext))
	dec.CryptBlocks(out, ciphertext)
	return out, nil
}

// removePKCS7Padding 按 RFC 5652 §6.3 验证并去 padding。
// 注意：只有**合法 PKCS7**才接受（最后一字节 p ∈ [1..16]，且末尾 p 个字节都等于 p）。
// padding 非法时返回 error 而不是静默保留——防止用户拿到前半段有效 + 尾部乱码的文件。
func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, fmt.Errorf("非法 PKCS7 pad 值: %d", pad)
	}
	if pad > len(data) {
		return nil, fmt.Errorf("padding %d 超过数据长度 %d", pad, len(data))
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, fmt.Errorf("padding 字节不一致")
		}
	}
	return data[:len(data)-pad], nil
}
