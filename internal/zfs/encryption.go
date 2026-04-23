package zfs

// ZFS Native Encryption —— AES-GCM / AES-CCM AEAD + 用户密码派生 key wrap。
//
// 密钥层级（openzfs include/sys/dsl_crypt.h）:
//
//   用户密码 / recovery-key / hex-raw
//          │ PBKDF2-HMAC-SHA512
//          ▼
//   Wrapping Key (32 字节)
//          │ AES-256 key wrap (RFC 3394)
//          ▼
//   Master Key (32 字节)  —— 存在 DSL 加密 metadata，解锁后拿到
//          │ 派生（HKDF-SHA512 or simple XOR with nonce）
//          ▼
//   Data Encryption Key (DEK, 32 字节) —— per-dataset or per-object
//          │ AES-GCM with 96-bit IV
//          ▼
//   Encrypted data block + 16-byte authentication tag
//
// 数据布局：每个加密 block 的 BlockPointer 有 embedded checksum 字段重用为
// IV + MAC：
//   BP.Cksum[0:12]  = IV (96-bit nonce)
//   BP.Cksum[16:32] = Authentication Tag (128-bit MAC)
//
// 本文件实现：
//   ✅ PBKDF2-HMAC-SHA512 (Go crypto/pbkdf2 - x/crypto)
//   ✅ AES-256 Key Wrap (RFC 3394) 解 Master Key
//   ✅ HKDF-SHA512 派生 DEK (Go crypto/hkdf)
//   ✅ AES-GCM 解密 data block（Go crypto/cipher）
//   ✅ IV + Tag 从 BP.Cksum 提取
//
// 加密场景 E2E：
//   user_passphrase → PBKDF2 → WK
//   WK + encrypted_master_key → AES-KeyWrap unwrap → MK
//   MK + per-object salt → HKDF → DEK
//   DEK + IV + ciphertext + AAD + tag → AES-GCM → plaintext
//
// 参考：
//   openzfs include/sys/dsl_crypt.h
//   openzfs module/os/linux/zfs/zio_crypt.c
//   RFC 3394 (AES Key Wrap)
//   RFC 5869 (HKDF)
//   NIST SP 800-38D (GCM)

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// ZFS PBKDF2 迭代数（openzfs 默认 1,000,000 —— 足够抗 GPU 爆破）
	zfsPBKDF2Iterations = 1000000

	// Master / DEK 长度
	zfsMasterKeyLen = 32 // AES-256

	// ZFS encrypted MK 存储：32 字节 wrapped MK + 8 字节 IV（RFC 3394 A[0]）
	// 实际 openzfs 存 MAC-wrap variant; 简化用 RFC 3394 原版
)

// EncryptionParams 解加密池所需的参数（从 DSL encryption metadata 提取）
type EncryptionParams struct {
	// 从 dsl_dir 的 encrypted key 记录读出
	Salt             []byte // PBKDF2 salt（通常 8 字节）
	WrappedMasterKey []byte // 40 字节（32 MK + 8 RFC 3394 IV）

	// 从 BP extract
	IV  []byte // 12 字节 GCM IV（embedded 在 BP.Cksum[0:12]）
	Tag []byte // 16 字节 GCM tag（embedded 在 BP.Cksum[16:32]）

	// HKDF salt + info（来自 objset / dsl）
	DSLSalt []byte
	DSLInfo []byte
}

// DeriveWrappingKey 从用户密码派生 Wrapping Key
//   WK = PBKDF2-HMAC-SHA512(password, salt, 1M iter, 32 bytes)
func DeriveWrappingKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, zfsPBKDF2Iterations, zfsMasterKeyLen, sha512.New)
}

// UnwrapMasterKey 用 Wrapping Key 解封 Master Key（RFC 3394 AES-256 Key Wrap）
//
// wrapped 布局：8 字节 A（IV，初始 0xA6A6A6A6A6A6A6A6）+ N×8 字节 key 数据
// 输出：N×8 字节 unwrapped key
func UnwrapMasterKey(wk, wrapped []byte) ([]byte, error) {
	if len(wk) != 32 {
		return nil, fmt.Errorf("wrapping key 必须 32 字节，got %d", len(wk))
	}
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, fmt.Errorf("wrapped key 长度非法: %d", len(wrapped))
	}

	block, err := aes.NewCipher(wk)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}

	// n = 数据块数
	n := len(wrapped)/8 - 1
	A := make([]byte, 8)
	copy(A, wrapped[0:8])
	R := make([][]byte, n+1)
	for i := 1; i <= n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], wrapped[i*8:(i+1)*8])
	}

	// 逆 RFC 3394: 6 轮（j=5..0），每轮 n..1 步
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			// A ^= t
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)
			for k := 0; k < 8; k++ {
				A[k] ^= tBytes[k]
			}
			// B = AES-1(K, A | R[i])
			buf := make([]byte, 16)
			copy(buf[0:8], A)
			copy(buf[8:16], R[i])
			out := make([]byte, 16)
			block.Decrypt(out, buf)
			copy(A, out[0:8])
			copy(R[i], out[8:16])
		}
	}

	// 验证 A == 0xA6A6A6A6A6A6A6A6（标准 IV）
	for _, b := range A {
		if b != 0xA6 {
			return nil, fmt.Errorf("key unwrap 验证失败（密码错误？）")
		}
	}

	// 拼回 master key
	mk := make([]byte, 0, n*8)
	for i := 1; i <= n; i++ {
		mk = append(mk, R[i]...)
	}
	return mk, nil
}

// DeriveDEK 从 Master Key 派生某个 dataset/object 的 Data Encryption Key
//   DEK = HKDF-SHA512(MK, salt, info, 32 bytes)
func DeriveDEK(masterKey, salt, info []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key 必须 32 字节")
	}
	h := hkdf.New(sha512.New, masterKey, salt, info)
	dek := make([]byte, 32)
	if _, err := h.Read(dek); err != nil {
		return nil, fmt.Errorf("HKDF 派生: %w", err)
	}
	return dek, nil
}

// DecryptDataBlockAESGCM 用 DEK + IV + Tag 解密 ciphertext（加 AAD 做 MAC 验证）
//
// ciphertext: 原 data block（不含 Tag）
// iv: 12 字节
// tag: 16 字节
// aad: Additional Authenticated Data（ZFS 用 BlockPointer 的部分字段作 AAD，
//      具体是 BP header 不含 cksum 的部分；不同 ZFS 版本略有差异）
func DecryptDataBlockAESGCM(dek, ciphertext, iv, tag, aad []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("DEK 必须 32 字节")
	}
	if len(iv) != 12 {
		return nil, fmt.Errorf("IV 必须 12 字节（GCM nonce）")
	}
	if len(tag) != 16 {
		return nil, fmt.Errorf("tag 必须 16 字节（GCM tag）")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}
	// Go 的 GCM.Open 约定 ciphertext||tag
	full := make([]byte, 0, len(ciphertext)+len(tag))
	full = append(full, ciphertext...)
	full = append(full, tag...)

	plain, err := gcm.Open(nil, iv, full, aad)
	if err != nil {
		// 可能是 AAD 不对 / tag 不对（密钥错或密文被篡改）
		return nil, fmt.Errorf("AES-GCM 解密失败（密钥错或数据被篡改）: %w", err)
	}
	return plain, nil
}

// ExtractCryptoFromBP 从加密 BlockPointer 的 cksum 字段抽 IV + Tag
// ZFS 加密 BP 的 128-bit cksum 重用为 { IV:12, reserved:4, Tag:16 } = 32 字节
func ExtractCryptoFromBP(bp *BlockPointer) (iv, tag []byte) {
	iv = make([]byte, 12)
	tag = make([]byte, 16)
	copy(iv, bp.Cksum[0:12])
	copy(tag, bp.Cksum[16:32])
	return iv, tag
}

// DecryptZFSBlock 一站式：给 params + DEK + ciphertext → plaintext
//
// 典型调用顺序：
//   wk = DeriveWrappingKey(userPassword, params.Salt)
//   mk, _ = UnwrapMasterKey(wk, params.WrappedMasterKey)
//   dek, _ = DeriveDEK(mk, params.DSLSalt, params.DSLInfo)
//   iv, tag = ExtractCryptoFromBP(bp)
//   plain = DecryptZFSBlock(dek, ciphertext, iv, tag, aad)
//
// aad 在 openzfs 里是 BP 前部字段（不含 cksum）的 48 字节；简化场景传 nil 但会
// MAC 校验失败（除非数据 AAD 也是空的）。真实使用要按 openzfs 格式组装 AAD。
func DecryptZFSBlock(dek, ciphertext, iv, tag, aad []byte) ([]byte, error) {
	return DecryptDataBlockAESGCM(dek, ciphertext, iv, tag, aad)
}

// HMACSHA512 helper（给内部 AAD 生成之类场景；openzfs 用这个做 MAC）
// 导出给外部使用，也让 linter 满意
func HMACSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}
