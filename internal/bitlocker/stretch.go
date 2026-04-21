package bitlocker

import (
	"crypto/sha256"
	"encoding/binary"
)

// BitLocker 的 Stretch Key 算法（Microsoft 自定义，不是标准 PBKDF2）。
//
// 输入：
//   - rawKey      16 字节（recovery key 中间密钥 / password 派生的密钥）
//   - salt        16 字节（来自 STRETCH_KEY datum 的 header）
//
// 输出：32 字节 stretched key，可直接当 AES-256 / 双 AES-128 用来解 VMK。
//
// 算法（基于 [MS-FVE] § 3.2.4 + dislocker 实现）：
//
//	struct StretchedKey {
//	    uint8  last_sha256[32]      // 上一次迭代的 hash 输出，初值为 0
//	    uint8  initial_sha256[32]   // SHA-256(rawKey)，固定不变
//	    uint8  salt[16]
//	    uint64 hash_count
//	}
//
//	for i = 0 to 0xFFFFF (1048575):
//	    StretchedKey.hash_count = i
//	    StretchedKey.last_sha256 = SHA-256(StretchedKey 整体 88 字节)
//
//	最终 last_sha256 即输出。
//
// 计算量：1M 次 SHA-256 ≈ 1-2 秒（现代 CPU），是 BitLocker 防暴力破解的核心。
//
// 此函数允许调用方传入 progress 回调（每 ~8K 次回调一次，让 UI 显示"正在解密 BitLocker..."）。
func StretchKey(rawKey []byte, salt [16]byte, progress func(done, total uint64)) [32]byte {
	const iterations = 0x100000 // 1048576

	var state [88]byte
	// state[0:32]   last_sha256（初值 0）
	// state[32:64]  initial_sha256 = SHA-256(rawKey)
	initial := sha256.Sum256(rawKey)
	copy(state[32:64], initial[:])
	// state[64:80]  salt
	copy(state[64:80], salt[:])
	// state[80:88]  hash_count（每轮更新）

	const reportEvery = 8192

	for i := uint64(0); i < iterations; i++ {
		binary.LittleEndian.PutUint64(state[80:88], i)
		h := sha256.Sum256(state[:])
		copy(state[0:32], h[:])
		if progress != nil && i%reportEvery == 0 {
			progress(i, iterations)
		}
	}
	if progress != nil {
		progress(iterations, iterations)
	}

	var out [32]byte
	copy(out[:], state[0:32])
	return out
}
