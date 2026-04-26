package veracrypt

// ============================================================================
// VeraCrypt / TrueCrypt 密码派生
//
// VeraCrypt 用 PBKDF2-HMAC，hash 函数和 iter 数 用户在创建时选：
//   SHA-512    : VC 500000 / TC 1000-2000
//   SHA-256    : VC 500000 / TC 不支持
//   Whirlpool  : VC 500000 / TC 1000
//   Streebog   : VC 500000 / TC 不支持
//   RIPEMD-160 : TC 2000；VC 不再支持
//
// **本工具实现**：SHA-512 + SHA-256 + RIPEMD-160（用 golang.org/x/crypto/ripemd160）
//
// 不支持 Whirlpool / Streebog —— 它们在 Go 标准库里没有，要拉第三方依赖。
// 这两个 hash 占 < 5% VC 用户；不支持时我们让用户用官方 VeraCrypt 客户端解锁。
//
// 派生输出长度：
//   AES-256 XTS 单 cipher：64 字节（cipher key + tweak key）
//   AES + Twofish cascade：128 字节
//   AES + Twofish + Serpent cascade：192 字节
//
// 我们一次派生足够长（192B）；不同 cipher 取前 N 字节即可。
// ============================================================================

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/pbkdf2"
	// 必须支持 RIPEMD-160 才能解锁老 TrueCrypt 7.x / 早期 VeraCrypt 卷。
	// staticcheck SA1019 / gosec G507 都警告 "legacy weak primitive"——对，但
	// 取证恢复是处理 *老存量*，没得选；新创建的卷我们不写 RIPEMD。
	//lint:ignore SA1019 legacy VC/TC compatibility
	// #nosec G507 -- VC/TC 老卷只能用 RIPEMD-160 解；纯只读取证用途
	"golang.org/x/crypto/ripemd160"
)

// VC / TC 默认迭代数
const (
	VCIterSHA512 = 500000
	VCIterSHA256 = 500000
	VCIterRIPEMD = 655331 // VC 也支持，新版用更高
	TCIterSHA512 = 1000
	TCIterRIPEMD = 2000
)

// IterationsForPIM 返回给定 PIM (Personal Iterations Multiplier) 下的真实 iter 数。
//
// VeraCrypt 支持用户在创建容器时指定 PIM 来调整 KDF 强度（默认 PIM=0 = 走默认 iter）。
// 公式（来自 VeraCrypt 源码 src/Common/Pkcs5.cpp）：
//
//	非系统加密 (data volume)：
//	  SHA-512    : 15000 + 1000 * PIM
//	  SHA-256    : 15000 + 1000 * PIM
//	  Whirlpool  : 15000 + 1000 * PIM
//	  Streebog   : 15000 + 1000 * PIM
//	  RIPEMD-160 : 327661 + 2048 * PIM
//
//	系统加密 (system encryption / boot loader)：
//	  SHA-256 / Streebog / Whirlpool : 200000   (固定，不受 PIM 影响)
//	  RIPEMD-160                     : pim * 2048   (PIM=0 → 1000 iter 兜底)
//	  注意：系统加密分区的卷头 layout 与普通容器不同（offset 31744），
//	  本工具的 unlock 路径目前不识别系统加密卷（VolumeHeader.PayloadOffset==0
//	  会被拒）；公式仍按业界 spec 实现，方便后续接入 system encryption parser。
//
// PIM = 0 时走 hashName 默认 iter（VCIter*）。
func IterationsForPIM(hashName string, pim int) int {
	return IterationsForPIMSystem(hashName, pim, false)
}

// IterationsForPIMSystem 是 IterationsForPIM 的扩展，多一个 isSystemEncryption 参数。
// 系统加密容器（VeraCrypt 给 Windows boot 盘做的全盘加密）走不同公式。
func IterationsForPIMSystem(hashName string, pim int, isSystemEncryption bool) int {
	// 系统加密分支（VC src/Common/Pkcs5.cpp 的 PRF_iteration_count 函数）：
	if isSystemEncryption {
		switch hashName {
		case "ripemd160":
			if pim <= 0 {
				return 1000 // VC 系统加密 RIPEMD 默认 PIM=0 兜底 1000 iter
			}
			return pim * 2048
		case "sha256", "sha512", "whirlpool", "streebog":
			// 系统加密下 SHA-256 / SHA-512 / Whirlpool / Streebog 固定 200000 iter（不受 PIM 影响）
			// （VC 1.x 起的硬性约束；boot loader 可承载的 KDF 时间预算有限）
			return 200000
		}
		return 200000
	}

	// 非系统加密（普通容器 / 数据卷）
	if pim <= 0 {
		// 默认：等同 IterationsFor(false, hashName)
		switch hashName {
		case "sha512", "sha256":
			return VCIterSHA512
		case "ripemd160":
			return VCIterRIPEMD
		}
		return VCIterSHA512
	}
	switch hashName {
	case "ripemd160":
		return 327661 + 2048*pim
	default:
		// SHA-512 / SHA-256（Whirlpool / Streebog 我们也不支持，但落这条）
		return 15000 + 1000*pim
	}
}

// HashSpec 是一个支持的 PBKDF2 hash 配置
type HashSpec struct {
	Name  string
	NewFn func() hash.Hash
}

// SupportedHashes 返回我们解锁时枚举的 hash 算法集合（按 VC/TC 默认顺序）
func SupportedHashes() []HashSpec {
	return []HashSpec{
		{Name: "sha512", NewFn: sha512.New},
		{Name: "sha256", NewFn: sha256.New},
		{Name: "ripemd160", NewFn: ripemd160.New},
	}
}

// DeriveHeaderKey 用密码派生 64+ 字节 header_key（实际我们派 192B 足够 cascade）
func DeriveHeaderKey(password []byte, salt []byte, iter int, h func() hash.Hash) []byte {
	return pbkdf2.Key(password, salt, iter, 192, h)
}

// IterationsFor 返回给定 (vc/tc) + hash 的默认迭代数
func IterationsFor(isTrueCrypt bool, hashName string) int {
	if isTrueCrypt {
		switch hashName {
		case "sha512":
			return TCIterSHA512
		case "ripemd160":
			return TCIterRIPEMD
		}
		return TCIterSHA512
	}
	switch hashName {
	case "sha512":
		return VCIterSHA512
	case "sha256":
		return VCIterSHA256
	case "ripemd160":
		return VCIterRIPEMD
	}
	return VCIterSHA512
}
