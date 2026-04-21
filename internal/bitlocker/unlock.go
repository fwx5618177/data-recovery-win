package bitlocker

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// VMK / FVEK 解锁的完整密钥链：
//
//	48-digit recovery key
//	     │
//	     ▼  ParseRecoveryPassword
//	16-byte intermediate key
//	     │
//	     ▼  StretchKey(salt from STRETCH_KEY datum, 1M iter)
//	32-byte stretched key
//	     │
//	     ▼  AES-CCM decrypt(VMK datum's AES_CCM_ENCRYPTED_KEY child)
//	32-byte VMK (Volume Master Key)
//	     │
//	     ▼  AES-CCM decrypt(FVEK info datum's AES_CCM_ENCRYPTED_KEY child)
//	{16,32}-byte FVEK (Full Volume Encryption Key) ← 真正解扇区的密钥
//
// 不同保护器（recovery / TPM / password / startup key）只是替换了第一段密钥派生方式；
// 进入 AES-CCM 的部分对所有 protector 都一样。

// AES-CCM Encrypted Key datum 的 28 字节 header 布局：
//
//	+0x00  nonce_time     uint64  Windows FILETIME（微软时间戳）
//	+0x08  nonce_counter  uint32  跟时间戳合并组成 12 字节 nonce
//	+0x0C  mac_tag        16 bytes  AES-CCM tag
//	+0x1C  ... 之后是密文
const aesccmHeaderLen = 28

// decryptAESCCMDatum 是把"datum 里 AES-CCM 包的密钥"解开的统一方法。
//
// keyBytes: 用来解的密钥（recovery 路径下是 stretched key；FVEK 路径下是 VMK）
// d:        要解的 AES_CCM_ENCRYPTED_KEY datum
//
// 返回明文（可能是另一个 datum，也可能是裸密钥字节）。
func decryptAESCCMDatum(keyBytes []byte, d *Datum) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("nil datum")
	}
	if d.ValueType != DatumValueAESCCMKey && d.ValueType != DatumValueAESCCMConcat {
		return nil, fmt.Errorf("不是 AES-CCM datum: ValueType=0x%X", d.ValueType)
	}
	if len(d.Body) < aesccmHeaderLen {
		return nil, fmt.Errorf("AES-CCM datum body 太短: %d", len(d.Body))
	}

	// 12-byte nonce = 8-byte FILETIME + 4-byte counter
	nonce := make([]byte, 12)
	copy(nonce[0:8], d.Body[0:8])
	copy(nonce[8:12], d.Body[8:12])

	tag := d.Body[12:28]
	ciphertext := d.Body[28:]

	plaintext, err := DecryptAESCCM(keyBytes, nonce, ciphertext, tag)
	if err != nil {
		return nil, fmt.Errorf("AES-CCM 解密失败: %w", err)
	}
	return plaintext, nil
}

// extractKeyFromKeyDatumBytes 解析"KEY value type"载荷里的实际密钥字节。
//
// 解开 AES-CCM datum 后，明文通常是嵌套的 KEY datum（ValueType=0x0001）：
//
//	+0x00  Datum header (8 bytes)        ValueType=0x0001
//	+0x08  encryption_method (4 bytes)   类型标识（AES-128 / AES-256 等）
//	+0x0C  key bytes (16 / 32 bytes)
//
// 返回密钥字节（按 method 决定 16 或 32 字节）。
func extractKeyFromKeyDatumBytes(plaintext []byte) ([]byte, error) {
	// 尝试当作完整 datum 解析
	if len(plaintext) >= 8 {
		d, _, err := ParseDatum(plaintext, 0)
		if err == nil && d.ValueType == DatumValueKey {
			if len(d.Body) >= 4 {
				// body[0:4] = encryption_method；剩下是密钥
				return d.Body[4:], nil
			}
		}
	}
	// 退化：明文本身就是密钥（某些版本协议没有外包 datum）
	return plaintext, nil
}

// UnlockVMKWithRecoveryKey 用 48 位 recovery key 解开一个 VMK 保护器条目。
//
// 步骤：
//  1. ParseRecoveryPassword 把 48 位数字转 16-byte intermediate key
//  2. 在 VMK datum 子节点里找 STRETCH_KEY datum，取它 header 的 salt
//  3. StretchKey(intermediate, salt, 1M iterations) → 32-byte stretched key
//  4. 在 VMK datum 子节点里找 AES_CCM_ENCRYPTED_KEY datum
//  5. AES-CCM decrypt → 拿到 VMK
//
// progress 在 stretch 阶段被回调（让 UI 显示"正在派生密钥..."）。
func UnlockVMKWithRecoveryKey(
	recoveryKey string,
	vmk *VMKDatum,
	progress func(done, total uint64),
) ([]byte, error) {
	if vmk == nil || vmk.Datum == nil {
		return nil, fmt.Errorf("nil VMK datum")
	}
	if vmk.ProtectionType != VMKProtectionRecoveryPwd {
		return nil, fmt.Errorf("此 VMK 保护类型 0x%X 不是 recovery key", vmk.ProtectionType)
	}

	intermediate, err := ParseRecoveryPassword(recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("recovery key 校验失败: %w", err)
	}

	// 在 VMK 子 datum 里找 STRETCH_KEY；它的 header 前 4 字节是 encryption_method，
	// 后 16 字节是 salt
	stretchDatum := FindDatumByValueType(vmk.Datum.Children, DatumValueStretchKey)
	if stretchDatum == nil {
		return nil, fmt.Errorf("VMK 子 datum 中找不到 STRETCH_KEY")
	}
	if len(stretchDatum.Body) < 20 {
		return nil, fmt.Errorf("STRETCH_KEY datum body 太短: %d", len(stretchDatum.Body))
	}
	var salt [16]byte
	copy(salt[:], stretchDatum.Body[4:20])

	stretched := StretchKey(intermediate[:], salt, progress)

	// 在 VMK 子 datum 中找 AES_CCM_ENCRYPTED_KEY
	// 注意：STRETCH_KEY datum 内部还嵌套着另一个 AES_CCM datum（password 路径）；
	// 但 recovery 路径通常 AES_CCM 直接挂在 VMK 下
	aesccm := findAESCCMForVMK(vmk.Datum)
	if aesccm == nil {
		return nil, fmt.Errorf("VMK 中找不到 AES_CCM_ENCRYPTED_KEY")
	}

	plaintext, err := decryptAESCCMDatum(stretched[:], aesccm)
	if err != nil {
		return nil, fmt.Errorf("VMK 解密失败（recovery key 可能错？）: %w", err)
	}
	return extractKeyFromKeyDatumBytes(plaintext)
}

// hashUserPasswordUTF16 把用户密码按 [MS-FVE] 的方式编码成 32 字节"intermediate key"：
//
//	SHA-256( SHA-256( UTF-16LE 编码的 password ) )
//
// 用户密码可以包含任意 Unicode，不截长度（BitLocker 实际对密码长度有上限，
// 但这里不是校验的地方）。
func hashUserPasswordUTF16(password string) []byte {
	utf16Codes := utf16.Encode([]rune(password))
	buf := make([]byte, 2*len(utf16Codes))
	for i, c := range utf16Codes {
		binary.LittleEndian.PutUint16(buf[2*i:2*i+2], c)
	}
	h1 := sha256.Sum256(buf)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

// UnlockVMKWithPassword 用"用户密码"保护器解 VMK。
//
// 与 recovery key 路径的唯一差别：intermediate key 不再来自 48 位数字解码，
// 而是来自 SHA-256(SHA-256(UTF-16LE(password)))。进入 StretchKey + AES-CCM 之后一模一样。
func UnlockVMKWithPassword(
	password string,
	vmk *VMKDatum,
	progress func(done, total uint64),
) ([]byte, error) {
	if vmk == nil || vmk.Datum == nil {
		return nil, fmt.Errorf("nil VMK datum")
	}
	if vmk.ProtectionType != VMKProtectionPassword {
		return nil, fmt.Errorf("此 VMK 保护类型 0x%X 不是 password", vmk.ProtectionType)
	}
	if password == "" {
		return nil, fmt.Errorf("password 为空")
	}

	intermediate := hashUserPasswordUTF16(password)

	stretchDatum := FindDatumByValueType(vmk.Datum.Children, DatumValueStretchKey)
	if stretchDatum == nil {
		return nil, fmt.Errorf("VMK 子 datum 中找不到 STRETCH_KEY")
	}
	if len(stretchDatum.Body) < 20 {
		return nil, fmt.Errorf("STRETCH_KEY datum body 太短: %d", len(stretchDatum.Body))
	}
	var salt [16]byte
	copy(salt[:], stretchDatum.Body[4:20])

	stretched := StretchKey(intermediate, salt, progress)

	aesccm := findAESCCMForVMK(vmk.Datum)
	if aesccm == nil {
		return nil, fmt.Errorf("VMK 中找不到 AES_CCM_ENCRYPTED_KEY")
	}
	plaintext, err := decryptAESCCMDatum(stretched[:], aesccm)
	if err != nil {
		return nil, fmt.Errorf("VMK 解密失败（密码可能错？）: %w", err)
	}
	return extractKeyFromKeyDatumBytes(plaintext)
}

// UnlockVMKWithStartupKey 用 BEK 文件里的 32 字节"external key"解 VMK。
//
// BEK 文件本身是一个只含 EXTERNAL_KEY datum 的 FVE metadata block；
// 调用方可以用 ParseBEKFile 读出 32 字节 external key 再传进来。
//
// 与 recovery / password 路径相比，startup key 不走 StretchKey，直接用 BEK 的密钥
// 解 VMK 下的 AES_CCM datum（那个 datum 里存着被 external key 加密的 VMK 本体）。
func UnlockVMKWithStartupKey(externalKey []byte, vmk *VMKDatum) ([]byte, error) {
	if vmk == nil || vmk.Datum == nil {
		return nil, fmt.Errorf("nil VMK datum")
	}
	if vmk.ProtectionType != VMKProtectionStartupKey {
		return nil, fmt.Errorf("此 VMK 保护类型 0x%X 不是 startup key", vmk.ProtectionType)
	}
	if len(externalKey) < 32 {
		return nil, fmt.Errorf("external key 长度不足: %d（需要 32）", len(externalKey))
	}

	aesccm := findAESCCMForVMK(vmk.Datum)
	if aesccm == nil {
		return nil, fmt.Errorf("VMK 中找不到 AES_CCM_ENCRYPTED_KEY")
	}
	plaintext, err := decryptAESCCMDatum(externalKey[:32], aesccm)
	if err != nil {
		return nil, fmt.Errorf("VMK 解密失败（BEK 不匹配此 VMK？）: %w", err)
	}
	return extractKeyFromKeyDatumBytes(plaintext)
}

// SummarizeProtectors 给上层一份"这卷有哪些 VMK 保护器、哪些可解、哪些卡住"的清单，
// 配合 UI 提示用户该用哪种密钥 / 该跑什么命令导出 recovery key。
type ProtectorSummary struct {
	Kind         string // "recovery" / "password" / "tpm" / "tpm-pin" / "startup-key" / "unknown"
	Solvable     bool   // 本工具能否独立解锁（recovery / password / startup-key 是 true）
	Hint         string // 给用户的引导
}

// SummarizeProtectors 把 metadata 里的所有 VMK 翻译成人话清单。
//
// 调用方典型用法：用户点"解锁 BitLocker"前，先调一次拿到清单展示给用户：
// "本卷有 1 个 TPM + 1 个 recovery key 保护器，请用 recovery key（48 位数字）解锁"。
func SummarizeProtectors(mb *FVEMetadataBlock) []ProtectorSummary {
	if mb == nil {
		return nil
	}
	var out []ProtectorSummary
	for _, v := range mb.FindVMKs() {
		out = append(out, classifyProtector(v.ProtectionType))
	}
	return out
}

func classifyProtector(pt uint16) ProtectorSummary {
	switch pt {
	case VMKProtectionRecoveryPwd:
		return ProtectorSummary{
			Kind:     "recovery",
			Solvable: true,
			Hint:     "请输入 48 位 recovery key（在 microsoft.com/account 或 AD 域 / 管理员保存的 txt）",
		}
	case VMKProtectionPassword:
		return ProtectorSummary{
			Kind:     "password",
			Solvable: true,
			Hint:     "请输入用户密码",
		}
	case VMKProtectionStartupKey:
		return ProtectorSummary{
			Kind:     "startup-key",
			Solvable: true,
			Hint:     "请提供 .BEK startup key 文件",
		}
	case VMKProtectionTPM:
		return ProtectorSummary{
			Kind:     "tpm",
			Solvable: false,
			Hint: "TPM-only 保护器无法在跨平台工具里解（需要原机的 TPM 硬件）。请在原 Windows 系统上跑\n" +
				"  manage-bde -protectors -get C:\n" +
				"导出 recovery key，再用本工具解；或在原系统挂载后用 dislocker。",
		}
	case VMKProtectionTPMAndPin:
		return ProtectorSummary{
			Kind:     "tpm-pin",
			Solvable: false,
			Hint: "TPM+PIN 保护器需要原机的 TPM 硬件 + PIN，跨平台无法解。请在原 Windows 系统跑\n" +
				"  manage-bde -protectors -get C:\n" +
				"先导出 recovery key 再用本工具。",
		}
	case VMKProtectionClearKey:
		return ProtectorSummary{
			Kind:     "clear",
			Solvable: true,
			Hint:     "卷已暂停 BitLocker（明文 VMK 直接在卷上）—— 直接读即可，无须密钥",
		}
	default:
		return ProtectorSummary{
			Kind:     "unknown",
			Solvable: false,
			Hint:     fmt.Sprintf("未识别的保护器类型 0x%X；请用 manage-bde 检查并导出 recovery key", pt),
		}
	}
}

// findAESCCMForVMK 在 VMK 子 datum 中找到正确的 AES_CCM datum。
// 优先找 STRETCH_KEY 内部的 AES_CCM（password / recovery 路径都把它嵌套在 STRETCH_KEY 里），
// 找不到再找直接挂在 VMK 下的。
func findAESCCMForVMK(vmkDatum *Datum) *Datum {
	if vmkDatum == nil {
		return nil
	}
	// 先深搜 STRETCH_KEY 内部
	for i := range vmkDatum.Children {
		c := &vmkDatum.Children[i]
		if c.ValueType == DatumValueStretchKey {
			if inner := FindDatumByValueType(c.Children, DatumValueAESCCMKey); inner != nil {
				return inner
			}
			if inner := FindDatumByValueType(c.Children, DatumValueAESCCMConcat); inner != nil {
				return inner
			}
		}
	}
	// fallback：直接挂在 VMK 下
	for i := range vmkDatum.Children {
		c := &vmkDatum.Children[i]
		if c.ValueType == DatumValueAESCCMKey || c.ValueType == DatumValueAESCCMConcat {
			return c
		}
	}
	return nil
}

// ExtractFVEKFromMetadata 用 32-byte VMK 解开 metadata 里的 FVEK info datum，
// 返回真正用来解扇区的 FVEK + 加密算法。
//
// 步骤：
//  1. 在 metadata.Datums 里找 Type=DatumEntryFVEKInfo 的 datum
//  2. 它内部有一个 AES_CCM_ENCRYPTED_KEY 子 datum
//  3. 用 VMK 解密 → 拿到 FVEK 数据
//  4. 解析出 encryption_method + 密钥字节
func ExtractFVEKFromMetadata(mb *FVEMetadataBlock, vmk []byte) (fvek []byte, method uint16, err error) {
	if mb == nil {
		return nil, 0, fmt.Errorf("nil metadata block")
	}
	// 找 FVEK info datum（Type 字段判断，而不是 ValueType）
	var fvekInfo *Datum
	for i := range mb.Datums {
		if mb.Datums[i].Type == DatumEntryFVEKInfo {
			fvekInfo = &mb.Datums[i]
			break
		}
	}
	if fvekInfo == nil {
		return nil, 0, fmt.Errorf("metadata 里没有 FVEK info datum")
	}

	aesccm := FindDatumByValueType(fvekInfo.Children, DatumValueAESCCMKey)
	if aesccm == nil {
		aesccm = FindDatumByValueType(fvekInfo.Children, DatumValueAESCCMConcat)
	}
	if aesccm == nil {
		return nil, 0, fmt.Errorf("FVEK info datum 里没有 AES_CCM_ENCRYPTED_KEY")
	}

	plaintext, err := decryptAESCCMDatum(vmk, aesccm)
	if err != nil {
		return nil, 0, fmt.Errorf("FVEK 解密失败: %w", err)
	}
	// plaintext 应该是嵌套的 KEY datum，前 4 字节 encryption_method，后面是密钥
	if len(plaintext) < 12 {
		return nil, 0, fmt.Errorf("FVEK plaintext 太短: %d", len(plaintext))
	}
	d, _, err := ParseDatum(plaintext, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("FVEK 内部 datum 解析失败: %w", err)
	}
	if d.ValueType != DatumValueKey {
		return nil, 0, fmt.Errorf("FVEK 内部 datum 类型异常: 0x%X", d.ValueType)
	}
	if len(d.Body) < 4 {
		return nil, 0, fmt.Errorf("FVEK datum body 太短")
	}
	method = uint16(binary.LittleEndian.Uint32(d.Body[0:4]))
	fvek = d.Body[4:]
	return fvek, method, nil
}
