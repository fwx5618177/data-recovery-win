// Package veracrypt 检测 VeraCrypt / TrueCrypt 加密容器。
//
// **关键困难**：VeraCrypt 整个卷头是加密的（用户密码派生的密钥加密），所以**没有
// 明文 magic 可以匹配**。识别只能靠"统计学特征"：
//   - 整个 512 字节 boot sector 是高熵随机字节
//   - 没有 NTFS / exFAT / FAT / 任何已知文件系统的 OEM ID
//   - 文件大小 / 设备容量正好是 512 字节倍数 + 没有分区表
//
// 我们做"启发式 detect"：对盘前 N KB 算字节熵 + 排除已知文件系统魔数。
// 高熵 + 无已知 fs magic = "可能是 VeraCrypt 容器"提示。会有假阳性，但比"完全不识别"好。
//
// 完整解锁需要用户输入密码 → PBKDF2-HMAC-{SHA512/Whirlpool/SHA256/Streebog} (500000 iter) →
// 多 cipher cascade — 实现等同 VeraCrypt 项目本身，本工具不做。
package veracrypt

import (
	"fmt"
	"io"
	"math"

	"data-recovery/internal/disk"
)

// Hint 是"可能是 VeraCrypt 容器"的检测结果（只是提示，不保证）
type Hint struct {
	Offset     int64
	Confidence float64 // 0..1；越高越像
	Note       string
}

// 已知文件系统的 OEM ID / magic（命中其中之一就说明不是 VC）
var knownOEMIDs = []string{
	"NTFS    ",
	"MSDOS5.0",
	"MSWIN4.1",
	"EXFAT   ",
	"-FVE-FS-", // BitLocker
}

// Detect 启发式扫前 4KB；高熵 + 无 known OEM ID + 无分区表 → 给出 hint。
func Detect(reader disk.DiskReader, volStart int64) (*Hint, error) {
	const probe = 4096
	buf := make([]byte, probe)
	n, err := reader.ReadAt(buf, volStart)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 VC 候选: %w", err)
	}
	if n < probe {
		return nil, nil
	}
	// 排除已知 OEM ID
	if len(buf) >= 11 {
		for _, oem := range knownOEMIDs {
			if string(buf[3:11]) == oem {
				return nil, nil
			}
		}
	}
	// 排除 GPT
	if string(buf[512:520]) == "EFI PART" {
		return nil, nil
	}
	// 排除 MBR (boot signature 0xAA55 + 看起来像分区表)
	if buf[510] == 0x55 && buf[511] == 0xAA {
		// 是 MBR；检查分区表 4 项是否合理
		nonEmpty := 0
		for i := 0; i < 4; i++ {
			if buf[446+i*16+4] != 0 {
				nonEmpty++
			}
		}
		if nonEmpty > 0 {
			return nil, nil
		}
	}
	// 高熵检查
	ent := byteEntropy(buf)
	if ent < 7.5 {
		return nil, nil
	}
	return &Hint{
		Offset:     volStart,
		Confidence: (ent - 7.5) / 0.5, // 7.5..8.0 → 0..1
		Note:       fmt.Sprintf("可能是 VeraCrypt / TrueCrypt 容器（前 4KB 熵 %.2f bits，无已知 fs magic）。请用 VeraCrypt 客户端解锁后再扫挂载点。", ent),
	}, nil
}

func byteEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var hist [256]int
	for _, c := range b {
		hist[c]++
	}
	total := float64(len(b))
	h := 0.0
	for _, cnt := range hist {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) / total
		h -= p * math.Log2(p)
	}
	return h
}
