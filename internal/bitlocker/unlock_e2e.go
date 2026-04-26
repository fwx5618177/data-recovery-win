package bitlocker

import (
	"fmt"

	"data-recovery/internal/disk"
)

// UnlockResult 是端到端解锁的最终产出：可读的"明文"DiskReader + 元数据。
type UnlockResult struct {
	Reader            *DecryptingReader
	EncryptionMethod  uint16 // AES-XTS-128 / AES-XTS-256 等
	VolumeIdentifier  [16]byte
	MetadataBlock     *FVEMetadataBlock
}

// UnlockBitLockerVolumeWithRecoveryKey 是给上层用的"一键解锁"入口：
//
//	输入：
//	  - underlying:  打开的磁盘 reader（位置在 BitLocker 卷起始处）
//	  - bvolume:     bitlocker.Detect 拿到的 Volume 元数据
//	  - recoveryKey: 用户输入的 48 位 recovery key
//	  - progress:    stretch key 进度回调（让 UI 显示"正在派生密钥..."）
//
//	输出：
//	  - UnlockResult.Reader: 透明解密的 DiskReader，可直接喂给 NTFS scanner
//
// 失败原因可能是：recovery key 错 / metadata 损坏 / FVEK 解密 tag 不对。
// 失败的 error 文案会指明在哪一步出错以便定位。
func UnlockBitLockerVolumeWithRecoveryKey(
	underlying disk.DiskReader,
	bvolume *Volume,
	recoveryKey string,
	progress func(done, total uint64),
) (*UnlockResult, error) {
	if underlying == nil || bvolume == nil {
		return nil, fmt.Errorf("nil underlying / bvolume")
	}

	// 1. 读 FVE metadata —— 三个冗余位置依次试，第一个能 parse 就用
	var mb *FVEMetadataBlock
	var lastErr error
	for _, off := range []int64{
		bvolume.FVEMetaBlockOffset1,
		bvolume.FVEMetaBlockOffset2,
		bvolume.FVEMetaBlockOffset3,
	} {
		if off <= 0 {
			continue
		}
		// metadata block 在卷起始的相对偏移 → 转绝对偏移
		absOff := bvolume.Offset + off
		mb, lastErr = ParseFVEMetadataBlock(underlying, absOff)
		if mb != nil {
			break
		}
	}
	if mb == nil {
		return nil, fmt.Errorf("三个冗余 metadata block 全部解析失败: %v", lastErr)
	}

	// 2. 找到 recovery password VMK
	vmkDatum := mb.FindRecoveryPasswordVMK()
	if vmkDatum == nil {
		return nil, fmt.Errorf("此卷没有 recovery key 保护器（可能只用 TPM/password 等其他方式）")
	}

	// 3. 用 recovery key 解 VMK
	vmk, err := UnlockVMKWithRecoveryKey(recoveryKey, vmkDatum, progress)
	if err != nil {
		return nil, fmt.Errorf("VMK 解锁失败: %w", err)
	}

	// 4. 用 VMK 解出 FVEK
	fvek, method, err := ExtractFVEKFromMetadata(mb, vmk)
	if err != nil {
		return nil, fmt.Errorf("FVEK 提取失败: %w", err)
	}

	// 5. 按加密方法构造 SectorCipher（XTS / CBC / CBC+diffuser）
	sectorCipher, err := buildSectorCipherForMethod(fvek, method)
	if err != nil {
		return nil, err
	}

	// 6. 包装成透明解密 reader（开 8192 sector LRU 缓存 ≈ 4MB，
	//    覆盖 NTFS MFT hot 区，加密卷扫描显著加速）
	reader, err := NewDecryptingReaderWithCache(underlying, sectorCipher, bvolume.OEMID, 8192)
	if err != nil {
		return nil, err
	}
	// 把卷起始偏移告诉 reader：上层用 volume-relative offset，底层 IO 会自动 +volumeOffset
	reader.SetVolumeOffset(bvolume.Offset)

	// 如果 metadata 里有 Volume Header Block datum，把明文头大小告诉 reader，
	// 这段区间 ReadAt 会跳过 XTS 解密（那段数据本身是明文副本，再"解密"一次会变乱码）。
	if vhInfo := mb.FindVolumeHeaderInfo(); vhInfo != nil && vhInfo.PlaintextHeaderSize > 0 {
		reader.SetPlainTextHeaderEnd(vhInfo.PlaintextHeaderSize)
	}

	return &UnlockResult{
		Reader:           reader,
		EncryptionMethod: method,
		VolumeIdentifier: mb.VolumeIdentifier,
		MetadataBlock:    mb,
	}, nil
}

// BuildSectorCipherForMethodPublic 是 buildSectorCipherForMethod 的导出版，
// 给"在 unlock_e2e 之外自己拿到 fvek + method"的入口用（如 memory-image 路径）。
func BuildSectorCipherForMethodPublic(fvek []byte, method uint16) (SectorCipher, error) {
	return buildSectorCipherForMethod(fvek, method)
}

// buildSectorCipherForMethod 按 EncryptionMethod 选择正确的 SectorCipher 实现。
//
// 支持的算法：
//   - AES-XTS-128 / AES-XTS-256        Win10+ 默认
//   - AES-CBC-128 / AES-CBC-256        无 diffuser
//   - AES-CBC-128 + diffuser / AES-CBC-256 + diffuser    Vista / Win 7 默认
func buildSectorCipherForMethod(fvek []byte, method uint16) (SectorCipher, error) {
	switch method {
	case EncryptionAESXTS128:
		if len(fvek) < 32 {
			return nil, fmt.Errorf("AES-XTS-128 FVEK 长度不足: %d", len(fvek))
		}
		return NewXTSCipher(fvek[:32], 512)
	case EncryptionAESXTS256:
		if len(fvek) < 64 {
			return nil, fmt.Errorf("AES-XTS-256 FVEK 长度不足: %d", len(fvek))
		}
		return NewXTSCipher(fvek[:64], 512)
	case EncryptionAESCBC128, EncryptionAESCBC256,
		EncryptionAESCBCDiff128, EncryptionAESCBCDiff256:
		return NewCBCDiffuserCipher(fvek, method, 512)
	}
	return nil, fmt.Errorf("未知 BitLocker 加密方法: 0x%04X", method)
}
