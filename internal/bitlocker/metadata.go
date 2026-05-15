package bitlocker

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// FVEMetadataBlock 是 BitLocker 在卷里固定位置存放的元数据集合（通常 3 份冗余）。
//
// 结构（基于 [MS-FVE] § 3.2.1.1）：
//
//	+0x00  Signature    "-FVE-FS-"  (8 bytes)
//	+0x08  Size         uint16  本块字节数（含全部 entries + padding）
//	+0x0A  Version      uint16  通常 = 2
//	+0x0C  HeaderSize   uint16  metadata header 字节数（典型 0x40 / 64）
//	+0x0E  CopyNumber   uint16
//	+0x10  VolumeIdentifier  GUID (16)
//	+0x20  NextNonceCounter  uint32
//	+0x24  EncryptionMethod  uint16  (AES-CBC-128/256, AES-XTS-128/256)
//	+0x26  ?            uint16
//	+0x28  CreationTime FILETIME (8)
//	+0x30  ... 偏移 0x40 之后是 datum 序列
//
// EncryptionMethod 取值：
//
//	0x8000 AES-CBC-128 with diffuser    (Vista)
//	0x8001 AES-CBC-256 with diffuser    (Vista)
//	0x8002 AES-CBC-128 no diffuser
//	0x8003 AES-CBC-256 no diffuser
//	0x8004 AES-XTS-128                  (Win10+)
//	0x8005 AES-XTS-256                  (Win10+)
const (
	EncryptionAESCBCDiff128 uint16 = 0x8000
	EncryptionAESCBCDiff256 uint16 = 0x8001
	EncryptionAESCBC128     uint16 = 0x8002
	EncryptionAESCBC256     uint16 = 0x8003
	EncryptionAESXTS128     uint16 = 0x8004
	EncryptionAESXTS256     uint16 = 0x8005
)

// FVEMetadataBlock 解析后的元数据块
type FVEMetadataBlock struct {
	Signature        string
	Size             uint16
	Version          uint16
	HeaderSize       uint16
	CopyNumber       uint16
	VolumeIdentifier [16]byte
	NextNonceCounter uint32
	EncryptionMethod uint16
	Datums           []Datum
}

// ParseFVEMetadataBlock 从绝对字节偏移 absOffset 处读取并解析整个 metadata block。
//
// 调用方应该先用 Detect() 拿到 Volume.FVEMetaBlockOffset1/2/3，三处都试一下，
// 优先用前两处一致校验过的（这是 BitLocker 自己的冗余设计）。
func ParseFVEMetadataBlock(reader disk.DiskReader, absOffset int64) (*FVEMetadataBlock, error) {
	// 先读 64 字节头部，再按 Size 字段读完整块
	hdr := make([]byte, 64)
	n, err := reader.ReadAt(hdr, absOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 FVE metadata 头失败: %w", err)
	}
	if n < 64 {
		return nil, fmt.Errorf("FVE metadata 头不足: %d", n)
	}
	if string(hdr[0:8]) != fveOEMID {
		return nil, fmt.Errorf("FVE metadata 签名错: %q", string(hdr[0:8]))
	}

	mb := &FVEMetadataBlock{
		Signature:        string(hdr[0:8]),
		Size:             binary.LittleEndian.Uint16(hdr[8:10]),
		Version:          binary.LittleEndian.Uint16(hdr[10:12]),
		HeaderSize:       binary.LittleEndian.Uint16(hdr[12:14]),
		CopyNumber:       binary.LittleEndian.Uint16(hdr[14:16]),
		NextNonceCounter: binary.LittleEndian.Uint32(hdr[32:36]),
		EncryptionMethod: binary.LittleEndian.Uint16(hdr[36:38]),
	}
	copy(mb.VolumeIdentifier[:], hdr[16:32])

	// 合理性（uint16 自然上限 64KB，所以只校验下限）
	if mb.Size < mb.HeaderSize {
		return nil, fmt.Errorf("FVE metadata Size 异常: %d < HeaderSize %d", mb.Size, mb.HeaderSize)
	}
	if mb.HeaderSize < 64 || mb.HeaderSize > mb.Size {
		return nil, fmt.Errorf("FVE metadata HeaderSize 异常: %d", mb.HeaderSize)
	}

	// 读完整块（如果比 64 大）
	full := make([]byte, mb.Size)
	if int(mb.Size) > 64 {
		n, err := reader.ReadAt(full, absOffset)
		if err != nil && n == 0 {
			return nil, fmt.Errorf("读 FVE metadata 完整块失败: %w", err)
		}
		if n < int(mb.Size) {
			return nil, fmt.Errorf("FVE metadata 完整块读不完整: %d / %d", n, mb.Size)
		}
	} else {
		copy(full, hdr[:mb.Size])
	}

	// 从 HeaderSize 之后 parse datum 列表
	if int(mb.HeaderSize) < len(full) {
		datums, err := parseDatumList(full[mb.HeaderSize:])
		if err == nil {
			mb.Datums = datums
		}
	}

	return mb, nil
}

// VMKDatum 是从 metadata 中提取出来的单个 VMK 保护器条目（**未解密**的 VMK）
type VMKDatum struct {
	GUID           [16]byte
	ProtectionType uint16
	Datum          *Datum // 原始 VMK datum，含子 datum（STRETCH_KEY / AES_CCM_KEY 等）
}

// FindVMKs 从 metadata 里枚举所有 VMK 保护器条目
func (mb *FVEMetadataBlock) FindVMKs() []VMKDatum {
	all := FindAllDatumByValueType(mb.Datums, DatumValueVMK)
	out := make([]VMKDatum, 0, len(all))
	for _, d := range all {
		if len(d.Body) < 28 {
			continue
		}
		v := VMKDatum{Datum: d}
		copy(v.GUID[:], d.Body[0:16])
		v.ProtectionType = binary.LittleEndian.Uint16(d.Body[24:26])
		out = append(out, v)
	}
	return out
}

// FindRecoveryPasswordVMK 找第一个由 48 位恢复密钥保护的 VMK
func (mb *FVEMetadataBlock) FindRecoveryPasswordVMK() *VMKDatum {
	for _, v := range mb.FindVMKs() {
		if v.ProtectionType == VMKProtectionRecoveryPwd {
			vCopy := v
			return &vCopy
		}
	}
	return nil
}

// VolumeHeaderInfo 是 metadata 里 "Volume Header Block" datum 解出来的信息。
// 对应 [MS-FVE] 3.2.1.5 里的 FVE_VOLUME_HEADER_DESCRIPTOR。
// 它描述"原始卷头前 N 字节（即 NTFS boot sector 那一段）在加密前的明文位置"。
//
// BitLocker 把原始卷头（含 NTFS 魔数、BPB 等）加密后，会在磁盘里另一处重新写一段明文副本，
// 让操作系统即使还没加载 BitLocker 驱动也能认出这是个"卷"（fvevol.sys 用这个定位）。
// 我们做只读扫描时：
//   - 超出 PlaintextHeaderSize 的扇区必须 XTS 解密
//   - [0, PlaintextHeaderSize) 这段本身已经是明文，不能再解密一次（否则会出乱码）
type VolumeHeaderInfo struct {
	// 加密前"真实卷头"在卷里的字节偏移（通常 0）
	OriginalOffset int64
	// "明文卷头副本"在卷里的字节偏移
	PlaintextOffset int64
	// 明文卷头副本字节数（上层读到这个范围内的数据直接当明文用）
	PlaintextHeaderSize int64
}

// FindVolumeHeaderInfo 在 metadata 里查找 Volume Header Block datum 并解出
// 加密/明文偏移。找不到返回 nil（不是错误 —— 某些老版本 BitLocker 布局没这个）。
//
// Volume Header Block datum 结构（[MS-FVE] 3.2.1.5）：
//
//	+0x00  datum header (8)
//	+0x08  block_offset  uint64  encrypted 原始卷头在卷里的字节偏移
//	+0x10  block_size    uint64  encrypted 原始卷头的字节数
//	+0x18  data_offset   uint64  "明文副本"所在的字节偏移
//	...
func (mb *FVEMetadataBlock) FindVolumeHeaderInfo() *VolumeHeaderInfo {
	for i := range mb.Datums {
		d := &mb.Datums[i]
		if d.Type != DatumEntryVolumeHeaderBlock {
			continue
		}
		// datum body 至少要含 3 个 uint64
		if len(d.Body) < 24 {
			continue
		}
		info := &VolumeHeaderInfo{
			OriginalOffset:      int64(binary.LittleEndian.Uint64(d.Body[0:8])),
			PlaintextHeaderSize: int64(binary.LittleEndian.Uint64(d.Body[8:16])),
			PlaintextOffset:     int64(binary.LittleEndian.Uint64(d.Body[16:24])),
		}
		// 合理性：SIZE 不能比整卷还大，避免脏 metadata 导致后续 ReadAt OOB
		if info.PlaintextHeaderSize < 0 || info.PlaintextHeaderSize > (1<<40) {
			continue
		}
		return info
	}
	return nil
}
