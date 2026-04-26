package veracrypt

// ============================================================================
// VeraCrypt / TrueCrypt 卷头解析
//
// 卷头物理布局（512 字节，从卷起点算）：
//
//   off  size  field
//   0    64    salt（明文，PBKDF2 输入）
//   64   448   encrypted header data（用 header_key 经 AES-XTS-256 加密，sector_idx=0）
//
// 解密后这 448 字节内部布局（offset 都是相对解密块起点）：
//
//   off  size  field
//   0    4     ASCII signature: "VERA" 或 "TRUE"
//   4    2     header version (BE)        VC 当前 5；TC 5+
//   6    2     min program version (BE)
//   8    4     CRC-32 of decrypted bytes 192..447 (master keys area), BE
//   12   16    reserved (zeros)
//   28   8     hidden volume size (BE)
//   36   8     volume size (BE)
//   44   8     master key area start byte (BE) —— payload 区起点（卷内字节偏移）
//   52   8     master key area size (BE)        —— payload 区字节数
//   60   4     flag bits (BE)
//   64   4     sector size (BE), 默认 512
//   68   120   reserved
//   188  4     CRC-32 of decrypted bytes 0..187 (header data), BE
//   192  64    reserved (zeros)
//   256  192   master keys area —— AES-XTS-256 用前 64B（32B cipher + 32B tweak）
//
// 数据区 XTS sector index = byte_offset_within_volume / 512
// （**重要**：和 LUKS 不一样！LUKS 是相对 payload 起点；VC 是相对卷起点。）
// ============================================================================

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	// SaltSize 是卷头明文 salt 的字节数
	SaltSize = 64

	// EncryptedHeaderSize 是 PBKDF2 派生 header_key 加密的字节数
	EncryptedHeaderSize = 448

	// VolumeHeaderTotalSize 是卷头总字节数（salt + encrypted）
	VolumeHeaderTotalSize = SaltSize + EncryptedHeaderSize // 512

	// 标准容器卷头偏移（针对非系统加密 / 非隐藏卷）
	StandardVolumeHeaderOffset int64 = 0

	// 隐藏卷头偏移：紧接标准卷头之后
	HiddenVolumeHeaderOffset int64 = 65536

	// 备份头距卷尾的字节数（用于损坏卷恢复）
	BackupHeaderTrailerOffset int64 = 65536

	// HeaderEncSectorSize 是头部 XTS 加解密的扇区大小（必须 = SectorSize）
	HeaderEncSectorSize = 512

	// 系统加密卷头偏移（VC Windows 全盘加密）
	//
	// 来源：VC src/Common/Crypto.h
	//   TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET = 62 * 512 = 31744
	//
	// 系统加密 (Windows boot 盘) layout：
	//   sector 0..61   (offset 0..31743):    boot loader（不加密）
	//   sector 62      (offset 31744):       VC volume header（512B；同 layout = 64 salt + 448 encrypted）
	//   sector 63..255 (offset 32256..131071): reserved / boot loader 续区
	//   sector 256+    (offset 131072+):     加密数据区（Windows 分区内容）
	SystemEncryptionHeaderOffset int64 = 31744
)

// VolumeHeader 解密后的卷头
type VolumeHeader struct {
	IsTrueCrypt   bool   // true="TRUE"，false="VERA"
	HeaderVersion uint16
	MinProgVer    uint16
	HiddenSize    uint64
	VolumeSize    uint64
	PayloadOffset uint64 // master key area 起点（字节，相对卷起点）
	PayloadSize   uint64 // master key area 大小（字节）
	Flags         uint32
	SectorSize    uint32

	// MasterKey 是数据区加密用的完整 key 区（192 字节，cascade 最多用满）
	// 单 cipher (AES-XTS-256) 只用前 64 字节：32B cipher + 32B tweak
	MasterKey []byte
}

var (
	veraSignature = []byte{'V', 'E', 'R', 'A'}
	trueSignature = []byte{'T', 'R', 'U', 'E'}
)

// ParseDecryptedHeader 解析 *已用 header_key 解密好的* 448 字节卷头。
//
// 校验流程（从严到松）：
//   1. signature 必须是 "VERA" / "TRUE"
//   2. header CRC32 必须匹配（防止密码恰好让加密 garbage 看起来像头）
//   3. master keys CRC32 必须匹配
//   4. 卷大小 / payload offset / payload size 都要合理
//
// 任何一步失败都返回 error；上层"枚举密码 × 算法"循环里把错误当成密码错处理。
func ParseDecryptedHeader(buf []byte) (*VolumeHeader, error) {
	if len(buf) < EncryptedHeaderSize {
		return nil, fmt.Errorf("VC 头部 buffer 太短: %d", len(buf))
	}
	buf = buf[:EncryptedHeaderSize]

	// 1) signature
	sig := buf[0:4]
	var isTC bool
	switch {
	case bytesEq(sig, veraSignature):
		isTC = false
	case bytesEq(sig, trueSignature):
		isTC = true
	default:
		return nil, errors.New("VC: signature 不是 VERA/TRUE（密码或算法不对）")
	}

	// 2) header data CRC32 (decrypted bytes 0..187, expected at 188..191)
	headerCRC := binary.BigEndian.Uint32(buf[188:192])
	if got := crc32.ChecksumIEEE(buf[0:188]); got != headerCRC {
		return nil, fmt.Errorf("VC 头部 CRC32 不匹配: got %08x want %08x", got, headerCRC)
	}

	// 3) master keys CRC32 (decrypted bytes 192..447, expected at 8..11)
	mkCRC := binary.BigEndian.Uint32(buf[8:12])
	if got := crc32.ChecksumIEEE(buf[192:EncryptedHeaderSize]); got != mkCRC {
		return nil, fmt.Errorf("VC master keys CRC32 不匹配")
	}

	h := &VolumeHeader{
		IsTrueCrypt:   isTC,
		HeaderVersion: binary.BigEndian.Uint16(buf[4:6]),
		MinProgVer:    binary.BigEndian.Uint16(buf[6:8]),
		HiddenSize:    binary.BigEndian.Uint64(buf[28:36]),
		VolumeSize:    binary.BigEndian.Uint64(buf[36:44]),
		PayloadOffset: binary.BigEndian.Uint64(buf[44:52]),
		PayloadSize:   binary.BigEndian.Uint64(buf[52:60]),
		Flags:         binary.BigEndian.Uint32(buf[60:64]),
		SectorSize:    binary.BigEndian.Uint32(buf[64:68]),
	}

	// 192 字节 cascade key 区
	h.MasterKey = append([]byte{}, buf[256:EncryptedHeaderSize]...)

	// 4) 合理性
	if h.SectorSize != 512 {
		return nil, fmt.Errorf("VC 不支持 sector_size=%d（仅 512）", h.SectorSize)
	}
	if h.VolumeSize == 0 || h.PayloadSize == 0 {
		return nil, errors.New("VC 卷大小 / payload size 为 0（头部数据破坏）")
	}
	// 注意：VC system encryption 卷头里 PayloadOffset 也可以是 0（boot 区不算 payload，
	// 加密数据区从 sector 256 = 131072 字节开始 = data area；但 PayloadOffset 字段
	// 表达的是"加密区起点"在 *partition* 里的字节偏移，可能为 0/131072/其他）。
	// 这里不再硬性拒绝 PayloadOffset==0 —— 让 caller (system encryption parser) 决定。
	return h, nil
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
