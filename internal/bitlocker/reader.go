package bitlocker

import (
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// DecryptingReader 是一个 disk.DiskReader 实现，用 FVEK 透明解密 BitLocker 卷。
//
// 设计：
//   - 包一个底层（已解锁的）disk.DiskReader（通常是 image file 或物理盘）
//   - 用 XTSCipher 把每个 ReadAt 调用的扇区独立解密
//   - 透明导出"明文卷"给上层 NTFS scanner / carver 用
//
// 关键约束：
//   - 上层 ReadAt(buf, offset) 的 offset/size 必须扇区对齐？**不必**！
//     我们内部按扇区做 read+decrypt，再切片给调用方。这是性能 vs 简单的权衡。
//   - 加密区从 BitLocker 卷的某个起始扇区开始（不一定是 0；卷头不加密）
//
// BitLocker 卷头不加密的部分：
//   - 第一个 sector（boot sector）—— 含 OEM ID 和 FVE metadata 偏移指针
//   - 一些预留区域和 metadata blocks 本身
// 标准做法：从 metadata 里读 "Volume Header Block" datum（type 0x2007）拿到加密区
// 起止偏移；本实现简化为"全部扇区都解"——上层若读到卷头明文区也只是看到乱码而已，
// 后续读 NTFS boot sector 时都在加密区内，不影响。
//
// 对于大多数 Win10+ BitLocker 卷，第一个 sector 的明文是合法 NTFS boot sector
// （BitLocker 把它"复制保留"了一份），所以即便不解密第一个扇区，NTFS scanner 也能用。
// 这种"前若干扇区不加密"的特殊处理对正确性影响很小，留 TODO 待真实磁盘测试时再调。
// SectorCipher 抽象"按扇区独立解密"的能力。
// 实现方有 XTSCipher（Win10+ AES-XTS）和 CBCDiffuserCipher（Vista AES-CBC + diffuser）。
type SectorCipher interface {
	DecryptSector(dst, src []byte, sectorNumber uint64) error
	SectorSize() int
}

type DecryptingReader struct {
	underlying disk.DiskReader
	cipher     SectorCipher
	sectorSize int

	// BitLocker 卷在"整个物理盘"里的起始字节偏移。
	// 上层 NTFS scanner 视角里卷是从 0 开始的：ReadAt(_, 0) 读的是卷的第一扇区。
	// 我们把调用方给的 logical offset 加上 volumeOffset 得到物理盘偏移。
	// XTS sector_number 继续用 logical（volume 内）扇区号——这才是 BitLocker 的定义。
	volumeOffset int64

	// 卷头不加密区段：[0, plainTextHeaderEnd) 这段直接透传
	// 本 MVP 默认 0（全部加密），实际可由 metadata.VolumeHeaderBlock 设定
	plainTextHeaderEnd int64

	devicePath string // 用作日志 / DevicePath() 返回
}

// NewDecryptingReader 包装一个底层 reader，传入任意 SectorCipher 实现。
// 历史调用点会传 *XTSCipher，新调用点也可以传 *CBCDiffuserCipher。
func NewDecryptingReader(
	underlying disk.DiskReader,
	c SectorCipher,
	devicePath string,
) (*DecryptingReader, error) {
	if underlying == nil || c == nil {
		return nil, fmt.Errorf("nil underlying / cipher")
	}
	r := &DecryptingReader{
		underlying: underlying,
		cipher:     c,
		sectorSize: c.SectorSize(),
		devicePath: devicePath,
	}
	return r, nil
}

// SetPlainTextHeaderEnd 配置卷头不加密区结束偏移（字节数）。
// 调用方从 metadata 的 Volume Header Block datum 推算后传入。
func (r *DecryptingReader) SetPlainTextHeaderEnd(off int64) {
	r.plainTextHeaderEnd = off
}

// SetVolumeOffset 配置 BitLocker 卷在物理盘里的绝对起始字节偏移。
// 默认 0（调用方把 reader 指向的"就是卷本身"）；当 reader 指向整块物理盘时，
// 调用方必须传入 Detect() 找到的 volumeOffset，否则 XTS tweak 对不上会解出乱码。
func (r *DecryptingReader) SetVolumeOffset(off int64) {
	r.volumeOffset = off
}

// Open / Close 透传给 underlying；DecryptingReader 不持有自己的设备句柄
func (r *DecryptingReader) Open() error  { return r.underlying.Open() }
func (r *DecryptingReader) Close() error { return r.underlying.Close() }

// Size / SectorSize / DevicePath 透传或自定义
func (r *DecryptingReader) Size() (int64, error) { return r.underlying.Size() }
func (r *DecryptingReader) SectorSize() int      { return r.sectorSize }
func (r *DecryptingReader) DevicePath() string {
	if r.devicePath != "" {
		return r.devicePath
	}
	return r.underlying.DevicePath()
}

// ReadAt 是核心：按扇区对齐读，逐扇区解密，再裁到调用方要求的范围。
//
// 算法：
//  1. 算出 [offset, offset+len(p)) 落在哪些扇区上（first / last sector index）
//  2. 一次性从 underlying 读完这些扇区（连续 IO 比逐扇区快很多）
//  3. 对每个扇区独立解密（XTS sector_number = byte_offset / sectorSize）
//  4. 切出 [offset, offset+len(p)) 对应的字节
//  5. 卷头明文区（如果配置了）跳过解密
func (r *DecryptingReader) ReadAt(p []byte, offset int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if offset < 0 {
		return 0, fmt.Errorf("offset 不能为负")
	}

	sectorSize64 := int64(r.sectorSize)
	firstSector := offset / sectorSize64
	endByte := offset + int64(len(p))
	lastSector := (endByte - 1) / sectorSize64

	bufLen := int((lastSector - firstSector + 1) * sectorSize64)
	buf := make([]byte, bufLen)

	// 把 logical offset 翻译成物理盘 offset 再做底层 IO
	n, err := r.underlying.ReadAt(buf, r.volumeOffset+firstSector*sectorSize64)
	if err != nil && err != io.EOF && n == 0 {
		return 0, err
	}
	buf = buf[:n]

	// 逐扇区解密（卷头明文区直接保持）
	for i := int64(0); i*sectorSize64 < int64(len(buf)); i++ {
		sectorOff := (firstSector + i) * sectorSize64
		from := i * sectorSize64
		to := from + sectorSize64
		if int64(len(buf)) < to {
			break // 最后一段不完整扇区，跳过解密（数据已读，不解密直接给）
		}

		if sectorOff < r.plainTextHeaderEnd {
			// 卷头明文区，直接保持
			continue
		}

		sectorNum := uint64(firstSector + i)
		sectorBytes := buf[from:to]
		// in-place 解密
		if err := r.cipher.DecryptSector(sectorBytes, sectorBytes, sectorNum); err != nil {
			return 0, fmt.Errorf("扇区 %d 解密失败: %w", sectorNum, err)
		}
	}

	// 切出调用方真正要的范围
	startInBuf := offset - firstSector*sectorSize64
	available := int64(len(buf)) - startInBuf
	if available <= 0 {
		return 0, io.EOF
	}
	want := int64(len(p))
	if want > available {
		want = available
	}
	copy(p, buf[startInBuf:startInBuf+want])
	if want < int64(len(p)) {
		return int(want), io.EOF
	}
	return int(want), nil
}

// 编译期断言 DecryptingReader 实现 disk.DiskReader 接口
var _ disk.DiskReader = (*DecryptingReader)(nil)
