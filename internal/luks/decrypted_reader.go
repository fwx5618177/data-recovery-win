package luks

// ============================================================================
// DecryptedReader —— 把"已解锁的 LUKS 卷"暴露成一个普通 DiskReader
//
// 角色：拿到 master_key 后，下游 NTFS / ext4 / APFS 等扫描器直接对它 ReadAt，
// 完全不需要知道这是个 LUKS 卷。架构上这层把 "存储介质" 与 "文件系统解析器"
// 彻底解耦——和 BitLocker / VeraCrypt 走同一种代理模式，未来再加 dm-crypt 等
// 也只需要套同一个 SectorCipher 接口。
//
// 性能要点：
//   - ReadAt 每次只解密"实际命中的 sectors"，不缓存解密结果（NTFS scanner 自己
//     有 LRU；这里再做一层就重复占内存）
//   - 多 goroutine 并发 ReadAt 是安全的：xts.Cipher.Decrypt 是无状态的，
//     底层 reader.ReadAt 有 io.ReaderAt 语义保证
//   - 非 sector 对齐的请求自动扩到对齐边界后切片返回，对外完全透明
// ============================================================================

import (
	"errors"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// DecryptedReader 把 [start, start+size) 区间里的密文按 sectorIndex 解密后
// 暴露成偏移从 0 开始的虚拟磁盘。
type DecryptedReader struct {
	underlying  disk.DiskReader
	cipher      SectorCipher
	payloadOff  int64  // 密文起点（在 underlying 上的字节偏移）
	payloadSize int64  // 解密后可见的总字节数（dynamic 时传 0 表示直到 underlying 末尾）
	devicePath  string // 透传，便于上层提示"现在扫的是 unlocked-XXX"
	// sector_size：512 (LUKS1 / 老 LUKS2) 或 4096 (现代 LUKS2 + Advanced Format / NVMe)
	// 由 cipher.SectorSize() 决定，与 SectorCipher 的 4K-aware 实现联动
	sectorSize int
	// ivBase 是 LUKS2 segment.iv_tweak 字段（LUKS1 一律 0）。
	// XTS 的 sector tweak = ivBase + (offset / sectorSize)
	ivBase uint64

	// 可选 LRU 缓存（CacheSectors > 0 时启用）；由 disk 包提供共享实现，
	// LUKS / VC / BitLocker 同型号复用，降低维护面 + 单点优化全部受益。
	cache *disk.SectorCache
}

// DecryptedReaderConfig 构造参数
type DecryptedReaderConfig struct {
	Underlying  disk.DiskReader
	Cipher      SectorCipher
	PayloadOff  int64  // payload 起点字节偏移
	PayloadSize int64  // 0 = 用 underlying.Size() - PayloadOff
	DevicePath  string // 默认 "luks-decrypted://" + underlying.DevicePath()
	IVBase      uint64 // 默认 0
	// CacheSectors 启用解密 sector 缓存，单位 = 多少个 sector。
	// 0 = 禁用；典型 8192 (= 4MB @ 512B / 32MB @ 4096B) 命中率最佳。
	// 加密卷扫描 NTFS 时 hot 区集中在 MFT 前 1MB；4-8MB 缓存覆盖 80%+。
	CacheSectors int
}


// NewDecryptedReader 构造一个解密视图 reader。
// underlying 必须已经 Open()；本 reader 的 Open() / Close() 透传到底层。
func NewDecryptedReader(cfg DecryptedReaderConfig) (*DecryptedReader, error) {
	if cfg.Underlying == nil {
		return nil, errors.New("DecryptedReader: underlying 为 nil")
	}
	if cfg.Cipher == nil {
		return nil, errors.New("DecryptedReader: cipher 为 nil")
	}
	if cfg.PayloadOff < 0 {
		return nil, fmt.Errorf("DecryptedReader: payloadOff 非法 %d", cfg.PayloadOff)
	}
	sectorSize := cfg.Cipher.SectorSize()
	if sectorSize <= 0 {
		return nil, errors.New("DecryptedReader: cipher.SectorSize() <= 0")
	}
	if cfg.PayloadOff%int64(sectorSize) != 0 {
		return nil, fmt.Errorf("DecryptedReader: payloadOff %d 未按 %d 字节对齐",
			cfg.PayloadOff, sectorSize)
	}

	devicePath := cfg.DevicePath
	if devicePath == "" {
		devicePath = "luks-decrypted://" + cfg.Underlying.DevicePath()
	}

	size := cfg.PayloadSize
	if size == 0 {
		us, err := cfg.Underlying.Size()
		if err != nil {
			return nil, fmt.Errorf("DecryptedReader: 读 underlying size: %w", err)
		}
		size = us - cfg.PayloadOff
		if size < 0 {
			return nil, fmt.Errorf("DecryptedReader: payloadOff %d 超过 underlying size %d",
				cfg.PayloadOff, us)
		}
	}

	dr := &DecryptedReader{
		underlying:  cfg.Underlying,
		cipher:      cfg.Cipher,
		payloadOff:  cfg.PayloadOff,
		payloadSize: size,
		devicePath:  devicePath,
		sectorSize:  sectorSize,
		ivBase:      cfg.IVBase,
	}
	if cfg.CacheSectors > 0 {
		dr.cache = disk.NewSectorCache(cfg.CacheSectors)
	}
	return dr, nil
}

// Open / Close 透传 ——
// 上层期望 DiskReader 是"自管理生命周期"的；这里我们不关闭 underlying（它的所有权
// 在调用方，可能还要被别的代码用），只做 no-op。
func (d *DecryptedReader) Open() error  { return nil }
func (d *DecryptedReader) Close() error { return nil }

// CacheStats 返回 LRU sector 缓存命中率快照（cache 未启用时所有字段为 0）。
// 给 UI / metrics 端点用 —— "缓存命中率 87%" 让用户能感知优化生效。
func (d *DecryptedReader) CacheStats() disk.CacheStats { return d.cache.Stats() }

// Size 返回解密后可见区域的字节数
func (d *DecryptedReader) Size() (int64, error) { return d.payloadSize, nil }

// SectorSize 返回 cipher 的扇区粒度：512 或 4096，由 LUKS2 segment.sector_size 决定
func (d *DecryptedReader) SectorSize() int { return d.sectorSize }

// DevicePath 返回上层带前缀的虚拟设备路径
func (d *DecryptedReader) DevicePath() string { return d.devicePath }

// ReadAt 对外接口：buf / offset 都是 *解密视图* 上的字节坐标。
// 自动按扇区扩边、解密、切片返回——上层完全感知不到底层在做加密解密。
func (d *DecryptedReader) ReadAt(buf []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("DecryptedReader.ReadAt: 负偏移 %d", offset)
	}
	if offset >= d.payloadSize {
		return 0, io.EOF
	}
	if len(buf) == 0 {
		return 0, nil
	}

	// 截到不越界
	want := int64(len(buf))
	if offset+want > d.payloadSize {
		want = d.payloadSize - offset
	}

	// 算 sector-aligned 的 [readStart, readEnd)
	ss := int64(d.sectorSize)
	readStart := (offset / ss) * ss
	readEnd := ((offset + want + ss - 1) / ss) * ss
	if readEnd > d.payloadSize {
		// 视图末尾不足一个完整 sector：需要把这个 sector 完整读+解密，但只返回有效字节
		readEnd = ((d.payloadSize + ss - 1) / ss) * ss
	}
	readLen := readEnd - readStart

	encBuf := make([]byte, readLen)

	// 若启用缓存且整段命中，直接跳过底层 IO + cipher
	allHit := false
	if d.cache != nil {
		allHit = true
		for i := int64(0); i+ss <= readLen; i += ss {
			sectorIdx := uint64(readStart/ss) + uint64(i/ss) + d.ivBase
			if !d.cache.Get(sectorIdx, encBuf[i:i+ss]) {
				allHit = false
				break
			}
		}
	}

	if !allHit {
		n, err := d.underlying.ReadAt(encBuf, d.payloadOff+readStart)
		if err != nil && err != io.EOF {
			return 0, fmt.Errorf("DecryptedReader: 底层 ReadAt: %w", err)
		}
		// 若底层短读：截断到实际拿到的字节，但解密粒度仍按完整 sector 处理；
		// 不足 sector 的尾巴丢弃（解密结果会损坏，无意义）。
		usable := int64(n) / ss * ss
		if usable < readLen {
			readLen = usable
			encBuf = encBuf[:readLen]
		}

		// 逐 sector 解密：cache 命中的 sector 跳过 cipher 直接 overwrite。
		for i := int64(0); i+ss <= readLen; i += ss {
			sectorIdx := uint64(readStart/ss) + uint64(i/ss) + d.ivBase
			if d.cache.Get(sectorIdx, encBuf[i:i+ss]) {
				continue
			}
			if err := d.cipher.DecryptSector(encBuf[i:i+ss], sectorIdx); err != nil {
				return 0, fmt.Errorf("DecryptedReader: 扇区 %d 解密失败: %w", sectorIdx, err)
			}
			d.cache.Put(sectorIdx, encBuf[i:i+ss])
		}
	}

	// 复制到调用者 buf
	skip := offset - readStart
	avail := int64(len(encBuf)) - skip
	if avail <= 0 {
		return 0, io.EOF
	}
	copyLen := want
	if avail < copyLen {
		copyLen = avail
	}
	copy(buf[:copyLen], encBuf[skip:skip+copyLen])

	if copyLen < int64(len(buf)) {
		// 调用者要的比我们能给的多——返回实际给的字节数 + EOF（io.ReaderAt 语义）
		return int(copyLen), io.EOF
	}
	return int(copyLen), nil
}

var _ disk.DiskReader = (*DecryptedReader)(nil)
