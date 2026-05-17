package carver

import (
	"io"

	"data-recovery/internal/disk"
)

// prefetchReader 用 1 次大读吃掉所有 detector 用到的小读。
//
// 背景（v2.8.43）：用户报扫描 305 KB/s。审计发现 carver collector 给每个
// 匹配的文件调 determineFileSize → detectJPEGSize / detectMP4Size 等，
// 每个 detector 内部又做几十次 1-2 字节的 ReadAt（JPEG marker / MP4 box header
// / EXIF IFD entry）。HDD 上每次 ReadAt = 一次 5-10ms 寻道，30 次 = 200ms
// 浪费 / 文件。1000 文件就丢 200 秒到寻道。
//
// 这个 wrapper：
//   - 构造时 1 次大读窗口（默认 256KB，足够 JPEG header + MP4 ftyp + EOCD 等场景）
//   - ReadAt 落在窗口内 → 从内存切片，免寻道
//   - 落在窗口外 → 转发底层 reader（兜底）
//
// 不持有 underlying lifecycle —— Open / Close 转发，但不会主动关闭，
// 让上层管理底层 reader 的生命周期（典型场景：detector 用完即丢弃 wrapper，
// 底层 reader 继续给主扫描用）。
type prefetchReader struct {
	inner    disk.DiskReader
	cacheOff int64
	cache    []byte
}

// newPrefetchReader 创建一个预读 wrapper。size 是预读窗口字节数。
// 调用方应该传 detector 估计能用到的范围 + 一点 margin。
//
// 实际读到的可能少于 size（到达磁盘末尾），cache 字段记真实长度。
// 如果连一个字节都读不到（offset 越界 / 设备出错），cache 是 nil，
// 所有 ReadAt 都转发底层 —— 等于退化成无 cache 模式，行为正确。
func newPrefetchReader(inner disk.DiskReader, offset int64, size int) *prefetchReader {
	if size <= 0 {
		size = 256 * 1024
	}
	pr := &prefetchReader{inner: inner, cacheOff: offset}
	buf := make([]byte, size)
	n, err := inner.ReadAt(buf, offset)
	if n > 0 {
		pr.cache = buf[:n]
	}
	// 允许 io.EOF / 短读 —— cache 截断到 n 即可
	_ = err
	return pr
}

// ReadAt 实现 disk.DiskReader 的核心方法。
// 命中 cache → 内存 copy；否则转发底层。
func (p *prefetchReader) ReadAt(b []byte, off int64) (int, error) {
	if p.cache != nil {
		need := int64(len(b))
		cacheEnd := p.cacheOff + int64(len(p.cache))
		// 完整在 cache 内 → 直接拷贝
		if off >= p.cacheOff && off+need <= cacheEnd {
			start := off - p.cacheOff
			return copy(b, p.cache[start:start+need]), nil
		}
		// 部分在 cache 内（前半 cache + 后半底层）—— 不优化，直接转发
		// （detector 场景里这种横跨非常少，优化复杂收益小）
	}
	return p.inner.ReadAt(b, off)
}

// 以下都是转发 —— prefetchReader 不管底层生命周期
func (p *prefetchReader) Open() error          { return p.inner.Open() }
func (p *prefetchReader) Close() error         { return p.inner.Close() }
func (p *prefetchReader) Size() (int64, error) { return p.inner.Size() }
func (p *prefetchReader) SectorSize() int      { return p.inner.SectorSize() }
func (p *prefetchReader) DevicePath() string   { return p.inner.DevicePath() }

// 编译期断言：prefetchReader 是 disk.DiskReader
var _ disk.DiskReader = (*prefetchReader)(nil)

// 让 io.EOF / io.ErrUnexpectedEOF 引用不被 fmt 优化掉（防 staticcheck）
var _ = io.EOF
