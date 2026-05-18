package carver

import (
	"data-recovery/internal/disk"
)

// bufferBackedReader 让 detector / classifier 从已读到内存的 chunk 切片读，
// 命中不到才 fallback 底层 reader —— **零额外 IO**。
//
// 背景（v2.8.45 重构 v2.8.43-44 的 prefetchReader）：
// 之前 collector 对每个 AC match 主动 ReadAt 256KB-1MB prefetch，但 AC 误报
// 极多（每 8MB chunk 几百 match），bandwidth-limited 盘（USB / 网络盘）上
// IO 放大 5-10×，把扫描速度从 305 KB/s 拖到 67 KB/s。
//
// 关键洞察：chunk 数据已经在 worker 那边读到内存了。worker 把 match 起点
// 附近 32KB 切片拷贝给 rawMatch.Header，collector 直接用这块内存就够 99% 的
// detector 用例（JPEG marker / PNG chunk / MP4 ftyp / TIFF IFD），完全不用
// 触发额外 ReadAt。
//
// 不命中（极少数情况，比如 MP4 sample table 在 file body 后段）才 fallback
// 到底层 reader 做真正的 disk read，行为正确。
type bufferBackedReader struct {
	inner     disk.DiskReader
	bufferOff int64 // 缓冲区起始的磁盘偏移
	buffer    []byte
}

// newBufferBackedReader 用一段已在内存的 header 切片 + 底层 reader 兜底
// 构造 wrapper。如果 buffer 为空（worker 来不及拷贝），所有 ReadAt 直接
// fallback 底层 —— 行为正确，性能等价于原始 reader。
func newBufferBackedReader(inner disk.DiskReader, bufferOff int64, buffer []byte) *bufferBackedReader {
	return &bufferBackedReader{inner: inner, bufferOff: bufferOff, buffer: buffer}
}

func (b *bufferBackedReader) ReadAt(p []byte, off int64) (int, error) {
	if b.buffer != nil {
		need := int64(len(p))
		bufEnd := b.bufferOff + int64(len(b.buffer))
		// 完整落在 buffer 内 → 内存切片，零 IO
		if off >= b.bufferOff && off+need <= bufEnd {
			start := off - b.bufferOff
			return copy(p, b.buffer[start:start+need]), nil
		}
	}
	return b.inner.ReadAt(p, off)
}

func (b *bufferBackedReader) Open() error          { return b.inner.Open() }
func (b *bufferBackedReader) Close() error         { return b.inner.Close() }
func (b *bufferBackedReader) Size() (int64, error) { return b.inner.Size() }
func (b *bufferBackedReader) SectorSize() int      { return b.inner.SectorSize() }
func (b *bufferBackedReader) DevicePath() string   { return b.inner.DevicePath() }

// 编译期断言
var _ disk.DiskReader = (*bufferBackedReader)(nil)
