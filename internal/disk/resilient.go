package disk

import (
	"errors"
	"io"
	"sync"
	"time"
)

// ResilientReader 包一个底层 DiskReader，加入坏扇区跳过 + 重试 + 0 填充策略。
//
// 用户场景：物理盘已经有部分坏扇区，普通 ReadAt 遇到 IO error 直接停 → 扫不完。
// 这里的策略（参考 GNU ddrescue）：
//   - 大块读失败时按 sectorSize 切分逐块重读
//   - 每块最多重试 N 次（默认 2）
//   - 全失败的块用 0 填充并记录到 BadSectors 列表
//   - 上层（NTFS scanner / carver）拿到字节即可继续，事后从 BadSectors 拿不可恢复区列表
type ResilientReader struct {
	underlying  DiskReader
	sectorSize  int64
	maxRetry    int
	mu          sync.Mutex
	badSectors  []BadSector
}

type BadSector struct {
	Offset int64
	Size   int64
	Err    string
}

// NewResilientReader 默认值：sectorSize=512，maxRetry=2。
// 调用方传 0 用默认。
func NewResilientReader(underlying DiskReader, sectorSize int64, maxRetry int) *ResilientReader {
	if sectorSize <= 0 {
		sectorSize = 512
	}
	if maxRetry <= 0 {
		maxRetry = 2
	}
	return &ResilientReader{
		underlying: underlying,
		sectorSize: sectorSize,
		maxRetry:   maxRetry,
	}
}

func (r *ResilientReader) Open() error  { return r.underlying.Open() }
func (r *ResilientReader) Close() error { return r.underlying.Close() }
func (r *ResilientReader) Size() (int64, error) { return r.underlying.Size() }
func (r *ResilientReader) SectorSize() int      { return int(r.sectorSize) }
func (r *ResilientReader) DevicePath() string   { return r.underlying.DevicePath() }

// ReadAt 是核心：遇错就切小块逐扇区重试，全失败的扇区用 0 填充。
//
// 这种策略让"500GB 盘有 100 个坏扇区"也能完成扫描，而不是从第一个坏扇区就死。
// 副作用：返回的 buf 里坏扇区位置是 0，上层不知道（除非主动查 BadSectors()）。
// 现实里这种取舍是对的 — 用户更关心"能扫完"而不是"每个 IO 错误都报"。
func (r *ResilientReader) ReadAt(buf []byte, offset int64) (int, error) {
	n, err := r.underlying.ReadAt(buf, offset)
	if err == nil || err == io.EOF || n == len(buf) {
		return n, err
	}
	// 出错：按扇区切分逐块重试
	return r.readWithRetry(buf, offset)
}

func (r *ResilientReader) readWithRetry(buf []byte, offset int64) (int, error) {
	totalSize := int64(len(buf))
	totalRead := int64(0)
	sectorBuf := make([]byte, r.sectorSize)

	for totalRead < totalSize {
		// 当前要读的扇区起点 + 长度
		sectorOff := offset + totalRead
		readLen := r.sectorSize
		if totalRead+readLen > totalSize {
			readLen = totalSize - totalRead
		}

		var success bool
		var lastErr error
		for attempt := 0; attempt < r.maxRetry; attempt++ {
			n, err := r.underlying.ReadAt(sectorBuf[:readLen], sectorOff)
			if err == nil || err == io.EOF {
				copy(buf[totalRead:totalRead+readLen], sectorBuf[:n])
				success = true
				break
			}
			lastErr = err
			// 坏扇区常常需要短暂等待让控制器恢复
			time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
		}
		if !success {
			// 用 0 填充 + 记录
			for i := int64(0); i < readLen; i++ {
				buf[totalRead+i] = 0
			}
			r.recordBad(sectorOff, readLen, errString(lastErr))
		}
		totalRead += readLen
	}
	return int(totalRead), nil
}

func (r *ResilientReader) recordBad(off, size int64, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.badSectors = append(r.badSectors, BadSector{Offset: off, Size: size, Err: msg})
}

// BadSectors 返回到目前为止累计的所有不可恢复扇区列表。
func (r *ResilientReader) BadSectors() []BadSector {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]BadSector, len(r.badSectors))
	copy(out, r.badSectors)
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// 编译期断言
var _ DiskReader = (*ResilientReader)(nil)

// 我们故意不引 errors.Is 检查 specific OS error；任何 non-EOF error 都触发重试，
// 这样跨平台行为一致。如果上层想"区分'真坏'和'临时忙'"未来可加 IsRetryable 接口。
var _ = errors.New // 占位防 import 优化掉
