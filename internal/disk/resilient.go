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
//
// 策略（v2.8.9 重构，对齐 GNU ddrescue 三段式的"fast pass"）：
//
//   - **正常模式**：大块读失败时按 sectorSize 切分逐扇区读，每扇区 maxRetry 次。
//     失败的扇区 0 填充 + 记录到 BadSectors。
//
//   - **快速跳过模式**：连续 K 个扇区都失败 → 进入跳过模式 → 一次 0 填充 N 字节
//     不再尝试读 → 在跳过区末尾做一次 probe → probe 成功则退出跳过模式。
//
//     这是 ddrescue 的核心优化：坏扇区往往**聚簇**而不是散布。一旦确认进入坏区，
//     盲目逐扇区重试是死亡螺旋（4MB 全坏 = 8192 个 16s 重试 = 36 小时）。
//     聚簇跳过后 4MB 全坏区只花 ~1 分钟。
//
//   - **可选 retry 阶段**：将来 v2.9+ 加 separate retry pass，让用户在主扫描完成后
//     针对 BadSectors 重试（更长超时 + 更多 retries），对应 ddrescue scrape pass。
//
// 默认参数（v2.8.9 调整）：
//   - maxRetry: 2 → 1（每扇区只尝试 1 次。inline retry 极少救回真坏扇区，多数在 next pass 才能恢复）
//   - consecutiveFailureThreshold: 4 个连续坏扇区进入跳过模式
//   - 跳过模式 chunk 大小**自适应倍增**：从 sectorSize 开始，每次 probe 失败 ×2，封顶
//     maxSkipChunkBytes（默认 1MB）。连续坏区从快速跳过到大块跳过，能 1MB/8s = 4MB 在 32 秒内扫完。
//     单个孤立坏扇区进入 skip mode 也只损失 1 个扇区，倍增退出后仍是 sector 粒度。
type ResilientReader struct {
	underlying                  DiskReader
	sectorSize                  int64
	maxRetry                    int
	consecutiveFailureThreshold int
	maxSkipChunkBytes           int64
	mu                          sync.Mutex
	badSectors                  []BadSector
}

// BadSector 单个被跳过的坏扇区记录，供"坏扇区清单"UI / 取证报告展示。
//
// v2.8.34 加 JSON tag —— 之前裸字段被前端读 sector.offset / sector.size 全
// undefined，扫描后"坏扇区清单"对话框全空。
type BadSector struct {
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	Err    string `json:"err"`
}

// NewResilientReader 默认值：sectorSize=512，maxRetry=1（v2.8.9 从 2 降到 1，避免坏扇区死亡螺旋）。
// 调用方传 0 用默认。
//
// 内部默认：consecutiveFailureThreshold=4 个连续坏扇区触发跳过模式；skipAheadBytes=64KB 一跳。
func NewResilientReader(underlying DiskReader, sectorSize int64, maxRetry int) *ResilientReader {
	if sectorSize <= 0 {
		sectorSize = 512
	}
	if maxRetry <= 0 {
		maxRetry = 1
	}
	return &ResilientReader{
		underlying:                  underlying,
		sectorSize:                  sectorSize,
		maxRetry:                    maxRetry,
		consecutiveFailureThreshold: 4,
		maxSkipChunkBytes:           1024 * 1024, // 1MB cap
	}
}

func (r *ResilientReader) Open() error          { return r.underlying.Open() }
func (r *ResilientReader) Close() error         { return r.underlying.Close() }
func (r *ResilientReader) Size() (int64, error) { return r.underlying.Size() }
func (r *ResilientReader) SectorSize() int      { return int(r.sectorSize) }
func (r *ResilientReader) DevicePath() string   { return r.underlying.DevicePath() }

// Cancel 透传给底层（保留 Canceller 能力让 StopScan 能强制中断 underlying syscall）
func (r *ResilientReader) Cancel() error {
	if c, ok := r.underlying.(Canceller); ok {
		return c.Cancel()
	}
	return nil
}

// ReadAt 是核心：遇错就切小块逐扇区重试，全失败的扇区用 0 填充。
//
// 这种策略让"500GB 盘有 100 个坏扇区"也能完成扫描，而不是从第一个坏扇区就死。
// 副作用：返回的 buf 里坏扇区位置是 0，上层不知道（除非主动查 BadSectors()）。
// 现实里这种取舍是对的 — 用户更关心"能扫完"而不是"每个 IO 错误都报"。
//
// v2.8.23 例外：ErrReaderCancelled 必须**穿透**，不能当坏扇区 0-fill。
// 因为这条错误的语义是"reader 已停，不再服务"——继续重试不仅无意义，更会把
// 上层不带 ctx 的紧密读循环（Collector / format detector / validateAll）困死，
// 它们看 err==nil 就觉得读到了数据继续往下走，Cancel 信号完全失效。
func (r *ResilientReader) ReadAt(buf []byte, offset int64) (int, error) {
	n, err := r.underlying.ReadAt(buf, offset)
	if err == nil || err == io.EOF || n == len(buf) {
		return n, err
	}
	// v2.8.23: reader 已取消 → 直接透传，禁止当坏扇区 0-fill
	if IsCancelled(err) {
		return 0, err
	}
	// 出错：按扇区切分逐块重试
	return r.readWithRetry(buf, offset)
}

func (r *ResilientReader) readWithRetry(buf []byte, offset int64) (int, error) {
	totalSize := int64(len(buf))
	totalRead := int64(0)
	sectorBuf := make([]byte, r.sectorSize)

	consecutiveFailures := 0
	inSkipMode := false
	skipChunk := r.sectorSize // 自适应跳过 chunk，从 1 个 sector 开始倍增
	var probeBuf []byte

	for totalRead < totalSize {
		// ----- 跳过模式：自适应倍增 probe -----
		// 每次 probe 失败 chunk × 2（封顶 maxSkipChunkBytes），让大坏区快速扫过。
		// 一旦 probe 成功立刻退出 skip 模式 + chunk 重置 sectorSize，回归 sector 粒度。
		// 这是 ddrescue 的 fast pass 思想 —— 接受边界 1MB 数据丢失，换 4MB 全坏区从
		// 36 小时降到 ~30 秒（4MB / 1MB × 8s probe = 32s）。
		if inSkipMode {
			chunk := skipChunk
			if chunk > r.maxSkipChunkBytes {
				chunk = r.maxSkipChunkBytes
			}
			if totalRead+chunk > totalSize {
				chunk = totalSize - totalRead
			}
			if int64(len(probeBuf)) < chunk {
				probeBuf = make([]byte, r.maxSkipChunkBytes)
			}
			n, err := r.underlying.ReadAt(probeBuf[:chunk], offset+totalRead)
			if err == nil || err == io.EOF {
				// 健康 chunk —— 退出 skip mode + 重置 chunk 尺寸
				copy(buf[totalRead:totalRead+int64(n)], probeBuf[:n])
				totalRead += int64(n)
				consecutiveFailures = 0
				inSkipMode = false
				skipChunk = r.sectorSize
				if err == io.EOF {
					return int(totalRead), nil
				}
			} else if IsCancelled(err) {
				// v2.8.23: cancel 必须穿透；继续轮 chunk 会让循环跑完才返回
				return int(totalRead), err
			} else {
				// 整 chunk 坏 —— 0 填充 + 记录 + 倍增下一轮 chunk
				for i := int64(0); i < chunk; i++ {
					buf[totalRead+i] = 0
				}
				r.recordBad(offset+totalRead, chunk, errString(err))
				totalRead += chunk
				skipChunk *= 2
				if skipChunk > r.maxSkipChunkBytes {
					skipChunk = r.maxSkipChunkBytes
				}
			}
			continue
		}

		// ----- 正常模式：逐扇区读取 -----
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
			// v2.8.23: cancel 必须穿透；不浪费 sleep + retry 在已死的 reader 上
			if IsCancelled(err) {
				return int(totalRead), err
			}
			// 坏扇区常常需要短暂等待让控制器恢复
			if attempt+1 < r.maxRetry {
				time.Sleep(time.Duration(attempt+1) * 50 * time.Millisecond)
			}
		}
		if success {
			consecutiveFailures = 0
		} else {
			// 用 0 填充 + 记录
			for i := int64(0); i < readLen; i++ {
				buf[totalRead+i] = 0
			}
			r.recordBad(sectorOff, readLen, errString(lastErr))
			consecutiveFailures++
			if consecutiveFailures >= r.consecutiveFailureThreshold {
				inSkipMode = true
			}
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
