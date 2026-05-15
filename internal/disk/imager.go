package disk

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// ImageProgress 是镜像过程的实时状态，供 UI 更新进度条。
//
// v2.8.34 加 JSON tag —— 之前裸字段，作为 "imaging:progress" 事件 payload 时
// 前端读 p.bytesTotal / p.speed 全 undefined，整盘 dump 进度条不动。
type ImageProgress struct {
	BytesTotal    int64   `json:"bytesTotal"`    // 源盘总字节数
	BytesRead     int64   `json:"bytesRead"`     // 已尝试读取的字节数（含坏道跳过部分）
	BytesOK       int64   `json:"bytesOK"`       // 读取成功的字节数
	BytesBad      int64   `json:"bytesBad"`      // 坏道/读取失败被填零的字节数
	ElapsedSec    float64 `json:"elapsedSec"`
	Speed         int64   `json:"speed"`         // bytes/sec（基于最近区间）
	ETASec        float64 `json:"etaSec"`
	CurrentOffset int64   `json:"currentOffset"`
}

// ImageOptions 镜像选项。默认值就已经是行业合理做法。
type ImageOptions struct {
	// ChunkSize 顺利读取时的块大小。默认 4MB，够用且对顺序读友好
	ChunkSize int64
	// FallbackChunkSize 踩到读错时退到的"小块"大小。默认 4KB——
	// 以小块重试能减少"整个大块 4MB 被放弃"的数据损失；行业惯例值
	FallbackChunkSize int64
	// MaxBadBytesPercent 允许的坏道比例上限（0-1），超过直接放弃整个镜像。
	// 默认 0.10 = 10%；坏到这程度的盘通常需要 ddrescue 或专业数据恢复服务
	MaxBadBytesPercent float64
	// ProgressInterval 两次进度回调最小间隔；默认 1 秒
	ProgressInterval time.Duration
}

// DefaultImageOptions 行业合理默认。
func DefaultImageOptions() ImageOptions {
	return ImageOptions{
		ChunkSize:          4 * 1024 * 1024,
		FallbackChunkSize:  4 * 1024,
		MaxBadBytesPercent: 0.10,
		ProgressInterval:   time.Second,
	}
}

// DumpDiskToImage 把 src 里的所有字节顺序复制到 dstPath 产生一个镜像文件。
//
// 这是业界 image-first 工作流的关键一步：
//   - 源盘只被读一次、只读不写，随后就可以放回保险箱不再动
//   - 后续任意扫描工具（本项目 / PhotoRec / DMDE 等）都跑在镜像上
//   - 重试不同参数 / 不同工具不用再折磨源盘，尤其对老 HDD 非常关键
//
// 踩到读错（坏道）时：按 FallbackChunkSize 小块重试；再失败则用零填充，
// 继续往下走。这是保守的 ddrescue 思路（不做复杂的二次/三次扫描），够大多数个人场景用。
// 更凶残的坏盘建议直接上 ddrescue / HDDSuperClone。
func DumpDiskToImage(
	ctx context.Context,
	src DiskReader,
	dstPath string,
	opts ImageOptions,
	progress func(ImageProgress),
) (int64, error) {
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = 4 * 1024 * 1024
	}
	if opts.FallbackChunkSize <= 0 {
		opts.FallbackChunkSize = 4 * 1024
	}
	if opts.FallbackChunkSize > opts.ChunkSize {
		opts.FallbackChunkSize = opts.ChunkSize
	}
	if opts.MaxBadBytesPercent <= 0 {
		opts.MaxBadBytesPercent = 0.10
	}
	if opts.ProgressInterval <= 0 {
		opts.ProgressInterval = time.Second
	}

	total, err := src.Size()
	if err != nil {
		return 0, fmt.Errorf("读取源盘大小失败: %w", err)
	}
	if total <= 0 {
		return 0, fmt.Errorf("源盘大小无效: %d", total)
	}

	// O_EXCL 防止不小心覆盖已有文件——镜像一旦覆盖就没了
	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return 0, fmt.Errorf("创建镜像文件失败 [%s]: %w", dstPath, err)
	}
	defer dst.Close()

	// 预分配：Unix sparse、Windows 会真分配。失败不致命，继续就是
	_ = dst.Truncate(total)

	var (
		bytesRead atomic.Int64
		bytesOK   atomic.Int64
		bytesBad  atomic.Int64
	)

	startTime := time.Now()
	lastReport := startTime
	lastReportBytes := int64(0)
	badLimit := int64(float64(total) * opts.MaxBadBytesPercent)

	emitProgress := func(offset int64, force bool) {
		if progress == nil {
			return
		}
		now := time.Now()
		if !force && now.Sub(lastReport) < opts.ProgressInterval {
			return
		}
		elapsed := now.Sub(startTime).Seconds()
		read := bytesRead.Load()
		ok := bytesOK.Load()
		bad := bytesBad.Load()

		var speed int64
		if delta := now.Sub(lastReport).Seconds(); delta > 0 {
			speed = int64(float64(read-lastReportBytes) / delta)
		}
		var eta float64
		if speed > 0 && total > read {
			eta = float64(total-read) / float64(speed)
		}
		progress(ImageProgress{
			BytesTotal:    total,
			BytesRead:     read,
			BytesOK:       ok,
			BytesBad:      bad,
			ElapsedSec:    elapsed,
			Speed:         speed,
			ETASec:        eta,
			CurrentOffset: offset,
		})
		lastReport = now
		lastReportBytes = read
	}

	// 零填充缓冲：坏道退回零的情况直接复用
	zero := make([]byte, opts.FallbackChunkSize)
	buf := make([]byte, opts.ChunkSize)

	offset := int64(0)
	for offset < total {
		if err := ctx.Err(); err != nil {
			emitProgress(offset, true)
			return offset, err
		}

		chunkSize := opts.ChunkSize
		if offset+chunkSize > total {
			chunkSize = total - offset
		}

		n, rerr := src.ReadAt(buf[:chunkSize], offset)
		if rerr == nil && int64(n) == chunkSize {
			// 顺利路径
			if _, werr := dst.WriteAt(buf[:n], offset); werr != nil {
				return offset, fmt.Errorf("写入镜像失败 (offset=%d): %w", offset, werr)
			}
			bytesOK.Add(int64(n))
			bytesRead.Add(int64(n))
			offset += int64(n)
			emitProgress(offset, false)
			continue
		}

		// 大块读失败——退到小块精细重试，单块坏就填零继续
		subTotal := chunkSize
		subOffset := int64(0)
		for subOffset < subTotal {
			if err := ctx.Err(); err != nil {
				emitProgress(offset+subOffset, true)
				return offset + subOffset, err
			}
			subSize := opts.FallbackChunkSize
			if subOffset+subSize > subTotal {
				subSize = subTotal - subOffset
			}
			sn, serr := src.ReadAt(buf[subOffset:subOffset+subSize], offset+subOffset)
			if serr == nil && int64(sn) == subSize {
				if _, werr := dst.WriteAt(buf[subOffset:subOffset+subSize], offset+subOffset); werr != nil {
					return offset + subOffset, fmt.Errorf("写入镜像失败 (offset=%d): %w", offset+subOffset, werr)
				}
				bytesOK.Add(subSize)
			} else {
				// 小块也读不出：认定为坏道，用零填充
				if _, werr := dst.WriteAt(zero[:subSize], offset+subOffset); werr != nil {
					return offset + subOffset, fmt.Errorf("写入零填充失败 (offset=%d): %w", offset+subOffset, werr)
				}
				bytesBad.Add(subSize)
				// 早退出判断：坏道过多说明盘状态已崩，继续只是浪费时间
				if bytesBad.Load() > badLimit {
					emitProgress(offset+subOffset, true)
					return offset + subOffset, fmt.Errorf(
						"坏道累计 %s 超过上限 %s（%.0f%%），建议改用 ddrescue 处理物理损坏盘",
						formatBytes(bytesBad.Load()), formatBytes(badLimit), opts.MaxBadBytesPercent*100,
					)
				}
			}
			bytesRead.Add(subSize)
			subOffset += subSize
			emitProgress(offset+subOffset, false)
		}
		offset += subTotal
	}

	emitProgress(offset, true)
	if err := dst.Sync(); err != nil {
		return offset, fmt.Errorf("fsync 镜像失败: %w", err)
	}
	return offset, nil
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for i := n / unit; i >= unit; i /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
