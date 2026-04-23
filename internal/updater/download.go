package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// StallTimeout 定义下载停滞多久视为网络死掉。
// 30s 在国内慢速连接下仍留有容错（GitHub CDN 经常有短暂停顿），
// 但用户等 30s 没进度也能明确知道要重试 —— 不会无限卡死。
const StallTimeout = 30 * time.Second

// stallCheckInterval 是 watchdog 轮询间隔（不是 stall 判定阈值）。
var stallCheckInterval = 5 * time.Second

// DownloadProgress 是 DownloadAsset 在下载过程中回调的进度。
// JSON tag 与前端字段对齐（camelCase），否则 Wails 会输出 PascalCase 导致前端读空。
type DownloadProgress struct {
	BytesTotal int64   `json:"bytesTotal"`
	BytesDone  int64   `json:"bytesDone"`
	Speed      int64   `json:"speed"`  // bytes/sec
	ETASec     float64 `json:"etaSec"` // 剩余秒数估算
}

// DownloadAsset 把 asset 下载到 destPath，边下边算 SHA-256。
//
// 流程：
//  1. 建立 HTTPS 连接到 asset.DownloadURL（GitHub CDN）
//  2. 流式写入 destPath.tmp，同时 hasher.Sum
//  3. 完成后 rename 到 destPath（原子落盘）
//  4. 返回 sha256 hex 供上层校验 / 记录
//
// 取消策略：ctx 取消时立即关闭 reader 并清理 .tmp 文件；下载几 GB 也可随时中断。
//
// SHA-256 供应链校验：
//   - 发版 CI 在 Release assets 里附带一份 "SHA256SUMS.txt"（每行 "<hex>  <filename>"）
//   - DownloadAsset 计算下载文件的 sha256 并返回给上层
//   - 上层 (updater.ApplyPendingUpdate) 在应用更新前可调 VerifyAssetChecksum 核对
//
// 走 HTTPS（TLS 证书链已校验）+ sha256 双校验 = 比 GitHub 仅靠 TLS 更严。
func DownloadAsset(
	ctx context.Context,
	asset Asset,
	destPath string,
	progress func(DownloadProgress),
) (string, error) {
	if asset.DownloadURL == "" {
		return "", fmt.Errorf("asset.DownloadURL 为空")
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return "", fmt.Errorf("创建目标目录失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.DownloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "data-recovery/"+Version)
	req.Header.Set("Accept", "application/octet-stream")

	// 下载可能几百 MB-GB，不设总超时；由 ctx + stall detector 控制（见下方 watchdog）
	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求下载失败: %w", err)
	}
	defer resp.Body.Close()

	// Stall watchdog：如果超过 StallTimeout 没收到任何字节，强制关闭 Body 让 Read 返回
	// 错误 —— 否则 GitHub CDN 偶尔连接活着但不发数据的情况会让本 goroutine 永远 hang。
	// 这是"下载好像失败了"的主要根因。
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	var stalled atomic.Bool
	stallDone := make(chan struct{})
	defer close(stallDone)
	go func() {
		ticker := time.NewTicker(stallCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stallDone:
				return
			case <-ticker.C:
				last := time.Unix(0, lastActivity.Load())
				if time.Since(last) > StallTimeout {
					stalled.Store(true)
					// Close body → 主循环 Read 立刻返回 "use of closed network connection"
					_ = resp.Body.Close()
					return
				}
			}
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载状态码 %d", resp.StatusCode)
	}

	total := resp.ContentLength
	if total <= 0 && asset.Size > 0 {
		total = asset.Size
	}

	tmpPath := destPath + ".tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	// 带进度的流式拷贝
	var done int64
	buf := make([]byte, 128*1024) // 128KB 块
	start := time.Now()
	lastReport := start
	lastDone := int64(0)

	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := writer.Write(buf[:n]); werr != nil {
				return "", fmt.Errorf("写入临时文件失败: %w", werr)
			}
			done += int64(n)
			lastActivity.Store(time.Now().UnixNano())
			// 节流进度回调：每秒最多一次
			if progress != nil && time.Since(lastReport) > time.Second {
				dt := time.Since(lastReport).Seconds()
				speed := int64(float64(done-lastDone) / dt)
				var eta float64
				if speed > 0 && total > 0 && total > done {
					eta = float64(total-done) / float64(speed)
				}
				progress(DownloadProgress{
					BytesTotal: total,
					BytesDone:  done,
					Speed:      speed,
					ETASec:     eta,
				})
				lastReport = time.Now()
				lastDone = done
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			// 优先识别 stall 触发的关闭 —— 让用户看到清晰的"停滞超时"而不是 net.ErrClosed
			if stalled.Load() {
				return "", fmt.Errorf("下载停滞超过 %v（网络中断或服务器限速），已中止 —— 请检查网络后重试", StallTimeout)
			}
			return "", fmt.Errorf("读取响应失败: %w", rerr)
		}
	}

	if err := tmpFile.Sync(); err != nil {
		return "", fmt.Errorf("fsync 失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("关闭临时文件失败: %w", err)
	}

	if total > 0 && done != total {
		return "", fmt.Errorf("下载字节数不匹配: got %d, want %d", done, total)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return "", fmt.Errorf("重命名失败: %w", err)
	}
	cleanup = false

	sum := hex.EncodeToString(hasher.Sum(nil))

	// 最后一次进度：100%，填上平均速度让 UI 最后一帧不显示 "0.0 MB/s"
	if progress != nil {
		totalSec := time.Since(start).Seconds()
		var avgSpeed int64
		if totalSec > 0 {
			avgSpeed = int64(float64(done) / totalSec)
		}
		progress(DownloadProgress{
			BytesTotal: total,
			BytesDone:  done,
			Speed:      avgSpeed,
			ETASec:     0,
		})
	}

	return sum, nil
}
