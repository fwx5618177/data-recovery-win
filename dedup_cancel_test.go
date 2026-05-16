package main

import (
	"context"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestFindDuplicateImages_CancelStopsScan 锁住 v2.8.39 的 dedup cancel 契约：
//
// 用户关闭"正在扫描重复图片"toast 时调 CancelFindDuplicateImages，
// FindDuplicateImages 必须立刻退出，不再继续遍历目录 / 算 hash。
//
// 之前 FindDuplicateImages 是纯同步无 ctx —— 关 toast 只是前端 UI 消失，
// 后台 filepath.Walk + perceptual hash 仍然在跑（截图证明：用户关 toast 后
// 任务栏继续显示扫描通知，磁盘活动持续）。
func TestFindDuplicateImages_CancelStopsScan(t *testing.T) {
	// 造一个含足够多大点 PNG 的临时目录 —— 必须让 Walk + hash 跑久到能在
	// 取消信号到达前还没结束。32x32 PNG × 3000 张实测 macOS Air M2 上 ~600ms，
	// 足够给我们 50ms 后 cancel 抓住。
	dir := t.TempDir()
	const numImages = 3000
	for i := 0; i < numImages; i++ {
		path := filepath.Join(dir, "test_"+itoa(i)+".png")
		writeTinyPNG(t, path)
	}

	app := &App{ctx: context.Background()}

	// 在 goroutine 里启 FindDuplicateImages
	var (
		mu       sync.Mutex
		finished bool
		retErr   error
	)
	go func() {
		_, err := app.FindDuplicateImages(dir, 5)
		mu.Lock()
		finished = true
		retErr = err
		mu.Unlock()
	}()

	// 等到 backend 真正注册了 dedupCancel 才发取消（防 "cancel 比注册早" 的 race）。
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		app.dedupMu.Lock()
		registered := app.dedupCancel != nil
		app.dedupMu.Unlock()
		if registered {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	// 取消
	cancelStart := time.Now()
	app.CancelFindDuplicateImages()

	// 等最多 2s 让 FindDuplicateImages 真正退出
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := finished
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancelElapsed := time.Since(cancelStart)

	mu.Lock()
	gotFinished := finished
	gotErr := retErr
	mu.Unlock()

	if !gotFinished {
		t.Fatalf("CancelFindDuplicateImages 后 FindDuplicateImages 没在 2s 内退出 —— "+
			"取消机制失效，后台还在吃 IO（耗时 %v）", cancelElapsed)
	}
	if gotErr == nil {
		t.Errorf("期望 FindDuplicateImages 返回取消错误，得到 nil")
	}
	if cancelElapsed > 500*time.Millisecond {
		t.Logf("⚠ Cancel 响应耗时 %v（>500ms），可考虑在更内层 hash 循环加 ctx 检查", cancelElapsed)
	}
}

// TestCancelFindDuplicateImages_Idempotent 没在跑时调 cancel 也不能 panic。
func TestCancelFindDuplicateImages_Idempotent(t *testing.T) {
	app := &App{ctx: context.Background()}
	// 直接调，没启过任务
	app.CancelFindDuplicateImages()
	app.CancelFindDuplicateImages()
	// 通过 = 没 panic
}

// itoa 小工具，避免依赖 strconv
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// writeTinyPNG 写一个 8x8 单色 PNG 给 dedup 测试用 —— 数据量小，但解码 +
// perceptual hash 仍然要走完整路径，能模拟真实负载。
func writeTinyPNG(t *testing.T, path string) {
	t.Helper()
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, color.RGBA{uint8((x * 8) & 0xFF), uint8((y * 8) & 0xFF), 128, 255})
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
}
