package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDownloadAsset_RoundTripAndSHA256(t *testing.T) {
	payload := make([]byte, 200*1024) // 200KB
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}
	wantSHA := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(wantSHA[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "204800")
		w.Write(payload)
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "update.exe")
	asset := Asset{Name: "update.exe", DownloadURL: server.URL + "/update", Size: int64(len(payload))}

	gotSHA, err := DownloadAsset(context.Background(), asset, dest, nil)
	if err != nil {
		t.Fatalf("DownloadAsset: %v", err)
	}
	if gotSHA != wantHex {
		t.Errorf("SHA-256 不匹配:\n  got  %s\n  want %s", gotSHA, wantHex)
	}

	// 验证文件内容 byte-for-byte
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("读下载文件失败: %v", err)
	}
	if len(got) != len(payload) {
		t.Errorf("长度错: got %d want %d", len(got), len(payload))
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("byte %d mismatch: got 0x%02X want 0x%02X", i, got[i], payload[i])
		}
	}
}

func TestDownloadAsset_ProgressCallbackFires(t *testing.T) {
	payload := make([]byte, 5*1024*1024) // 5MB 足够触发至少一次进度回调
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "big.bin")
	asset := Asset{Name: "big.bin", DownloadURL: server.URL, Size: int64(len(payload))}

	calls := 0
	var lastProgress DownloadProgress
	_, err := DownloadAsset(context.Background(), asset, dest, func(p DownloadProgress) {
		calls++
		lastProgress = p
	})
	if err != nil {
		t.Fatalf("DownloadAsset: %v", err)
	}
	if calls == 0 {
		t.Error("至少应有一次进度回调")
	}
	if lastProgress.BytesDone == 0 {
		t.Error("BytesDone 应非零")
	}
}

func TestDownloadAsset_CtxCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟慢下载：每次写一点就 flush
		buf := make([]byte, 1024)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 1000; i++ {
			w.Write(buf)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "cancel.bin")
	asset := Asset{Name: "cancel.bin", DownloadURL: server.URL, Size: 1024 * 1000}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	_, err := DownloadAsset(ctx, asset, dest, nil)
	if err == nil {
		t.Error("取消的 ctx 应返回错误")
	}
	// 临时文件必须已清理
	if _, err := os.Stat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp 文件应已被清理，实际 stat err=%v", err)
	}
}

func TestPending_SaveLoadClear(t *testing.T) {
	// 重定向 pending 目录到 TempDir，避免污染真实用户配置
	orig := os.Getenv("XDG_CONFIG_HOME")
	tmp := t.TempDir()
	os.Setenv("XDG_CONFIG_HOME", tmp)
	defer os.Setenv("XDG_CONFIG_HOME", orig)

	// 准备一个假"新 exe"
	binPath := filepath.Join(tmp, "fake-new-exe")
	if err := os.WriteFile(binPath, []byte("fake binary content"), 0o644); err != nil {
		t.Fatalf("写假 exe 失败: %v", err)
	}
	info, _ := os.Stat(binPath)

	p := Pending{
		Version:    "v9.9.9",
		BinaryPath: binPath,
		SHA256:     "deadbeef",
		SizeBytes:  info.Size(),
		StagedAt:   "2026-04-19T00:00:00Z",
	}
	if err := SavePending(p); err != nil {
		t.Fatalf("SavePending: %v", err)
	}

	loaded, err := LoadPending()
	if err != nil {
		t.Fatalf("LoadPending: %v", err)
	}
	if loaded == nil {
		t.Fatal("应能读回 pending")
	}
	if loaded.Version != "v9.9.9" {
		t.Errorf("Version 错: %q", loaded.Version)
	}
	if loaded.SizeBytes != info.Size() {
		t.Errorf("SizeBytes 错: got %d want %d", loaded.SizeBytes, info.Size())
	}

	// 模拟"文件大小对不上" → Load 应返回 nil（视为脏状态）
	if err := os.WriteFile(binPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale, _ := LoadPending()
	if stale != nil {
		t.Error("文件大小不匹配时 LoadPending 应返回 nil（视为无 pending）")
	}

	// ClearPending
	if err := ClearPending(); err != nil {
		t.Fatalf("ClearPending: %v", err)
	}
	after, _ := LoadPending()
	if after != nil {
		t.Error("ClearPending 后应无 pending")
	}
}

// 回归测试：下载停滞时必须 bounded-time 返回错误，不能无限 hang。
//
// Bug 历史：DownloadAsset 的注释声称"由 ctx + stall detector 控制"，但
// 代码里根本没有 stall detector。http.Client.Timeout=0，外层 ctx 来自
// a.ctx（应用生命周期），没有任何机制检测"连接活着但服务器停发"这种
// 情况。GitHub CDN 在国内偶尔出现 TCP 活着不发数据的情形，主循环的
// resp.Body.Read 阻塞，progress 事件停止，用户 UI 冻结在"42%"，最终
// 以为"下载失败了"关闭应用 —— 但实际上 goroutine 还在泄漏。
//
// 这个测试起一个 HTTP handler：发完 headers + 一小段 body 后故意 hang
// 不关连接。有 stall detector 时 DownloadAsset 应在 ~StallTimeout 之后
// 返回错误；没有 stall detector 时会永远阻塞（测试通过 5s 上限捕获）。
func TestDownloadAsset_StallWatchdogTriggers(t *testing.T) {
	// 为了测试快跑，压缩 StallTimeout 到 500ms（生产是 30s）
	saveStallInterval := stallCheckInterval
	stallCheckInterval = 100 * time.Millisecond
	t.Cleanup(func() { stallCheckInterval = saveStallInterval })

	// 临时把 StallTimeout 压到 500ms，测试完恢复
	// （StallTimeout 是 const，不能直接改 —— 此测试验证当前 const 下
	// watchdog 能触发即可；stall 起作用的机制是"超过阈值就 close Body"）
	// 实际上我们验证的是：当 server 不发数据时，DownloadAsset 能在
	// StallTimeout + 裕量内返回错误，而不是永远阻塞。

	// 让 server 发 100 字节后故意 hang（不关连接）
	blockCh := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576") // 声明 1MB，实际只发 100
		w.(http.Flusher).Flush()
		w.Write(make([]byte, 100))
		w.(http.Flusher).Flush()
		// Hang 到测试结束
		<-blockCh
	}))
	defer func() {
		close(blockCh)
		server.Close()
	}()

	dest := filepath.Join(t.TempDir(), "stalled.bin")
	asset := Asset{Name: "stalled.bin", DownloadURL: server.URL, Size: 1048576}

	// 用一个比 StallTimeout 长的 test timeout 兜底（防 watchdog 没工作导致死锁）
	ctx, cancel := context.WithTimeout(context.Background(), StallTimeout+10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := DownloadAsset(ctx, asset, dest, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("stalled server 应让 DownloadAsset 返回错误，但 err == nil —— stall watchdog 没生效")
	}
	// 必须是"停滞"错误而不是 ctx.DeadlineExceeded，证明是 watchdog 触发而非 test ctx 兜底
	if ctx.Err() != nil {
		t.Fatalf("test ctx 先过期了（%v）而不是 watchdog 触发 —— stall watchdog 不起作用", ctx.Err())
	}
	if !strings.Contains(err.Error(), "停滞") {
		t.Errorf("错误应该提示下载停滞，实际: %v", err)
	}
	// 返回时间应接近 StallTimeout（watchdog interval 有 1 个周期的误差 + Go scheduling）
	if elapsed > StallTimeout+3*time.Second {
		t.Errorf("DownloadAsset 返回耗时 %v，超过 StallTimeout (%v) + 3s 裕量 —— watchdog 检测偏慢", elapsed, StallTimeout)
	}
	if elapsed < StallTimeout-1*time.Second {
		t.Errorf("DownloadAsset 返回耗时 %v，远小于 StallTimeout (%v) —— 可能是其他错误路径提前返回", elapsed, StallTimeout)
	}
}

// 回归测试：正常下载流程下 stall watchdog 不应误触发。
// 确保添加 watchdog 不会影响慢但持续有进度的连接。
func TestDownloadAsset_SlowButProgressingNotFalseTriggered(t *testing.T) {
	// 每 100ms 发一小段数据，共 10 段。总时长约 1s。
	// 比 StallTimeout 短，watchdog 不应触发。
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.(http.Flusher).Flush()
		for i := 0; i < 10; i++ {
			w.Write(make([]byte, 100))
			w.(http.Flusher).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "slow.bin")
	asset := Asset{Name: "slow.bin", DownloadURL: server.URL, Size: 1000}

	sum, err := DownloadAsset(context.Background(), asset, dest, nil)
	if err != nil {
		t.Fatalf("slow-but-progressing 不应触发 stall 错误: %v", err)
	}
	if sum == "" {
		t.Error("正常完成应返回 SHA256")
	}
}
