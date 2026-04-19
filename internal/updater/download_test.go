package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
