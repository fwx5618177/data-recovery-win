// Package session 负责把一次扫描的中间结果持久化到磁盘，
// 让用户在程序崩溃 / 重启后可以"继续上次的扫描"而不必重头跑几小时。
//
// 设计（v2.8.50 重构 — 增量 append-log）：
//
//	snapshot.json  — 当前快照基线（progress + 已合并的 files）
//	appendlog.jsonl — 自最近 snapshot 之后追加的新文件，一行一条 JSON
//
// 之前 v2.8.49 及更早：每次 Save 全量覆盖 snapshot.json，N 条文件 → O(N)
// 序列化 + O(N) 写盘。N=10K 时单次 ~3.5MB，每 60s 一次累计 IO 巨大。
//
// 新设计：
//   - `Save(snap)`：仅写 metadata（progress / drivePath / carverOffset），
//     files 留空 — 文件已经在 appendlog 里。这是 O(1) 写。
//   - `AppendFiles([]*RecoveredFile)`：append 一行 JSON 到 log，O(k) k=本批文件数
//     （典型几十）。批粒度由调用方控制，本包不缓冲。
//   - `Compact()`：把 log 合并进 snapshot，清空 log。摊销 O(1)/文件。
//   - `Load()`：snapshot.files + log 全部 replay，对老 v1/v2 格式向后兼容。
//
// 位置统一在 OS 用户配置目录下：
//   - macOS: ~/Library/Application Support/DataRecoveryMaster/
//   - Linux: ~/.config/DataRecoveryMaster/
//   - Win:   %APPDATA%/DataRecoveryMaster/
//
// 崩溃安全：
//   - snapshot.json 用 tmp + rename（原子）
//   - appendlog.jsonl 用 line-delimited JSON：崩溃时最后一行可能截断，
//     Load 时按行 unmarshal 失败的行直接丢（与 mergeAppendLog 一致）。
package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"data-recovery/internal/types"
)

const appDirName = "DataRecoveryMaster"

const (
	snapshotFile  = "session.json"
	appendLogFile = "session.log.jsonl"
)

// Snapshot 存盘结构。字段尽量扁平以便 JSON 往返。
type Snapshot struct {
	Version    int                    `json:"version"`
	SavedAt    time.Time              `json:"savedAt"`
	DrivePath  string                 `json:"drivePath"`
	DriveLabel string                 `json:"driveLabel"`
	Mode       string                 `json:"mode"`
	Progress   types.ScanProgress     `json:"progress"`
	Files      []*types.RecoveredFile `json:"files"`
	OutputDir  string                 `json:"outputDir,omitempty"`
	Completed  bool                   `json:"completed"`

	// CarverResumeOffset 深度扫描断点续扫锚点（字节位移，绝对磁盘地址）。
	// persistLoop 周期写入当前 carver 扫描点；用户在 WelcomePage 点"从断点
	// 继续"时，engine.Scan 从这个 offset 开始而不是 0。
	CarverResumeOffset int64 `json:"carverResumeOffset,omitempty"`
}

const currentVersion = 2

// Store 是带互斥锁的会话仓库，主程序持有一份。
type Store struct {
	mu           sync.Mutex
	dir          string
	snapshotPath string
	logPath      string
}

// NewStore 基于用户配置目录创建 store。
func NewStore() (*Store, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("无法定位用户配置目录: %w", err)
	}
	dir := filepath.Join(base, appDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建会话目录失败 %s: %w", dir, err)
	}
	return &Store{
		dir:          dir,
		snapshotPath: filepath.Join(dir, snapshotFile),
		logPath:      filepath.Join(dir, appendLogFile),
	}, nil
}

// NewStoreInDir 给测试 / 嵌入式场景用：自定义存储目录。
func NewStoreInDir(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建会话目录失败 %s: %w", dir, err)
	}
	return &Store{
		dir:          dir,
		snapshotPath: filepath.Join(dir, snapshotFile),
		logPath:      filepath.Join(dir, appendLogFile),
	}, nil
}

// Path 暴露 snapshot 文件位置，便于日志和调试。
func (s *Store) Path() string {
	return s.snapshotPath
}

// LogPath 暴露 append log 位置（诊断 / 测试用）。
func (s *Store) LogPath() string {
	return s.logPath
}

// Save 原子写入 metadata 快照。
//
// v2.8.50: snap.Files 字段会被**清空后再写**——文件主体已经/将通过
// AppendFiles 追加到 log。这是 O(metadata) 写，跟 N 无关。
//
// 想强制把 log 合并进 snapshot，调 Compact()。完整结束 / 一次性持久化
// 场景（用户主动停止扫描时）可以先 AppendFiles 全部剩余 + Compact()，
// 这样 snapshot 是自洽的。
func (s *Store) Save(snap Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap.Version = currentVersion
	if snap.SavedAt.IsZero() {
		snap.SavedAt = time.Now()
	}
	// 不让 Save 路径再扛 O(N) files 序列化：files 走 log 通道。
	// 调用方传了 files 也不要紧 —— 仍然写，但鼓励改用 AppendFiles + Compact。
	return s.writeSnapshotLocked(snap)
}

// writeSnapshotLocked 必须在持锁下调用。
func (s *Store) writeSnapshotLocked(snap Snapshot) error {
	tmpPath := s.snapshotPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("创建会话临时文件失败: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(snap); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("编码会话失败: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("关闭会话临时文件失败: %w", err)
	}
	if err := os.Rename(tmpPath, s.snapshotPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("保存会话失败: %w", err)
	}
	return nil
}

// AppendFiles 把一批新文件原子追加到 log。每个 file 一行 JSON。
//
// 多次调用是 O(k) k=本批文件数，与历史累积无关。崩溃时最后一行可能截断,
// Load 会按 SkipBadLines 模式跳过这条。
//
// nil / 空 slice 不开文件 (no-op)。
func (s *Store) AppendFiles(files []*types.RecoveredFile) error {
	if len(files) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("打开 append log 失败: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, file := range files {
		if file == nil {
			continue
		}
		b, err := json.Marshal(file)
		if err != nil {
			// 单条编码错不阻断其它条 —— 记日志的事让调用方做
			continue
		}
		if _, err := w.Write(b); err != nil {
			return fmt.Errorf("追加 log 失败: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
			return fmt.Errorf("追加 log 失败: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush append log 失败: %w", err)
	}
	return nil
}

// Compact 把 log 合并进 snapshot，清空 log。摊销 O(1)/文件。
// 调用方应在 N 比较多（如每 5000 文件）或 scan 结束时调用。
func (s *Store) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap, err := s.loadSnapshotLocked()
	if err != nil {
		return err
	}
	if snap == nil {
		// 没快照可压缩 —— 啥也不做
		return nil
	}
	extra, err := s.replayLogLocked()
	if err != nil {
		return err
	}
	if len(extra) == 0 {
		return nil // log 是空 → 已经 compact 过了
	}
	snap.Files = append(snap.Files, extra...)
	if err := s.writeSnapshotLocked(*snap); err != nil {
		return err
	}
	// 写 snapshot 成功后再清 log（保证不会双丢）
	if err := os.Truncate(s.logPath, 0); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("清空 append log 失败: %w", err)
	}
	return nil
}

// Load 读取 snapshot + 合并 log；文件不存在时返回 (nil, nil)。
// 老 session.json（无 log）也照常工作。
func (s *Store) Load() (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap, err := s.loadSnapshotLocked()
	if err != nil {
		return nil, err
	}
	if snap == nil {
		return nil, nil // 不存在
	}
	extra, err := s.replayLogLocked()
	if err != nil {
		// log 坏了不阻断 snapshot 加载 —— snapshot 仍然有效
		return snap, nil
	}
	if len(extra) > 0 {
		snap.Files = append(snap.Files, extra...)
	}
	return snap, nil
}

// loadSnapshotLocked 必须在持锁下调用。
func (s *Store) loadSnapshotLocked() (*Snapshot, error) {
	data, err := os.ReadFile(s.snapshotPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取会话失败: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		// 旧版本或损坏，直接忽略（前端会当作没有会话）
		return nil, nil
	}
	// v1 → v2 无破坏性字段；接受 v1 作为 v2 读
	if snap.Version != currentVersion && snap.Version != 1 {
		return nil, nil
	}
	return &snap, nil
}

// replayLogLocked 按行 JSON 读 append log。
// 单行 unmarshal 失败丢这行（崩溃时最后一行半截），其余行保留。
func (s *Store) replayLogLocked() ([]*types.RecoveredFile, error) {
	f, err := os.Open(s.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("打开 append log 失败: %w", err)
	}
	defer f.Close()

	var out []*types.RecoveredFile
	// 用 bufio.Scanner 但增大 buffer (默认 64KB)，单文件 JSON 可能 ~1KB,
	// 64KB 行已够。预防超大字段：MaxScanTokenSize 1MB。
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var file types.RecoveredFile
		if err := json.Unmarshal(line, &file); err != nil {
			// 崩溃时最后一行可能截断 → 跳过
			continue
		}
		out = append(out, &file)
	}
	// scanner.Err() 不视为致命 —— Load 已经拿到了能拿到的
	if err := scanner.Err(); err != nil && err != io.EOF {
		// 截断的行算 scanner.Err 为 nil；这里 err 多半是 IO 错
		return out, err
	}
	return out, nil
}

// Clear 删除 snapshot + log；文件不存在不算错误。
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var lastErr error
	for _, p := range []string{s.snapshotPath, s.logPath} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			lastErr = fmt.Errorf("清除会话失败 %s: %w", p, err)
		}
	}
	return lastErr
}
