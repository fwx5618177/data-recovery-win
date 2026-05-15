// Package session 负责把一次扫描的中间结果持久化到磁盘，
// 让用户在程序崩溃 / 重启后可以"继续上次的扫描"而不必重头跑几小时。
//
// 设计：每次 Save 全量覆盖单个 JSON 文件，位置统一在 OS 用户配置目录下：
//   - macOS: ~/Library/Application Support/DataRecoveryMaster/session.json
//   - Linux: ~/.config/DataRecoveryMaster/session.json
//   - Win:   %APPDATA%/DataRecoveryMaster/session.json
//
// Save 在扫描过程中被周期性调用（App 层每 N 秒或每 M 个文件一次）。
// 为避免长时间占用锁，先写到同目录下的 .tmp，再原子 rename。
package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"data-recovery/internal/types"
)

const appDirName = "DataRecoveryMaster"

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
	// persistLoop 每 5s 写入当前 carver 扫描点；用户在 WelcomePage 点"从断点
	// 继续"时，engine.Scan 从这个 offset 开始而不是 0。NTFS MFT / 各文件系统
	// 阶段耗时相对短（秒到分钟级），整段重跑可接受，主要值是省 carver 时间
	// （几 TB 盘要几小时）。
	CarverResumeOffset int64 `json:"carverResumeOffset,omitempty"`
}

const currentVersion = 2

// Store 是带互斥锁的会话仓库，主程序持有一份。
type Store struct {
	mu   sync.Mutex
	path string
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
	return &Store{path: filepath.Join(dir, "session.json")}, nil
}

// Path 暴露会话文件位置，便于日志和调试。
func (s *Store) Path() string {
	return s.path
}

// Save 原子写入快照。文件很大（几十万行）时 JSON 序列化耗时，
// 我们把它放到后台调用时序里（不阻塞扫描管线）。
func (s *Store) Save(snap Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap.Version = currentVersion
	if snap.SavedAt.IsZero() {
		snap.SavedAt = time.Now()
	}

	tmpPath := s.path + ".tmp"
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

	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("保存会话失败: %w", err)
	}
	return nil
}

// Load 读取快照；文件不存在时返回 (nil, nil)。
func (s *Store) Load() (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
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
	// v1 → v2 无破坏性字段（新增 CarverResumeOffset 默认 0）；接受 v1 作为 v2 读
	if snap.Version != currentVersion && snap.Version != 1 {
		return nil, nil
	}
	return &snap, nil
}

// Clear 删除会话文件；文件不存在不算错误。
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("清除会话失败: %w", err)
	}
	return nil
}
