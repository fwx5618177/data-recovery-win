// Package logging 提供全局 slog.Logger，供各子模块输出结构化日志。
//
// 设计目标：
//   - 单一来源：所有子模块通过 logging.L() 拿到同一个 logger
//   - 结构化：日志以 key=value 形式输出，便于在长扫描中按 phase/partition 过滤
//   - 默认行为与 stdlib log 一致（写 stderr）
//   - 支持以 DATA_RECOVERY_LOG_LEVEL 环境变量覆盖级别（debug/info/warn/error）
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	once    sync.Once
	logger  *slog.Logger
	logDir  string     // 本次进程日志落盘目录（EnableFileLogging 设置后非空）
	logFile *os.File   // 当前打开的日志文件
	logMu   sync.Mutex // 保护 logDir/logFile 的并发设置
)

// L 返回全局 logger，首次调用时根据环境变量初始化。
func L() *slog.Logger {
	once.Do(func() {
		logger = newLogger(os.Stderr)
	})
	return logger
}

// SetDefault 允许主程序注入自定义 logger（比如写入文件）。
// 通常在 main 启动时调用一次。
func SetDefault(l *slog.Logger) {
	logger = l
}

func newLogger(w io.Writer) *slog.Logger {
	level := parseLevel(os.Getenv("DATA_RECOVERY_LOG_LEVEL"))
	opts := &slog.HandlerOptions{Level: level}
	return slog.New(slog.NewTextHandler(w, opts))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// EnableFileLogging 把 logger 改为"同时写 stderr + 文件"。
// dir 是日志目录，按日期滚动：<dir>/data-recovery-YYYY-MM-DD.log。
// 调用失败（目录不可写）时保留 stderr-only logger，不 panic。
func EnableFileLogging(dir string) error {
	if dir == "" {
		return fmt.Errorf("log dir 为空")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建日志目录失败: %w", err)
	}
	name := fmt.Sprintf("data-recovery-%s.log", time.Now().Format("2006-01-02"))
	fp := filepath.Join(dir, name)
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}

	logMu.Lock()
	if logFile != nil {
		_ = logFile.Close()
	}
	logFile = f
	logDir = dir
	logMu.Unlock()

	mw := io.MultiWriter(os.Stderr, f)
	SetDefault(newLogger(mw))
	return nil
}

// LogDir 返回当前日志目录（EnableFileLogging 成功调用过才非空）。
// 诊断包导出会用到。
func LogDir() string {
	logMu.Lock()
	defer logMu.Unlock()
	return logDir
}

// Close 关闭文件 handle，主程序退出时调用。
func Close() {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
}
