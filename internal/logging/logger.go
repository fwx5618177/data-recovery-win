// Package logging 提供全局 slog.Logger，供各子模块输出结构化日志。
//
// 设计目标：
//   - 单一来源：所有子模块通过 logging.L() 拿到同一个 logger
//   - 结构化：日志以 key=value 形式输出，便于在长扫描中按 phase/partition 过滤
//   - 默认行为与 stdlib log 一致（写 stderr）
//   - 支持以 DATA_RECOVERY_LOG_LEVEL 环境变量覆盖级别（debug/info/warn/error）
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	once   sync.Once
	logger *slog.Logger
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
