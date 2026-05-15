package updater

// 外部审计 trail —— 更新事件可追溯日志。
//
// 目的（审计要求）：
//   出事后（用户报 "自动更新后我打不开应用了"）能追溯：
//     - 何时 check
//     - 下载哪个 version
//     - SHA 对比结果
//     - apply 是否成功 / 为什么失败 / 有没有 rollback
//
// 日志位置（固定在用户配置目录，与 pending manifest 同目录）：
//   macOS:  ~/Library/Application Support/DataRecoveryMaster/update_audit.log
//   Linux:  ~/.config/DataRecoveryMaster/update_audit.log
//   Win:    %APPDATA%/DataRecoveryMaster/update_audit.log
//
// 格式：每行一个 event，JSON Lines（便于 grep + 机器解析）
//   {"time":"2026-04-23T15:04:05Z","event":"apply-start","old":"/Applications/..","new":"..."}
//
// 保留策略：文件 > 1MB 时截断前半；避免无限增长（真实用户机器盘位紧）。

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const auditMaxSize int64 = 1 << 20 // 1 MB

// auditLog 追加一条审计事件到 update_audit.log
func auditLog(event string, kvPairs ...string) {
	path, err := auditLogPath()
	if err != nil {
		return // 无 config dir → 静默 skip
	}

	// 日志超限 → 保留后半（丢弃前半）
	_ = rotateIfLarge(path)

	entry := map[string]string{
		"time":  time.Now().UTC().Format(time.RFC3339),
		"event": event,
	}
	for i := 0; i+1 < len(kvPairs); i += 2 {
		entry[kvPairs[i]] = kvPairs[i+1]
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
	_, _ = f.Write([]byte("\n"))
}

// AuditLogPath 导出给外部（app.go / 诊断工具）让用户能导出 log
func AuditLogPath() (string, error) {
	return auditLogPath()
}

func auditLogPath() (string, error) {
	// 复用 pending.go 的 configDir 约定（已被真实用户用起来，不改）
	base, err := configDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "data-recovery")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "update_audit.log"), nil
}

// rotateIfLarge 当日志 > auditMaxSize 时，保留尾部 1/2，丢弃前半
func rotateIfLarge(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return nil // 不存在 OK
	}
	if info.Size() < auditMaxSize {
		return nil
	}
	// 读后半
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(info.Size()/2, io.SeekStart); err != nil {
		return err
	}
	// 丢弃到下一个 \n，避免截断一行 JSON
	buf := make([]byte, 1024)
	n, _ := f.Read(buf)
	startIdx := 0
	for startIdx < n && buf[startIdx] != '\n' {
		startIdx++
	}
	if startIdx < n {
		startIdx++
	}
	// 拼：buf[startIdx:n] + 后续
	rest, _ := io.ReadAll(f)
	tail := append(buf[startIdx:n], rest...)
	// 覆写
	nf, err := os.Create(path)
	if err != nil {
		return err
	}
	defer nf.Close()
	_, _ = nf.Write([]byte(fmt.Sprintf("# rotated at %s\n", time.Now().UTC().Format(time.RFC3339))))
	_, _ = nf.Write(tail)
	return nil
}
