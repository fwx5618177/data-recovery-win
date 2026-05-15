// Package diag 把"用户遇到问题时能帮开发定位"的一切打包成 zip：
//
//   - 最近 N 天的日志
//   - 应用版本、OS、arch
//   - pending update 状态
//   - 最近会话快照（文件名 / 大小 / 状态，不含文件内容）
//   - 最近一次恢复的失败清单
//
// 不包含任何磁盘扇区 / 文件内容 / 恢复密钥 —— 只含"能帮排障的元数据"。
// 用户可以把生成的 zip 直接贴到 GitHub issue。
package diag

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// ResolveDefaultExportDir 返回最佳默认导出目录。
//
// 顺序：
//  1. Windows: SHGetKnownFolderPath FOLDERID_Desktop（处理 OneDrive / D: 重定向 / 中文桌面）
//  2. macOS / Linux: ~/Desktop
//  3. 上述都拿不到：os.UserHomeDir()（家目录）
//
// 失败时返回空字符串让 caller 自行决定（比如弹"另存为"对话框）。
//
// v2.8.16 加 —— 之前固定写 ~/Desktop 在中文 Windows 上常常导出到 C:\Users\xxx\Desktop
// 但用户真实桌面在 D:\桌面 / OneDrive\Desktop，文件凭空消失。
func ResolveDefaultExportDir() string {
	// 1. Windows 走 Shell API
	if d := resolveRealDesktopPath(); d != "" {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	// 2. fallback: ~/Desktop
	if home, err := os.UserHomeDir(); err == nil {
		desk := filepath.Join(home, "Desktop")
		if fi, err := os.Stat(desk); err == nil && fi.IsDir() {
			return desk
		}
		// 3. 桌面不存在 → 用 home
		return home
	}
	return ""
}

// Metadata 是写到 zip 里 metadata.json 的内容。
type Metadata struct {
	ExportedAt  time.Time `json:"exportedAt"`
	AppVersion  string    `json:"appVersion"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	NumCPU      int       `json:"numCPU"`
	GoVersion   string    `json:"goVersion"`
	LogFiles    []string  `json:"logFiles"`
	SessionFile string    `json:"sessionFile,omitempty"`
	PendingFile string    `json:"pendingFile,omitempty"`
	ExtraNotes  string    `json:"extraNotes,omitempty"`
}

// Options 控制导出什么。
type Options struct {
	// DestPath zip 写到哪里（绝对路径）
	DestPath string
	// AppVersion 当前应用版本
	AppVersion string
	// LogDir 日志目录；会打包里面所有 .log 文件
	LogDir string
	// SessionFile 最近会话 snapshot 文件绝对路径；为空跳过
	SessionFile string
	// PendingFile update.pending/manifest.json 绝对路径；为空跳过
	PendingFile string
	// ExtraNotes 用户输入的自由文字（"我点扫描后界面卡住了"这类）
	ExtraNotes string
}

// Export 执行打包，返回实际写出的 zip 路径。
//
// 若 DestPath 指向目录，自动在目录下生成 data-recovery-diag-<ts>.zip；
// 否则把 DestPath 当作完整文件路径使用。
func Export(opts Options) (string, error) {
	if opts.DestPath == "" {
		return "", fmt.Errorf("DestPath 为空")
	}

	dest := opts.DestPath
	if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
		name := fmt.Sprintf("data-recovery-diag-%s.zip", time.Now().Format("20060102-150405"))
		dest = filepath.Join(dest, name)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("创建导出目录失败: %w", err)
	}

	f, err := os.Create(dest)
	if err != nil {
		return "", fmt.Errorf("创建 zip 文件失败: %w", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	md := Metadata{
		ExportedAt: time.Now(),
		AppVersion: opts.AppVersion,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		GoVersion:  runtime.Version(),
		ExtraNotes: opts.ExtraNotes,
	}

	// 1. 日志文件
	if opts.LogDir != "" {
		entries, _ := os.ReadDir(opts.LogDir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// 只打包 .log / .txt，避免把可能敏感的其他东西也带出去
			if ext := filepath.Ext(name); ext != ".log" && ext != ".txt" {
				continue
			}
			src := filepath.Join(opts.LogDir, name)
			if err := addFileToZip(zw, src, "logs/"+name); err == nil {
				md.LogFiles = append(md.LogFiles, name)
			}
		}
	}

	// 2. 会话 snapshot
	if opts.SessionFile != "" {
		if err := addFileToZip(zw, opts.SessionFile, "session/snapshot.json"); err == nil {
			md.SessionFile = filepath.Base(opts.SessionFile)
		}
	}

	// 3. pending 更新信息
	if opts.PendingFile != "" {
		if err := addFileToZip(zw, opts.PendingFile, "update/pending.json"); err == nil {
			md.PendingFile = filepath.Base(opts.PendingFile)
		}
	}

	// 4. metadata.json（放最后，这样前面哪些文件成功进包都记下来了）
	mdBytes, _ := json.MarshalIndent(md, "", "  ")
	w, err := zw.Create("metadata.json")
	if err != nil {
		return "", err
	}
	if _, err := w.Write(mdBytes); err != nil {
		return "", err
	}

	return dest, nil
}

func addFileToZip(zw *zip.Writer, srcPath, inZipPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return err
	}
	hdr, err := zip.FileInfoHeader(fi)
	if err != nil {
		return err
	}
	hdr.Name = inZipPath
	hdr.Method = zip.Deflate
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}
