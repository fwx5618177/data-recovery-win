// Package ocr 提供"已恢复图片 OCR 转文本"接口。
//
// **v2.8.4 重构**：app 内嵌 tessdata_fast 的 eng + chi_sim（约 19 MB），
// 用户无需手动 `apt install tesseract-ocr-chi-sim` / `brew install tesseract-lang`。
// 其它语言用户在 OCR Modal 里点 + 按需从 tessdata_fast 官方仓库下载。
//
// tesseract 二进制本身仍依赖系统装 —— 找不到时 UI 给清晰指引（Windows / macOS / Linux 各不同）。
// v2.9 计划把 tesseract 二进制也内嵌进来做到 100% zero-install。
package ocr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrTesseractNotInstalled tesseract 二进制找不到时返回
var ErrTesseractNotInstalled = errors.New("tesseract 未安装；OCR 引擎不可用")

// IsAvailable 检查本机有没有 tesseract（PATH + 常见安装路径）
func IsAvailable() bool {
	_, err := FindTesseractBin()
	return err == nil
}

// Recognize 把 imagePath 的图片识别成文本。
//
// langs 是 tesseract 语言代码列表（"eng" / "chi_sim" / "jpn" / ...）。
// 5 秒超时 → 改 30 秒（OCR 大图可能慢）。
//
// 用 app 自管的 cache/tessdata（含内嵌 eng + chi_sim + 用户下载的额外语言），
// **不依赖**系统 tessdata 目录，跨发行版行为一致。
func Recognize(imagePath string, langs []string) (string, error) {
	bin, err := FindTesseractBin()
	if err != nil {
		return "", ErrTesseractNotInstalled
	}
	if imagePath == "" {
		return "", fmt.Errorf("imagePath 为空")
	}
	if _, err := os.Stat(imagePath); err != nil {
		return "", fmt.Errorf("图片不存在: %w", err)
	}
	if len(langs) == 0 {
		langs = []string{"eng"}
	}
	if err := EnsureBuiltinLangs(); err != nil {
		return "", err
	}
	tessdir, err := TessdataDir()
	if err != nil {
		return "", err
	}
	lang := strings.Join(langs, "+")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, imagePath, "stdout",
		"-l", lang,
		"--tessdata-dir", tessdir,
		"--psm", "3",
	)
	// 也设 env var 兜底（某些 tesseract 版本忽视 --tessdata-dir）
	cmd.Env = append(os.Environ(), "TESSDATA_PREFIX="+tessdir)
	out, err := cmd.Output()
	if err != nil {
		// 把 stderr 的"找不到语言包"错误转成对用户更有用的话
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr := string(ee.Stderr)
			if strings.Contains(stderr, "Failed loading language") || strings.Contains(stderr, "could not be loaded") {
				return "", fmt.Errorf("tesseract 找不到语言包 %q —— 请在 OCR 设置里下载该语言后再试。原始错误：%s", lang, strings.TrimSpace(stderr))
			}
			return "", fmt.Errorf("tesseract 失败: %w（stderr: %s）", err, strings.TrimSpace(stderr))
		}
		return "", fmt.Errorf("tesseract 失败: %w", err)
	}
	return string(out), nil
}

// SearchInImages 给一组图片 + 关键词，返回包含关键词的图片路径列表。
// 单线程实现；上层（app.go）想要并发 / 进度推送自己包 goroutine + Wails event。
func SearchInImages(imagePaths []string, keyword string, langs []string) []string {
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	if keyword == "" {
		return nil
	}
	var hits []string
	for _, p := range imagePaths {
		text, err := Recognize(p, langs)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(text), keyword) {
			hits = append(hits, p)
		}
	}
	return hits
}

// SearchProgress 是 SearchInDirectory 的进度回调载荷
type SearchProgress struct {
	Current     int    `json:"current"`     // 已处理图片数（1-based）
	Total       int    `json:"total"`       // 总图片数
	CurrentFile string `json:"currentFile"` // 当前在 OCR 哪张
	HitCount    int    `json:"hitCount"`    // 累计命中数
}

// SearchInDirectory 是给前端 OCR Modal 用的"扫一个目录 / 关键词搜图"入口。
// 自己枚举 dir 下所有支持的图片格式，逐张 Recognize + match keyword，
// 通过 onProgress / onHit 回调推流式进度让 UI 更新。
//
// 不并发：tesseract 进程本身吃 CPU 多线程，再开多 goroutine 启动一堆 fork 反而抖动。
//
// ctx 取消时立刻返回（不等当前张 OCR 完成 —— 上层 cancel 一般是用户关 modal）。
func SearchInDirectory(
	ctx context.Context,
	dir, keyword string,
	langs []string,
	onProgress func(SearchProgress),
	onHit func(path string),
) ([]string, error) {
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	if keyword == "" {
		return nil, fmt.Errorf("关键词为空")
	}
	if dir == "" {
		return nil, fmt.Errorf("目录为空")
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("目录不存在: %w", err)
	}
	images, err := walkImages(dir)
	if err != nil {
		return nil, fmt.Errorf("枚举图片: %w", err)
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("目录下没找到任何图片（支持 .png/.jpg/.jpeg/.bmp/.tiff/.webp）")
	}

	var hits []string
	for i, p := range images {
		select {
		case <-ctx.Done():
			return hits, ctx.Err()
		default:
		}
		if onProgress != nil {
			onProgress(SearchProgress{
				Current:     i + 1,
				Total:       len(images),
				CurrentFile: p,
				HitCount:    len(hits),
			})
		}
		text, err := Recognize(p, langs)
		if err != nil {
			continue // 跳过损坏 / 不支持的图片
		}
		if strings.Contains(strings.ToLower(text), keyword) {
			hits = append(hits, p)
			if onHit != nil {
				onHit(p)
			}
		}
	}
	if onProgress != nil {
		onProgress(SearchProgress{
			Current:     len(images),
			Total:       len(images),
			CurrentFile: "",
			HitCount:    len(hits),
		})
	}
	return hits, nil
}

// walkImages 列出 dir 下（递归）所有图片扩展名匹配的文件
func walkImages(dir string) ([]string, error) {
	var imgs []string
	exts := map[string]bool{
		".png": true, ".jpg": true, ".jpeg": true,
		".bmp": true, ".tif": true, ".tiff": true,
		".webp": true,
	}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			// 单个文件读不了不致命，继续
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if exts[ext] {
			imgs = append(imgs, p)
		}
		return nil
	})
	return imgs, err
}
