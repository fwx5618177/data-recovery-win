// Package ocr 提供"已恢复图片 OCR 转文本"接口。
//
// **当前实现**：调用本机 tesseract 二进制（不引 cgo / 不内嵌 Tesseract）。
//   - macOS:  brew install tesseract tesseract-lang
//   - Linux:  apt install tesseract-ocr tesseract-ocr-eng tesseract-ocr-chi-sim
//   - Windows: 装 tesseract installer 后加 PATH
//
// 调用方典型流程：
//
//	// 用户找回了一堆截图，想搜"会议纪要"
//	for _, file := range recoveredImages {
//	    text, _ := ocr.Recognize(file.LocalPath, []string{"chi_sim", "eng"})
//	    if strings.Contains(text, "会议纪要") {
//	        // 高亮 / 移到优先文件夹
//	    }
//	}
//
// 找不到 tesseract 不 fail —— 返回 ErrTesseractNotInstalled，UI 显示一条提示即可。
package ocr

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ErrTesseractNotInstalled tesseract 二进制找不到时返回
var ErrTesseractNotInstalled = fmt.Errorf("tesseract 未安装；OCR 功能不可用")

// IsAvailable 检查本机有没有 tesseract
func IsAvailable() bool {
	_, err := exec.LookPath("tesseract")
	return err == nil
}

// Recognize 把 imagePath 的图片识别成文本。
//
// langs 是 tesseract 语言代码列表（"eng" / "chi_sim" / "jpn" / ...），多个用 "+" 拼。
// 5 秒超时（OCR 不应该太慢，慢了说明图太大或 tesseract 卡了）。
func Recognize(imagePath string, langs []string) (string, error) {
	if !IsAvailable() {
		return "", ErrTesseractNotInstalled
	}
	if imagePath == "" {
		return "", fmt.Errorf("imagePath 为空")
	}
	if len(langs) == 0 {
		langs = []string{"eng"}
	}
	lang := strings.Join(langs, "+")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// tesseract <input> stdout -l <lang> --psm 3
	cmd := exec.CommandContext(ctx, "tesseract", imagePath, "stdout",
		"-l", lang, "--psm", "3")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("tesseract 失败: %w", err)
	}
	return string(out), nil
}

// SearchInImages 给一组图片 + 关键词，返回包含关键词的图片路径列表。
//
// 给"用户想从 5 万张截图里搜出含'会议纪要'文字的那些"用。
// 单线程；若需要并行调用方自己用 goroutine 包。
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
