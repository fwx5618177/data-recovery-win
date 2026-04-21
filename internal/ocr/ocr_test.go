package ocr

import (
	"errors"
	"testing"
)

func TestRecognize_NoTesseract(t *testing.T) {
	if IsAvailable() {
		t.Skip("本机装了 tesseract，跳过 not-installed 测试")
	}
	_, err := Recognize("/tmp/nonexistent.png", []string{"eng"})
	if !errors.Is(err, ErrTesseractNotInstalled) {
		t.Errorf("应返回 ErrTesseractNotInstalled, 实际 %v", err)
	}
}

func TestSearchInImages_EmptyKeyword(t *testing.T) {
	hits := SearchInImages([]string{"x.png"}, "", nil)
	if hits != nil {
		t.Error("空 keyword 应返回 nil")
	}
}
