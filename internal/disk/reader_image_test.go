package disk

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNewReader_RoutesDevicePathToPlatform(t *testing.T) {
	// Windows 风格原盘路径
	r := NewReader(`\\.\PhysicalDrive0`)
	if _, ok := r.(*imageFileReader); ok {
		t.Error(`\\.\PhysicalDrive0 应该路由到平台 reader，不是 image reader`)
	}
	// Unix 风格原盘路径
	r = NewReader(`/dev/disk2`)
	if _, ok := r.(*imageFileReader); ok {
		t.Error(`/dev/disk2 应该路由到平台 reader，不是 image reader`)
	}
}

func TestNewReader_RoutesFilePathToImageReader(t *testing.T) {
	r := NewReader(`/tmp/disk.img`)
	if _, ok := r.(*imageFileReader); !ok {
		t.Errorf(`/tmp/disk.img 应该走 image reader，实际类型: %T`, r)
	}
	// Windows 本地文件（有盘符 + 反斜杠但不是 \\.\ 开头）
	r = NewReader(`C:\backup\disk.img`)
	if _, ok := r.(*imageFileReader); !ok {
		t.Errorf(`C:\backup\disk.img 应该走 image reader，实际类型: %T`, r)
	}
}

func TestImageFileReader_ReadAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.img")
	content := make([]byte, 4096)
	for i := range content {
		content[i] = byte(i & 0xFF)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("写测试镜像失败: %v", err)
	}

	r := NewReader(path)
	if err := r.Open(); err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	defer r.Close()

	size, err := r.Size()
	if err != nil || size != 4096 {
		t.Fatalf("Size 错: got %d err %v", size, err)
	}

	// 从中间偏移读一段，对比内容
	buf := make([]byte, 256)
	n, err := r.ReadAt(buf, 1024)
	if err != nil && n == 0 {
		t.Fatalf("ReadAt 失败: %v", err)
	}
	if n != 256 {
		t.Errorf("ReadAt 读短了: got %d want 256", n)
	}
	if !bytes.Equal(buf, content[1024:1280]) {
		t.Error("ReadAt 内容与预期不符")
	}
}

func TestImageFileReader_RejectsMissingFile(t *testing.T) {
	r := NewReader(filepath.Join(t.TempDir(), "does-not-exist.img"))
	if err := r.Open(); err == nil {
		r.Close()
		t.Error("不存在的镜像文件应返回错误")
	}
}

func TestImageFileReader_RejectsDirectory(t *testing.T) {
	r := NewReader(t.TempDir())
	if err := r.Open(); err == nil {
		r.Close()
		t.Error("目录路径应返回错误")
	}
}

func TestValidateRecoveryTarget_SkipsCheckForImageSource(t *testing.T) {
	// 源是镜像文件时，输出目录即使在同一卷也应该放行
	dir := t.TempDir()
	imagePath := filepath.Join(dir, "source.img")
	if err := os.WriteFile(imagePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("写镜像失败: %v", err)
	}
	if err := ValidateRecoveryTarget(imagePath, dir); err != nil {
		t.Errorf("镜像源不应触发同盘检查，实际: %v", err)
	}
}
