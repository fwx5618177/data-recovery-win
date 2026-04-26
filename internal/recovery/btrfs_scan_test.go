package recovery

import (
	"testing"

	"data-recovery/internal/btrfs"
)

// btrfsFileToRecoveredFile 单测：dir 不返回 RecoveredFile；普通文件转 source="btrfs"
// + 正确字段。
func TestBtrfsFileToRecoveredFile_FiltersDirsAndFillsFields(t *testing.T) {
	// 目录应被过滤
	dir := &btrfs.FSTreeFile{InoID: 256, IsDir: true, Name: "subdir"}
	if got := btrfsFileToRecoveredFile(dir, "test", 0); got != nil {
		t.Errorf("目录不应转成 RecoveredFile, got %+v", got)
	}

	// 普通文件
	f := &btrfs.FSTreeFile{
		InoID:       257,
		Name:        "photo.jpg",
		Size:        12345,
		Compression: 1, // zlib
		ModTime:     1700000000,
	}
	rf := btrfsFileToRecoveredFile(f, "mybtrfs", 0)
	if rf == nil {
		t.Fatal("普通文件应被转出")
	}
	if rf.Source != "btrfs" {
		t.Errorf("Source = %q, want btrfs", rf.Source)
	}
	if rf.FileName != "photo.jpg" {
		t.Errorf("FileName = %q", rf.FileName)
	}
	if rf.Extension != "jpg" {
		t.Errorf("Extension = %q", rf.Extension)
	}
	if rf.Size != 12345 {
		t.Errorf("Size = %d", rf.Size)
	}
	if rf.ModifiedTime == nil || rf.ModifiedTime.Year() != 2023 {
		t.Errorf("ModifiedTime 错: %v", rf.ModifiedTime)
	}
	// 确认 description 含 compression 提示
	if rf.Description == "" {
		t.Errorf("Description 应包含 compression 提示")
	}
}

// 没文件名（罕见 — INODE 没 INODE_REF）应回退到 INODE_<id> 命名
func TestBtrfsFileToRecoveredFile_FallsBackToInodeIDName(t *testing.T) {
	f := &btrfs.FSTreeFile{InoID: 999, Size: 100}
	rf := btrfsFileToRecoveredFile(f, "test", 0)
	if rf == nil {
		t.Fatal("应仍然转出 RecoveredFile")
	}
	if rf.FileName != "INODE_999" {
		t.Errorf("FileName 应回退到 INODE_999, got %q", rf.FileName)
	}
}
