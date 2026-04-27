package validator

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"testing"

	"data-recovery/internal/types"
)

// 模拟 disk reader：返回固定 buf 在指定 offset 之后的内容
type bufReader struct {
	buf []byte
}

func (b *bufReader) Open() error { return nil }
func (b *bufReader) ReadAt(p []byte, off int64) (int, error) {
	if int(off) >= len(b.buf) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[off:])
	return n, nil
}
func (b *bufReader) Size() (int64, error) { return int64(len(b.buf)), nil }
func (b *bufReader) Close() error         { return nil }
func (b *bufReader) SectorSize() int      { return 512 }
func (b *bufReader) DevicePath() string   { return "buf" }

// 端到端：损坏的 JPEG 在磁盘上 → RepairJPEGFromOffset → 拿到可解 JPEG + coverage 报告
func TestRepairJPEGFromOffset_RecoversCorrupted(t *testing.T) {
	// 构造 64×64 JPEG，损坏中段
	src := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			src.Set(x, y, color.RGBA{R: byte(x * 4), G: byte(y * 4), B: 64, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, src, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	// 损坏：在 SOS 之后插入非法 marker
	sosPos := findSOS(data)
	if sosPos < 0 {
		t.Fatal("test fixture 没 SOS")
	}
	if sosPos+150 < len(data) {
		data[sosPos+150] = 0xFF
		data[sosPos+151] = 0x88
	}
	// 验证 stdlib 真的解不出来
	if _, err := jpeg.Decode(bytes.NewReader(data)); err == nil {
		t.Skip("test fixture 修改后 stdlib 仍能解，跳过")
	}

	// 模拟把损坏 JPEG 放到磁盘 offset=4096 处
	disk := make([]byte, 8192)
	copy(disk[4096:], data)
	r := &bufReader{buf: disk}

	v := NewValidator(r)
	file := &types.RecoveredFile{
		FileName:  "broken.jpg",
		Extension: "jpg",
		Offset:    4096,
		Size:      int64(len(data)),
	}
	out := v.RepairJPEGFromOffset(file)
	if !out.Repaired {
		t.Fatalf("RepairJPEGFromOffset 未恢复: %s", out.HumanReadable)
	}
	// 修复后字节应能被 stdlib 解
	if _, err := jpeg.Decode(bytes.NewReader(out.RepairedBytes)); err != nil {
		t.Errorf("修复后 stdlib 仍解不开: %v", err)
	}
	if out.Coverage <= 0 || out.Coverage > 1 {
		t.Errorf("Coverage 越界: %f", out.Coverage)
	}
	if out.Strategy == "" {
		t.Error("Strategy 应被填充")
	}
	t.Logf("修复成功: strategy=%s coverage=%.2f msg=%s",
		out.Strategy, out.Coverage, out.HumanReadable)
}

// nil file 不应 panic
func TestRepairJPEGFromOffset_NilFile(t *testing.T) {
	r := &bufReader{}
	v := NewValidator(r)
	out := v.RepairJPEGFromOffset(nil)
	if out.Repaired {
		t.Error("nil file 不应被认为可修复")
	}
}

// 文件过大 → 跳过（防 OOM）
func TestRepairJPEGFromOffset_TooLarge(t *testing.T) {
	r := &bufReader{}
	v := NewValidator(r)
	out := v.RepairJPEGFromOffset(&types.RecoveredFile{
		FileName:  "huge.jpg",
		Extension: "jpg",
		Offset:    0,
		Size:      200 * 1024 * 1024, // > 100MB 上限
	})
	if out.Repaired {
		t.Error("超大文件应被跳过")
	}
}

// 健康文件：应识别成 "original" 策略
func TestClassifyRepair_OriginalEqual(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 32, 32))
	var buf bytes.Buffer
	jpeg.Encode(&buf, src, &jpeg.Options{Quality: 90})
	data := buf.Bytes()
	strategy, coverage, _ := classifyRepair(data, data)
	if strategy != "original" {
		t.Errorf("equal bytes 应是 original, got %s", strategy)
	}
	if coverage != 1.0 {
		t.Errorf("original coverage = %f want 1.0", coverage)
	}
}
