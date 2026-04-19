package disk

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// flakyReader 模拟一块"部分坏道"的源盘：正常路径返回内容，
// 落在 badRanges 里的任何读都直接报错。
type flakyReader struct {
	data      []byte
	badRanges []badRange
}

type badRange struct{ start, end int64 } // [start, end)

func (r *flakyReader) Open() error  { return nil }
func (r *flakyReader) Close() error { return nil }

func (r *flakyReader) ReadAt(buf []byte, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(r.data)) {
		return 0, io.EOF
	}
	end := offset + int64(len(buf))
	// 任一区间与请求区间有重叠就报错
	for _, b := range r.badRanges {
		if offset < b.end && end > b.start {
			return 0, os.ErrInvalid // 模拟坏道
		}
	}
	n := copy(buf, r.data[offset:])
	return n, nil
}

func (r *flakyReader) Size() (int64, error) { return int64(len(r.data)), nil }
func (r *flakyReader) SectorSize() int      { return 512 }
func (r *flakyReader) DevicePath() string   { return "mem://flaky" }

func TestDumpDiskToImage_HappyPath(t *testing.T) {
	src := make([]byte, 4*1024*1024+1000) // 4MB + 余数
	for i := range src {
		src[i] = byte(i & 0xFF)
	}

	reader := &flakyReader{data: src}
	dst := filepath.Join(t.TempDir(), "out.img")

	opts := DefaultImageOptions()
	opts.ChunkSize = 64 * 1024 // 小一点加快测试
	opts.FallbackChunkSize = 4 * 1024

	n, err := DumpDiskToImage(context.Background(), reader, dst, opts, nil)
	if err != nil {
		t.Fatalf("DumpDiskToImage 失败: %v", err)
	}
	if n != int64(len(src)) {
		t.Errorf("写入字节数错: got %d want %d", n, len(src))
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("读镜像失败: %v", err)
	}
	if !bytes.Equal(got, src) {
		t.Error("镜像内容与源不一致")
	}
}

func TestDumpDiskToImage_SkipsBadSectorsAsZeros(t *testing.T) {
	const total = int64(256 * 1024) // 256KB
	src := bytes.Repeat([]byte{0xAB}, int(total))

	// 构造一段坏道：偏移 100KB 开始的 8KB
	bad := badRange{start: 100 * 1024, end: 108 * 1024}

	reader := &flakyReader{data: src, badRanges: []badRange{bad}}
	dst := filepath.Join(t.TempDir(), "out.img")

	opts := DefaultImageOptions()
	opts.ChunkSize = 64 * 1024
	opts.FallbackChunkSize = 4 * 1024
	opts.MaxBadBytesPercent = 0.5 // 宽松

	n, err := DumpDiskToImage(context.Background(), reader, dst, opts, nil)
	if err != nil {
		t.Fatalf("DumpDiskToImage 应容忍坏道完成，实际: %v", err)
	}
	if n != total {
		t.Errorf("写入字节数错: got %d want %d", n, total)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("读镜像失败: %v", err)
	}

	// 坏道区域应是全零
	for i := bad.start; i < bad.end; i++ {
		if got[i] != 0 {
			t.Fatalf("坏道区内偏移 %d 应为 0x00，实际 0x%02X", i, got[i])
			break
		}
	}
	// 坏道之外应保持 0xAB
	for i := int64(0); i < bad.start; i++ {
		if got[i] != 0xAB {
			t.Fatalf("坏道前偏移 %d 应保留 0xAB，实际 0x%02X", i, got[i])
			break
		}
	}
	for i := bad.end; i < total; i++ {
		if got[i] != 0xAB {
			t.Fatalf("坏道后偏移 %d 应保留 0xAB，实际 0x%02X", i, got[i])
			break
		}
	}
}

func TestDumpDiskToImage_AbortsWhenBadExceedsThreshold(t *testing.T) {
	const total = int64(256 * 1024)
	src := bytes.Repeat([]byte{0xCD}, int(total))

	// 半个盘都是坏道
	bad := badRange{start: 0, end: 200 * 1024}

	reader := &flakyReader{data: src, badRanges: []badRange{bad}}
	dst := filepath.Join(t.TempDir(), "out.img")

	opts := DefaultImageOptions()
	opts.ChunkSize = 64 * 1024
	opts.FallbackChunkSize = 4 * 1024
	opts.MaxBadBytesPercent = 0.1 // 10% 上限，必定触发

	_, err := DumpDiskToImage(context.Background(), reader, dst, opts, nil)
	if err == nil {
		t.Fatal("坏道超限时应返回错误")
	}
}

func TestDumpDiskToImage_RejectsExistingDest(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "already.img")
	if err := os.WriteFile(dst, []byte("x"), 0o644); err != nil {
		t.Fatalf("预写目标失败: %v", err)
	}

	reader := &flakyReader{data: []byte("abc")}
	_, err := DumpDiskToImage(context.Background(), reader, dst, DefaultImageOptions(), nil)
	if err == nil {
		t.Error("目标已存在时应拒绝覆盖")
	}
}

func TestDumpDiskToImage_ContextCancel(t *testing.T) {
	src := bytes.Repeat([]byte{0x42}, 1*1024*1024)
	reader := &flakyReader{data: src}
	dst := filepath.Join(t.TempDir(), "cancel.img")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	_, err := DumpDiskToImage(ctx, reader, dst, DefaultImageOptions(), nil)
	if err == nil {
		t.Error("已取消的 context 应返回错误")
	}
}
