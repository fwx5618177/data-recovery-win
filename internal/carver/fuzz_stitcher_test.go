package carver

import (
	"bytes"
	"testing"

	"data-recovery/internal/disk"
)

// memReader: 给 fuzz 用的内存 disk.DiskReader，不开 file handle
type memReader struct {
	data []byte
}

func (m *memReader) Open() error             { return nil }
func (m *memReader) Close() error            { return nil }
func (m *memReader) Size() (int64, error)    { return int64(len(m.data)), nil }
func (m *memReader) SectorSize() int         { return 512 }
func (m *memReader) DevicePath() string      { return "memory" }
func (m *memReader) ReadAt(buf []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.data)) {
		return 0, nil
	}
	n := copy(buf, m.data[off:])
	return n, nil
}

var _ disk.DiskReader = (*memReader)(nil)

// FuzzPNGStitcher 给 PNG stitcher 喂任意字节，不能 panic
func FuzzPNGStitcher(f *testing.F) {
	// PNG signature 开头 + 随机尾
	sig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	f.Add(sig)
	f.Add(append(sig, make([]byte, 64)...))
	f.Add([]byte{}) // 空

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PNGStitcher panic on len=%d: %v", len(data), r)
			}
		}()
		r := &memReader{data: data}
		s := NewPNGStitcher(r)
		s.MaxOutputBytes = 1 << 20  // 1MB 上限防 decompression bomb
		s.MaxSearchWindow = 64 * 1024
		_, _ = s.Stitch(0)
	})
}

// FuzzMP4Stitcher 给 MP4 stitcher 喂任意字节，不能 panic
func FuzzMP4Stitcher(f *testing.F) {
	// ftyp box header
	f.Add([]byte{0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x41}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("MP4Stitcher panic on len=%d: %v", len(data), r)
			}
		}()
		r := &memReader{data: data}
		s := NewMP4Stitcher(r)
		s.MaxOutputBytes = 1 << 20
		s.MaxSearchWindow = 64 * 1024
		_, _ = s.Stitch(0)
	})
}

// FuzzZIPStitcher 给 ZIP stitcher 喂任意字节 + 不同 zipMaxSize
func FuzzZIPStitcher(f *testing.F) {
	// EOCD sig 在末尾
	eocd := []byte{0x50, 0x4B, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // 22 字节 minimal EOCD
	f.Add(eocd)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ZIPStitcher panic on len=%d: %v", len(data), r)
			}
		}()
		r := &memReader{data: data}
		s := NewZIPStitcher(r, 0, int64(len(data)))
		s.MaxOutputBytes = 1 << 20
		_, _ = s.Stitch()
	})
}

// FuzzJPEGHealthScore 启发式 JPEG 健康评分不能 panic
func FuzzJPEGHealthScore(f *testing.F) {
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xD9})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 128))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("JPEGHealthScore panic on len=%d: %v", len(data), r)
			}
		}()
		_ = JPEGHealthScore(data)
	})
}
