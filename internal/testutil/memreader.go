// Package testutil 提供测试期的通用工具，主要是一个内存型 DiskReader，
// 允许各 internal 包在不依赖真实磁盘的情况下对扫描/解析逻辑做单元测试。
package testutil

import (
	"bytes"
	"io"
	"sync"
)

// MemReader 实现 disk.DiskReader 接口，用字节切片模拟磁盘。
type MemReader struct {
	data       []byte
	sectorSize int
	mu         sync.Mutex
}

// NewMemReader 以给定字节内容构造一个内存 Reader。
func NewMemReader(data []byte) *MemReader {
	return &MemReader{data: data, sectorSize: 512}
}

func (m *MemReader) Open() error  { return nil }
func (m *MemReader) Close() error { return nil }

func (m *MemReader) ReadAt(buf []byte, offset int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if offset < 0 || offset >= int64(len(m.data)) {
		return 0, io.EOF
	}
	r := bytes.NewReader(m.data)
	return r.ReadAt(buf, offset)
}

func (m *MemReader) Size() (int64, error) { return int64(len(m.data)), nil }
func (m *MemReader) SectorSize() int      { return m.sectorSize }
func (m *MemReader) DevicePath() string   { return "mem://test" }
