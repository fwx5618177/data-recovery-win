//go:build !windows

package disk

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// unixReader 非 Windows 平台的磁盘读取器
// 使用标准 os.File，支持设备文件和普通磁盘镜像文件
type unixReader struct {
	path       string
	file       *os.File
	sectorSize int
	mu         sync.Mutex
}

// newPlatformReader 创建 Unix 平台的磁盘读取器
func newPlatformReader(devicePath string) DiskReader {
	return &unixReader{
		path:       devicePath,
		sectorSize: 512,
	}
}

// Open 打开磁盘设备或镜像文件
func (r *unixReader) Open() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file != nil {
		return fmt.Errorf("设备已打开: %s", r.path)
	}

	f, err := os.OpenFile(r.path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("权限不足，无法打开 %s: 请使用 sudo 运行程序", r.path)
		}
		if os.IsNotExist(err) {
			return fmt.Errorf("设备或文件不存在: %s", r.path)
		}
		return fmt.Errorf("打开设备失败 %s: %w", r.path, err)
	}

	r.file = f
	return nil
}

// Close 关闭设备句柄
func (r *unixReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file == nil {
		return nil
	}

	err := r.file.Close()
	r.file = nil
	if err != nil {
		return fmt.Errorf("关闭设备失败 %s: %w", r.path, err)
	}
	return nil
}

// ReadAt 从指定偏移量读取数据到 buf
// Unix 平台无需手动扇区对齐，操作系统会处理
func (r *unixReader) ReadAt(buf []byte, offset int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file == nil {
		return 0, fmt.Errorf("设备未打开，请先调用 Open()")
	}

	if len(buf) == 0 {
		return 0, nil
	}

	if offset < 0 {
		return 0, fmt.Errorf("无效的偏移量: %d", offset)
	}

	n, err := r.file.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("读取偏移 %d 处数据失败: %w", offset, err)
	}
	return n, err
}

// Size 返回磁盘/分区/文件的总大小（字节）
func (r *unixReader) Size() (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.file == nil {
		return 0, fmt.Errorf("设备未打开，请先调用 Open()")
	}

	// 先尝试 Seek 到末尾获取大小（适用于设备文件和普通文件）
	size, err := r.file.Seek(0, io.SeekEnd)
	if err == nil && size > 0 {
		// 将文件指针恢复到开头（不影响 ReadAt，但保持良好状态）
		_, _ = r.file.Seek(0, io.SeekStart)
		return size, nil
	}

	// 如果 Seek 失败，尝试 Stat 获取大小（仅适用于普通文件）
	info, err := r.file.Stat()
	if err != nil {
		return 0, fmt.Errorf("无法获取设备大小 %s: %w", r.path, err)
	}

	size = info.Size()
	if size == 0 {
		return 0, fmt.Errorf("无法确定设备大小 %s: 大小为 0，可能需要 root 权限", r.path)
	}

	return size, nil
}

// SectorSize 返回扇区大小（默认 512 字节）
func (r *unixReader) SectorSize() int {
	return r.sectorSize
}

// DevicePath 返回设备路径
func (r *unixReader) DevicePath() string {
	return r.path
}

// Cancel 关闭 file handle，让阻塞中的 ReadAt syscall 立刻返回 EBADF/closed file。
// 等价于 Close，但语义上表达"中断"而非"释放"—— 配合上层 Stop。
//
// 不持 mu：ReadAt 持锁时若死等，Cancel 拿不到锁就会等 ReadAt 完成 → 防御失效。
func (r *unixReader) Cancel() error {
	f := r.file
	if f == nil {
		return nil
	}
	return f.Close()
}
