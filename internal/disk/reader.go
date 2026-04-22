package disk

import (
	"fmt"
	"io"
	"time"
)

// DiskReader 定义磁盘原始数据读取接口
type DiskReader interface {
	// Open 打开磁盘设备，必须在读取前调用
	Open() error
	// Close 关闭设备句柄
	Close() error
	// ReadAt 从指定偏移量读取数据到 buf，返回实际读取字节数
	// 内部自动处理扇区对齐
	ReadAt(buf []byte, offset int64) (int, error)
	// Size 返回磁盘/分区总大小（字节）
	Size() (int64, error)
	// SectorSize 返回扇区大小（通常 512）
	SectorSize() int
	// DevicePath 返回设备路径
	DevicePath() string

	io.ReaderAt // 兼容标准库接口
}

// Canceller 可选接口：支持中断进行中的 ReadAt 调用。
// Windows reader 用 CancelIoEx；Unix reader 用 close handle —— 都会让
// 阻塞中的 ReadAt syscall 立刻返回 error。
//
// 上层（recovery.Engine.Stop）在 cancel ctx 后调用，强制中断卡在内核 IO 上的扫描。
type Canceller interface {
	Cancel() error
}

// OpenWithTimeout 在独立 goroutine 里调 r.Open()，超时返回 error。
// 注意：超时时 underlying CreateFile/OpenFile 仍可能在内核里 hang —— Windows API 层面
// 没有可移植的中断方式。这里的超时只保护 *调用方* 不被卡住；后台 goroutine 会泄漏，
// 等内核最终返回后自然终止。
//
// 用途：启动时检测加密卷 / 枚举分区，避免一块 dirty U 盘卡住整个流程。
func OpenWithTimeout(r DiskReader, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- r.Open()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("打开设备 %q 超时 (%v) — 可能磁盘正在系统级文件系统修复或硬件无响应",
			r.DevicePath(), timeout)
	}
}

// NewReader 创建 DiskReader。
//
// 路径识别规则：
//   - `\\.\PhysicalDriveN` / `\\.\C:` / `/dev/...` → 走平台原盘 reader（需要管理员权限）
//   - 其他路径（包括绝对路径的 .img / .dd / .raw 镜像文件）→ 走 imageFileReader
//
// 这样前端"选源盘"和"选镜像文件"可以复用同一入口，上层代码对来源完全透明。
// 业界最佳实践是先 ddrescue 把源盘 dump 到镜像，再对镜像做扫描（保护源盘）。
func NewReader(devicePath string) DiskReader {
	if looksLikeDevicePath(devicePath) {
		return newPlatformReader(devicePath)
	}
	return newImageFileReader(devicePath)
}
