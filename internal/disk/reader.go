package disk

import "io"

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

// NewReader 创建适合当前平台的 DiskReader
func NewReader(devicePath string) DiskReader {
	return newPlatformReader(devicePath)
}
