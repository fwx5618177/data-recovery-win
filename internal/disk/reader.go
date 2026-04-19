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
