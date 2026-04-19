package disk

// FreeSpace 表示某个路径所在文件系统的空间信息。
type FreeSpace struct {
	Total     int64 `json:"total"`     // 总容量（字节）
	Available int64 `json:"available"` // 可用容量（字节）
}

// GetFreeSpace 查询指定路径所在卷/挂载点的剩余空间。
// 实现分平台：Windows 用 GetDiskFreeSpaceExW，Unix 用 statfs。
func GetFreeSpace(path string) (FreeSpace, error) {
	return getFreeSpacePlatform(path)
}
