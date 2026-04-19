//go:build windows

package disk

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// alignedBufPool 复用扇区对齐缓冲区，避免每次 ReadAt 都 make 一块新内存。
// 约定按常见调用尺寸分级：64KB / 1MB / 4MB / 8MB / >8MB。
// 池按上界取整分配，命中时复用；不命中时单次 make 一块。
var alignedBufPool = [...]struct {
	max  int64
	pool sync.Pool
}{
	{max: 64 * 1024, pool: sync.Pool{New: func() any { b := make([]byte, 64*1024); return &b }}},
	{max: 1 * 1024 * 1024, pool: sync.Pool{New: func() any { b := make([]byte, 1*1024*1024); return &b }}},
	{max: 4 * 1024 * 1024, pool: sync.Pool{New: func() any { b := make([]byte, 4*1024*1024); return &b }}},
	{max: 8 * 1024 * 1024, pool: sync.Pool{New: func() any { b := make([]byte, 8*1024*1024); return &b }}},
}

// getAlignedBuf 获取长度至少 size 的缓冲区，返回 (buf, release)。
// 调用方用完后必须 release()；超出最大档位时 release 为 no-op。
func getAlignedBuf(size int64) ([]byte, func()) {
	for i := range alignedBufPool {
		if size <= alignedBufPool[i].max {
			ptr := alignedBufPool[i].pool.Get().(*[]byte)
			idx := i
			return (*ptr)[:size], func() {
				// 归还时保持原始容量，切回最大长度避免调用者持有截短切片
				full := (*ptr)[:cap(*ptr)]
				*ptr = full
				alignedBufPool[idx].pool.Put(ptr)
			}
		}
	}
	// 超大读，不进池
	b := make([]byte, size)
	return b, func() {}
}

var (
	modkernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procSetFilePointerEx = modkernel32.NewProc("SetFilePointerEx")
)

// setFilePointerEx wraps the Windows SetFilePointerEx API which is not
// directly exported by golang.org/x/sys/windows.
func setFilePointerEx(handle windows.Handle, distanceToMove int64, newFilePointer *int64, moveMethod uint32) error {
	r1, _, e1 := procSetFilePointerEx.Call(
		uintptr(handle),
		uintptr(distanceToMove),
		uintptr(unsafe.Pointer(newFilePointer)),
		uintptr(moveMethod),
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

// IOCTL 常量定义
const (
	ioctlDiskGetLengthInfo    = 0x0007405C // IOCTL_DISK_GET_LENGTH_INFO
	ioctlDiskGetDriveGeometry = 0x00070000 // IOCTL_DISK_GET_DRIVE_GEOMETRY
)

// diskGetLengthInfo 对应 Windows GET_LENGTH_INFORMATION 结构体
type diskGetLengthInfo struct {
	Length int64
}

// diskGeometry 对应 Windows DISK_GEOMETRY 结构体
type diskGeometry struct {
	Cylinders         int64
	MediaType         uint32
	TracksPerCylinder uint32
	SectorsPerTrack   uint32
	BytesPerSector    uint32
}

// windowsReader Windows 平台磁盘读取器
type windowsReader struct {
	path       string
	handle     windows.Handle
	sectorSize int
	diskSize   int64
	mu         sync.Mutex
}

// newPlatformReader 创建 Windows 平台磁盘读取器
func newPlatformReader(devicePath string) DiskReader {
	return &windowsReader{
		path:       devicePath,
		handle:     windows.InvalidHandle,
		sectorSize: 512,
		diskSize:   -1,
	}
}

// Open 打开磁盘设备
// 使用直接 I/O 模式（FILE_FLAG_NO_BUFFERING）绕过系统缓存
func (r *windowsReader) Open() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pathPtr, err := windows.UTF16PtrFromString(r.path)
	if err != nil {
		return fmt.Errorf("无效的设备路径 %q: %w", r.path, err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_NO_BUFFERING|windows.FILE_FLAG_RANDOM_ACCESS,
		0,
	)
	if err != nil {
		// 权限不足时给出清晰提示
		if err == windows.ERROR_ACCESS_DENIED {
			return fmt.Errorf("无法打开设备 %q: 权限不足，请以管理员身份运行程序", r.path)
		}
		return fmt.Errorf("无法打开设备 %q: %w", r.path, err)
	}

	r.handle = handle

	// 尝试获取扇区大小
	r.detectSectorSize()

	// 尝试获取磁盘大小并缓存
	size, err := r.getDiskSize()
	if err == nil {
		r.diskSize = size
	}

	return nil
}

// Close 关闭设备句柄
func (r *windowsReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.handle == windows.InvalidHandle {
		return nil
	}

	err := windows.CloseHandle(r.handle)
	r.handle = windows.InvalidHandle
	if err != nil {
		return fmt.Errorf("关闭设备句柄失败: %w", err)
	}
	return nil
}

// ReadAt 从指定偏移量读取数据到 buf
// 自动处理扇区对齐，保证直接 I/O 模式下的正确读取
func (r *windowsReader) ReadAt(buf []byte, offset int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.handle == windows.InvalidHandle {
		return 0, fmt.Errorf("设备未打开，请先调用 Open()")
	}

	if len(buf) == 0 {
		return 0, nil
	}

	sectorSize := int64(r.sectorSize)

	// 计算扇区对齐的偏移量和大小
	alignedOffset := offset - (offset % sectorSize)
	endOffset := offset + int64(len(buf))
	alignedEnd := endOffset
	if alignedEnd%sectorSize != 0 {
		alignedEnd = alignedEnd + (sectorSize - alignedEnd%sectorSize)
	}
	alignedSize := alignedEnd - alignedOffset

	// 从缓冲池取一块对齐缓冲区（4MB 块 × worker 数 × 秒级调用，不池化会频繁触发 GC）
	alignedBuf, release := getAlignedBuf(alignedSize)
	defer release()

	// 设置文件指针到对齐位置
	err := setFilePointerEx(r.handle, alignedOffset, nil, windows.FILE_BEGIN)
	if err != nil {
		return 0, fmt.Errorf("定位到偏移量 %d 失败: %w", alignedOffset, err)
	}

	// 读取对齐后的数据
	var bytesRead uint32
	err = windows.ReadFile(r.handle, alignedBuf, &bytesRead, nil)
	if err != nil {
		return 0, fmt.Errorf("读取偏移量 %d 处数据失败: %w", alignedOffset, err)
	}

	// 从对齐缓冲区中拷贝实际需要的范围
	copyStart := offset - alignedOffset
	copyEnd := copyStart + int64(len(buf))
	if copyEnd > int64(bytesRead) {
		copyEnd = int64(bytesRead)
	}
	if copyStart >= int64(bytesRead) {
		return 0, fmt.Errorf("读取的数据不足：需要偏移 %d，仅读取 %d 字节", copyStart, bytesRead)
	}

	n := copy(buf, alignedBuf[copyStart:copyEnd])
	return n, nil
}

// Size 返回磁盘/分区总大小（字节）
func (r *windowsReader) Size() (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.diskSize > 0 {
		return r.diskSize, nil
	}

	if r.handle == windows.InvalidHandle {
		return 0, fmt.Errorf("设备未打开，请先调用 Open()")
	}

	size, err := r.getDiskSize()
	if err != nil {
		return 0, err
	}
	r.diskSize = size
	return size, nil
}

// getDiskSize 获取磁盘大小（内部方法，不加锁）
func (r *windowsReader) getDiskSize() (int64, error) {
	// 方法一：通过 IOCTL_DISK_GET_LENGTH_INFO 获取
	var lengthInfo diskGetLengthInfo
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		r.handle,
		ioctlDiskGetLengthInfo,
		nil,
		0,
		(*byte)(unsafe.Pointer(&lengthInfo)),
		uint32(unsafe.Sizeof(lengthInfo)),
		&bytesReturned,
		nil,
	)
	if err == nil && lengthInfo.Length > 0 {
		return lengthInfo.Length, nil
	}

	// 方法二：使用 SetFilePointerEx 定位到末尾获取大小
	var size int64
	err = setFilePointerEx(r.handle, 0, &size, windows.FILE_END)
	if err != nil {
		return 0, fmt.Errorf("无法获取磁盘大小: %w", err)
	}

	// 将指针恢复到文件开头
	_ = setFilePointerEx(r.handle, 0, nil, windows.FILE_BEGIN)

	if size > 0 {
		return size, nil
	}

	return 0, fmt.Errorf("无法获取磁盘大小：所有方法均失败")
}

// detectSectorSize 检测扇区大小（内部方法，不加锁）
func (r *windowsReader) detectSectorSize() {
	var geometry diskGeometry
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		r.handle,
		ioctlDiskGetDriveGeometry,
		nil,
		0,
		(*byte)(unsafe.Pointer(&geometry)),
		uint32(unsafe.Sizeof(geometry)),
		&bytesReturned,
		nil,
	)
	if err == nil && geometry.BytesPerSector > 0 {
		r.sectorSize = int(geometry.BytesPerSector)
	}
	// 检测失败时保持默认值 512
}

// SectorSize 返回扇区大小
func (r *windowsReader) SectorSize() int {
	return r.sectorSize
}

// DevicePath 返回设备路径
func (r *windowsReader) DevicePath() string {
	return r.path
}
