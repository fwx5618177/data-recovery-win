//go:build windows

package disk

import (
	"fmt"
	"sync"
	"sync/atomic"
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
	procCancelIoEx       = modkernel32.NewProc("CancelIoEx")
)

// cancelIoEx 取消 handle 上所有 pending IO，让阻塞中的 ReadFile 立刻返回错误。
// lpOverlapped 传 NULL 表示取消同步 IO 也即所有 pending IO。
func cancelIoEx(handle windows.Handle) error {
	r1, _, e1 := procCancelIoEx.Call(uintptr(handle), 0)
	if r1 == 0 {
		return e1
	}
	return nil
}

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

	// cancelled 是 reader 的"毒化"开关。v2.8.22 加 —— Cancel 之后 ReadAt 立刻
	// 返回 ErrReaderCancelled，不再触达内核 ReadFile。
	//
	// 背景：v2.8.20 的 CancelIoEx 只能取消"当下那一个" pending IO。后续 ReadAt
	// 又能正常 ReadFile。carver Collector / per-format detector 这种没 ctx 的
	// 读循环可在 Stop 后持续打满磁盘几十秒～几分钟。这个 flag 一开就让所有
	// 读路径瞬间快退。
	cancelled atomic.Bool
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
	// v2.8.22: reader 被取消 → 不进内核，直接 fail，让上层 read 循环（不带 ctx 的）
	// 快退。无锁的 atomic.Load 比锁 ReadFile 快几个数量级。
	if r.cancelled.Load() {
		return 0, ErrReaderCancelled
	}
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

// Cancel 把 reader 标为"毒化" + 取消所有 pending IO。
//
// v2.8.22 修订：
//   - 先 atomic.Store cancelled=true → 后续 ReadAt 第一句就 fail，不再触达内核
//   - 再 CancelIoEx → 让卡在内核 ReadFile 上的当前那个 goroutine 立刻醒来
//
// 之前的版本只做 CancelIoEx 但是 CancelIoEx 是一次性的，handle 留着所以后续
// ReadAt 又能正常读盘。carver Collector / per-format detector 等不带 ctx 的
// read 循环就在 Stop 后继续打满磁盘 IO。
//
// CompareAndSwap 保证 Cancel 幂等 + 重复 Stop 不会乱套（用户可能连点 stop）。
//
// 不持锁：ReadAt 当前持有 mu —— 加锁会死等到 ReadAt 自然返回，丢失 Cancel 的意义。
// handle 是 uintptr，原子读 + windows CancelIoEx 对已关闭/无效句柄安全（返回错误而非崩溃）。
func (r *windowsReader) Cancel() error {
	if !r.cancelled.CompareAndSwap(false, true) {
		return nil // 已经取消过
	}
	h := r.handle
	if h == windows.InvalidHandle {
		return nil
	}
	return cancelIoEx(h)
}
