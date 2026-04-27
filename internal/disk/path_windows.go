//go:build windows

package disk

import (
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows 路径解析工具。
//
// 用户在前端选盘时，drive list 来自 GetLogicalDrives + EnumPhysicalDrives，
// 路径既可能是 `\\.\PhysicalDriveN` 也可能是 `\\.\X:`。但很多硬件级操作
// （SMART / GPT / SED / 扇区级 IOCTL）只能在物理盘 handle 上跑 —— 必须把
// 逻辑卷映射回物理盘。

// IOCTL_STORAGE_GET_DEVICE_NUMBER —— 给定卷 / 设备 handle，返回它所在的物理盘索引。
// winioctl.h: CTL_CODE(IOCTL_STORAGE_BASE, 0x0420, METHOD_BUFFERED, FILE_ANY_ACCESS)
const ioctlStorageGetDeviceNumber uint32 = 0x002D1080

// STORAGE_DEVICE_NUMBER 结构（winioctl.h）
type storageDeviceNumber struct {
	DeviceType      uint32
	DeviceNumber    uint32
	PartitionNumber uint32
}

// ResolveToPhysicalDriveWindows 把任意 Windows 盘路径标准化为 `\\.\PhysicalDriveN`。
// 失败返回原路径（让调用方自己决定是否退化处理）。
//
//   - `\\.\PhysicalDriveN`  → 原样返回
//   - `\\.\X:`              → 用 IOCTL_STORAGE_GET_DEVICE_NUMBER 查物理盘索引
//   - `diskN` / `N`         → 当成索引补成 PhysicalDriveN
//   - 镜像文件路径          → 原样返回（虚拟设备无物理盘概念）
func ResolveToPhysicalDriveWindows(devicePath string) string {
	return resolveToPhysicalDriveWindows(devicePath)
}

// 内部小写版（package 内调用）
func resolveToPhysicalDriveWindows(devicePath string) string {
	if devicePath == "" {
		return ""
	}
	low := strings.ToLower(devicePath)

	// 已经是物理盘 → 原样返回
	if strings.HasPrefix(low, `\\.\physicaldrive`) {
		return devicePath
	}
	// 索引补全：disk0 / 0 / physicaldrive0
	if !strings.HasPrefix(low, `\\.\`) {
		if n := tryParseDriveIndex(devicePath); n >= 0 {
			return `\\.\PhysicalDrive` + strconv.Itoa(n)
		}
	}
	// 逻辑卷 \\.\X: → 查 device number
	if strings.HasPrefix(low, `\\.\`) && len(low) >= 6 && low[5] == ':' {
		if n := lookupPhysicalDriveForVolume(devicePath); n >= 0 {
			return `\\.\PhysicalDrive` + strconv.Itoa(n)
		}
	}
	// 其它情况（镜像 / UNC / 未识别）—— 原样返回，让上层自己处理
	return devicePath
}

// lookupPhysicalDriveForVolume 用 IOCTL_STORAGE_GET_DEVICE_NUMBER 查
// 逻辑卷（如 \\.\G:）所在的物理盘索引。失败返回 -1。
func lookupPhysicalDriveForVolume(volumePath string) int {
	pUTF16, err := windows.UTF16PtrFromString(volumePath)
	if err != nil {
		return -1
	}
	// 注意：这里用 0 access 打开 —— 只问 metadata 不读数据，能避开"卷被独占占用"的问题
	hFile, err := windows.CreateFile(
		pUTF16,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return -1
	}
	defer windows.CloseHandle(hFile)

	var sdn storageDeviceNumber
	var bytesReturned uint32
	if err := windows.DeviceIoControl(
		hFile,
		ioctlStorageGetDeviceNumber,
		nil, 0,
		(*byte)(unsafe.Pointer(&sdn)), uint32(unsafe.Sizeof(sdn)),
		&bytesReturned, nil,
	); err != nil {
		return -1
	}
	// PartitionNumber 是逻辑卷在该物理盘上的分区号（1-based）；DeviceNumber 是物理盘索引（0-based）
	return int(sdn.DeviceNumber)
}
