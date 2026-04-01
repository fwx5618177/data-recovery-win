//go:build windows

package disk

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"data-recovery/internal/types"
)

// listDrivesPlatform Windows 平台驱动器枚举实现
func listDrivesPlatform() ([]*types.DriveInfo, error) {
	var drives []*types.DriveInfo

	// 1. 枚举逻辑驱动器（C:, D: 等）
	logicalDrives, err := listLogicalDrives()
	if err == nil {
		drives = append(drives, logicalDrives...)
	}

	// 2. 枚举物理磁盘（\\.\PhysicalDrive0, 1, 2...）
	physicalDrives, err := listPhysicalDrives()
	if err == nil {
		drives = append(drives, physicalDrives...)
	}

	if len(drives) == 0 {
		return nil, fmt.Errorf("未找到任何驱动器，请以管理员身份运行程序")
	}

	return drives, nil
}

// listLogicalDrives 枚举逻辑驱动器
func listLogicalDrives() ([]*types.DriveInfo, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, fmt.Errorf("获取逻辑驱动器失败: %w", err)
	}

	var drives []*types.DriveInfo

	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}

		letter := string(rune('A' + i))
		rootPath := letter + `:\`
		devicePath := `\\.\` + letter + ":"

		// 获取驱动器类型
		driveType := windows.GetDriveType(windows.StringToUTF16Ptr(rootPath))

		// 跳过不相关的驱动器类型
		if driveType == windows.DRIVE_NO_ROOT_DIR || driveType == windows.DRIVE_UNKNOWN {
			continue
		}

		info := &types.DriveInfo{
			Path:      devicePath,
			DriveType: "logical",
		}

		// 判断是否可移动设备
		switch driveType {
		case windows.DRIVE_REMOVABLE:
			info.IsRemovable = true
		case windows.DRIVE_CDROM:
			// 跳过光驱
			continue
		}

		// 获取卷信息（卷名、文件系统）
		volumeName, fileSystem := getVolumeInfo(rootPath)
		info.FileSystem = fileSystem
		if volumeName != "" {
			info.Name = fmt.Sprintf("%s (%s:)", volumeName, letter)
		} else {
			info.Name = fmt.Sprintf("本地磁盘 (%s:)", letter)
		}

		// 获取磁盘大小
		totalSize := getDiskFreeSpace(rootPath)
		info.Size = totalSize
		info.SizeHuman = types.FormatSize(totalSize)

		drives = append(drives, info)
	}

	return drives, nil
}

// getVolumeInfo 获取卷名和文件系统信息
func getVolumeInfo(rootPath string) (volumeName string, fileSystem string) {
	var volumeNameBuf [windows.MAX_PATH + 1]uint16
	var fileSystemBuf [windows.MAX_PATH + 1]uint16
	var serialNumber uint32
	var maxComponentLen uint32
	var fileSystemFlags uint32

	err := windows.GetVolumeInformation(
		windows.StringToUTF16Ptr(rootPath),
		&volumeNameBuf[0],
		uint32(len(volumeNameBuf)),
		&serialNumber,
		&maxComponentLen,
		&fileSystemFlags,
		&fileSystemBuf[0],
		uint32(len(fileSystemBuf)),
	)
	if err != nil {
		return "", ""
	}

	volumeName = windows.UTF16ToString(volumeNameBuf[:])
	fileSystem = windows.UTF16ToString(fileSystemBuf[:])
	return volumeName, fileSystem
}

// getDiskFreeSpace 获取磁盘总大小
func getDiskFreeSpace(rootPath string) int64 {
	var freeBytesAvailable uint64
	var totalNumberOfBytes uint64
	var totalNumberOfFreeBytes uint64

	err := windows.GetDiskFreeSpaceEx(
		windows.StringToUTF16Ptr(rootPath),
		&freeBytesAvailable,
		&totalNumberOfBytes,
		&totalNumberOfFreeBytes,
	)
	if err != nil {
		return 0
	}

	return int64(totalNumberOfBytes)
}

// listPhysicalDrives 枚举物理磁盘
func listPhysicalDrives() ([]*types.DriveInfo, error) {
	var drives []*types.DriveInfo

	// 尝试打开 PhysicalDrive0 到 PhysicalDrive15
	for i := 0; i <= 15; i++ {
		devicePath := fmt.Sprintf(`\\.\PhysicalDrive%d`, i)
		pathPtr, err := windows.UTF16PtrFromString(devicePath)
		if err != nil {
			continue
		}

		// 尝试打开设备
		handle, err := windows.CreateFile(
			pathPtr,
			windows.GENERIC_READ,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		if err != nil {
			// 无法打开，跳过此设备
			continue
		}

		info := &types.DriveInfo{
			Path:      devicePath,
			Name:      fmt.Sprintf("物理磁盘 %d", i),
			DriveType: "physical",
		}

		// 获取磁盘大小
		diskSize := getPhysicalDiskSize(handle)
		info.Size = diskSize
		info.SizeHuman = types.FormatSize(diskSize)

		// 尝试判断是否为可移动设备（通过设备描述中的关键词）
		if strings.Contains(strings.ToLower(info.Name), "usb") ||
			strings.Contains(strings.ToLower(info.Name), "removable") {
			info.IsRemovable = true
		}

		windows.CloseHandle(handle)
		drives = append(drives, info)
	}

	if len(drives) == 0 {
		return nil, fmt.Errorf("未找到物理磁盘，请以管理员身份运行程序")
	}

	return drives, nil
}

// getPhysicalDiskSize 通过 IOCTL 获取物理磁盘大小
func getPhysicalDiskSize(handle windows.Handle) int64 {
	// 使用 IOCTL_DISK_GET_LENGTH_INFO 获取磁盘大小
	// 返回的结构体只包含一个 int64 (LARGE_INTEGER)
	var diskLength int64
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		handle,
		ioctlDiskGetLengthInfo,
		nil,
		0,
		(*byte)(unsafe.Pointer(&diskLength)),
		uint32(unsafe.Sizeof(diskLength)),
		&bytesReturned,
		nil,
	)
	if err == nil {
		return diskLength
	}

	// 回退方案：使用 SetFilePointerEx 移动到末尾获取大小
	var size int64
	err = setFilePointerEx(handle, 0, &size, windows.FILE_END)
	if err == nil {
		// 重置到开头
		setFilePointerEx(handle, 0, nil, windows.FILE_BEGIN)
		return size
	}

	return 0
}
