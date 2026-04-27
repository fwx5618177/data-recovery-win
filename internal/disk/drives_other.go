//go:build !windows

package disk

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"data-recovery/internal/logging"
	"data-recovery/internal/types"
)

var driveLogger = logging.L().With("component", "disk")

// listDrivesPlatform 非 Windows 平台的驱动器枚举实现
func listDrivesPlatform() ([]*types.DriveInfo, error) {
	// 检查是否有 root 权限
	if os.Geteuid() != 0 {
		driveLogger.Warn("非 root 用户，可能无法访问磁盘设备。请使用 sudo 获取完整驱动器列表。")
	}

	switch runtime.GOOS {
	case "darwin":
		return listDrivesMacOS()
	case "linux":
		return listDrivesLinux()
	default:
		return nil, fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// listDrivesMacOS 扫描 macOS 磁盘设备
//
// **DEV 模式** (`DATA_RECOVERY_DEV_MODE=1`)：跳过物理盘枚举，直接返回空列表
// + 提示信息。原因：每次 os.Open("/dev/disk0") 在没有 Full Disk Access 时会
// 触发 macOS 系统级权限框（不光是错误返回，是 modal 弹窗 → 严重伤开发体验）。
// dev 模式下用户应该用 .img 镜像文件 + 拖入测试，不需要真物理盘。
func listDrivesMacOS() ([]*types.DriveInfo, error) {
	if os.Getenv("DATA_RECOVERY_DEV_MODE") == "1" {
		// dev 模式：返回单条"占位"提示卡，让 UI 知道不是 bug
		return []*types.DriveInfo{{
			Path:        "",
			Name:        "[DEV-MODE] 物理盘枚举已跳过",
			Size:        0,
			SizeHuman:   "—",
			DriveType:   "dev-placeholder",
			FileSystem:  "",
			IsRemovable: false,
		}}, nil
	}

	var drives []*types.DriveInfo

	// 扫描 /dev/disk* 设备（仅整盘，排除分区如 disk0s1）
	matches, err := filepath.Glob("/dev/disk[0-9]*")
	if err != nil {
		return nil, fmt.Errorf("扫描 /dev/disk* 失败: %w", err)
	}

	for _, devPath := range matches {
		baseName := filepath.Base(devPath)

		// 排除分区设备（含有 's' 的是分区，如 disk0s1）
		if strings.Contains(baseName[4:], "s") {
			continue
		}

		// 检查设备是否可访问
		info, err := os.Stat(devPath)
		if err != nil {
			continue
		}

		// 获取磁盘大小（尝试打开设备读取）
		var diskSize int64
		diskSize = getDiskSizeMacOS(devPath)
		if diskSize <= 0 {
			// 回退：使用 stat 信息（对于设备文件通常为 0，但对镜像文件有效）
			diskSize = info.Size()
		}

		drive := &types.DriveInfo{
			Path:        devPath,
			Name:        fmt.Sprintf("磁盘 %s", baseName),
			Size:        diskSize,
			SizeHuman:   types.FormatSize(diskSize),
			DriveType:   "physical",
			FileSystem:  "",
			IsRemovable: isRemovableMacOS(baseName),
		}

		drives = append(drives, drive)
	}

	// 同时扫描 rdisk 设备（raw disk，性能更好）不添加到列表，
	// 但如果用户直接指定 rdisk 路径也是可以用的

	return drives, nil
}

// getDiskSizeMacOS 尝试获取 macOS 磁盘大小
func getDiskSizeMacOS(devPath string) int64 {
	f, err := os.Open(devPath)
	if err != nil {
		return 0
	}
	defer f.Close()

	// 通过 Seek 到末尾获取大小
	size, err := f.Seek(0, 2) // io.SeekEnd
	if err != nil {
		return 0
	}

	// 复位到开头
	_, _ = f.Seek(0, 0)

	return size
}

// isRemovableMacOS 判断 macOS 磁盘是否为可移动设备
func isRemovableMacOS(diskName string) bool {
	// macOS 上 disk0 通常是内置硬盘，disk1 及以上可能是可移动设备
	// 这是简化逻辑；完整实现应使用 diskutil 或 IOKit
	numStr := strings.TrimPrefix(diskName, "disk")
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return false
	}
	return num > 0
}

// listDrivesLinux 从 /sys/block/ 获取 Linux 块设备列表
func listDrivesLinux() ([]*types.DriveInfo, error) {
	var drives []*types.DriveInfo

	// 读取 /sys/block/ 目录获取所有块设备
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, fmt.Errorf("读取 /sys/block/ 失败: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()

		// 跳过 loop 设备和 ram 设备
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}

		devPath := "/dev/" + name
		sysPath := "/sys/block/" + name

		// 检查设备是否存在
		if _, err := os.Stat(devPath); err != nil {
			continue
		}

		// 读取磁盘大小（单位：512字节扇区）
		diskSize := getBlockDeviceSizeLinux(sysPath)

		// 判断是否可移动
		removable := isRemovableLinux(sysPath)

		// 判断设备类型名称
		devType := "physical"
		displayName := fmt.Sprintf("磁盘 %s", name)
		if strings.HasPrefix(name, "sd") {
			displayName = fmt.Sprintf("SCSI/SATA 磁盘 %s", name)
		} else if strings.HasPrefix(name, "nvme") {
			displayName = fmt.Sprintf("NVMe 磁盘 %s", name)
		} else if strings.HasPrefix(name, "vd") {
			displayName = fmt.Sprintf("虚拟磁盘 %s", name)
		} else if strings.HasPrefix(name, "mmcblk") {
			displayName = fmt.Sprintf("SD/eMMC 卡 %s", name)
			removable = true
		}

		drive := &types.DriveInfo{
			Path:        devPath,
			Name:        displayName,
			Size:        diskSize,
			SizeHuman:   types.FormatSize(diskSize),
			DriveType:   devType,
			FileSystem:  "",
			IsRemovable: removable,
		}

		drives = append(drives, drive)
	}

	return drives, nil
}

// getBlockDeviceSizeLinux 从 sysfs 读取块设备大小
func getBlockDeviceSizeLinux(sysPath string) int64 {
	sizePath := filepath.Join(sysPath, "size")
	data, err := os.ReadFile(sizePath)
	if err != nil {
		return 0
	}

	sectorCount, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}

	// /sys/block/xxx/size 的单位是 512 字节扇区
	return sectorCount * 512
}

// isRemovableLinux 从 sysfs 判断设备是否可移动
func isRemovableLinux(sysPath string) bool {
	removablePath := filepath.Join(sysPath, "removable")
	data, err := os.ReadFile(removablePath)
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(data)) == "1"
}
