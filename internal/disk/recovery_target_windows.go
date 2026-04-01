//go:build windows

package disk

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const ioctlVolumeGetVolumeDiskExtents = 0x00560000

var procGetVolumePathNameW = modkernel32.NewProc("GetVolumePathNameW")

type diskExtent struct {
	DiskNumber     uint32
	_              uint32
	StartingOffset int64
	ExtentLength   int64
}

type volumeDiskExtents struct {
	NumberOfDiskExtents uint32
	_                   uint32
	Extents             [1]diskExtent
}

func validateRecoveryTargetPlatform(sourceDevicePath string, outputDir string) error {
	sourceDisks, sourceLabel, err := diskNumbersForSource(sourceDevicePath)
	if err != nil {
		return fmt.Errorf("无法确认源盘信息: %w", err)
	}

	if isWindowsUNCPath(outputDir) {
		return nil
	}

	outputDisks, outputLabel, err := diskNumbersForOutputDir(outputDir)
	if err != nil {
		return fmt.Errorf("无法确认恢复目录所在磁盘: %w", err)
	}

	if hasDiskOverlap(sourceDisks, outputDisks) {
		return fmt.Errorf(
			"恢复目录位于源盘所在的同一块物理磁盘（源盘 %s，恢复目录 %s），请改选另一块磁盘或 U 盘",
			sourceLabel,
			outputLabel,
		)
	}

	return nil
}

func diskNumbersForSource(sourceDevicePath string) (map[uint32]struct{}, string, error) {
	cleanPath := strings.TrimSpace(sourceDevicePath)
	if cleanPath == "" {
		return nil, "", fmt.Errorf("源盘路径为空")
	}

	if diskNumber, ok := parsePhysicalDriveNumber(cleanPath); ok {
		return map[uint32]struct{}{diskNumber: {}}, cleanPath, nil
	}

	devicePath, label, err := normalizeWindowsVolumeDevicePath(cleanPath)
	if err != nil {
		return nil, cleanPath, err
	}

	disks, err := diskNumbersForVolumeDevicePath(devicePath)
	if err != nil {
		return nil, label, err
	}

	return disks, label, nil
}

func diskNumbersForOutputDir(outputDir string) (map[uint32]struct{}, string, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(outputDir))
	if cleanPath == "" {
		return nil, "", fmt.Errorf("恢复目录为空")
	}

	volumeRoot, err := getVolumePathName(cleanPath)
	if err != nil {
		return nil, cleanPath, err
	}

	if isWindowsUNCPath(volumeRoot) {
		return nil, volumeRoot, nil
	}

	devicePath, label, err := normalizeWindowsVolumeDevicePath(volumeRoot)
	if err != nil {
		return nil, cleanPath, err
	}

	disks, err := diskNumbersForVolumeDevicePath(devicePath)
	if err != nil {
		return nil, label, err
	}

	return disks, label, nil
}

func diskNumbersForVolumeDevicePath(volumePath string) (map[uint32]struct{}, error) {
	handle, err := openVolumeHandle(volumePath)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	const maxExtents = 32
	extentSize := unsafe.Sizeof(diskExtent{})
	headerSize := unsafe.Sizeof(volumeDiskExtents{})
	bufSize := int(headerSize + uintptr(maxExtents-1)*extentSize)
	buf := make([]byte, bufSize)
	var bytesReturned uint32

	err = windows.DeviceIoControl(
		handle,
		ioctlVolumeGetVolumeDiskExtents,
		nil,
		0,
		&buf[0],
		uint32(len(buf)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("读取卷磁盘映射失败: %w", err)
	}

	header := (*volumeDiskExtents)(unsafe.Pointer(&buf[0]))
	count := int(header.NumberOfDiskExtents)
	if count <= 0 {
		return nil, fmt.Errorf("卷没有可用的磁盘映射")
	}
	if count > maxExtents {
		return nil, fmt.Errorf("卷跨越的磁盘数量超出支持范围: %d", count)
	}

	disks := make(map[uint32]struct{}, count)
	basePtr := unsafe.Pointer(&header.Extents[0])
	for index := 0; index < count; index++ {
		extent := (*diskExtent)(unsafe.Pointer(uintptr(basePtr) + uintptr(index)*extentSize))
		disks[extent.DiskNumber] = struct{}{}
	}

	return disks, nil
}

func getVolumePathName(path string) (string, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("无效的路径 %q: %w", path, err)
	}

	buf := make([]uint16, 1024)
	r1, _, callErr := procGetVolumePathNameW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return "", callErr
		}
		return "", fmt.Errorf("GetVolumePathNameW 调用失败")
	}

	return windows.UTF16ToString(buf), nil
}

func openVolumeHandle(volumePath string) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(volumePath)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("无效的卷路径 %q: %w", volumePath, err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("打开卷 %q 失败: %w", volumePath, err)
	}

	return handle, nil
}

func normalizeWindowsVolumeDevicePath(path string) (string, string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return "", "", fmt.Errorf("卷路径为空")
	}

	if isWindowsVolumeDevicePath(cleanPath) {
		letter := strings.ToUpper(cleanPath[4:6])
		return `\\.\` + letter, letter + `\`, nil
	}

	cleanPath = strings.TrimRight(cleanPath, `\`)
	if len(cleanPath) >= 2 && cleanPath[1] == ':' {
		letter := strings.ToUpper(cleanPath[:2])
		return `\\.\` + letter, letter + `\`, nil
	}

	return "", cleanPath, fmt.Errorf("无法识别卷路径 %q", path)
}

func isWindowsUNCPath(path string) bool {
	cleanPath := strings.TrimSpace(path)
	return strings.HasPrefix(cleanPath, `\\`) && !strings.HasPrefix(cleanPath, `\\.\`)
}

func isWindowsVolumeDevicePath(path string) bool {
	if len(path) < 6 {
		return false
	}

	return strings.HasPrefix(strings.ToLower(path), `\\.\`) && path[5] == ':'
}

func parsePhysicalDriveNumber(path string) (uint32, bool) {
	lowerPath := strings.ToLower(strings.TrimSpace(path))
	index := strings.LastIndex(lowerPath, "physicaldrive")
	if index < 0 {
		return 0, false
	}

	value := strings.TrimSpace(lowerPath[index+len("physicaldrive"):])
	if value == "" {
		return 0, false
	}

	number, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, false
	}

	return uint32(number), true
}

func hasDiskOverlap(sourceDisks map[uint32]struct{}, outputDisks map[uint32]struct{}) bool {
	if len(sourceDisks) == 0 || len(outputDisks) == 0 {
		return false
	}

	for diskNumber := range sourceDisks {
		if _, ok := outputDisks[diskNumber]; ok {
			return true
		}
	}

	return false
}
