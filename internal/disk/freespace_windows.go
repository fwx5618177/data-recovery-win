//go:build windows

package disk

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func getFreeSpacePlatform(path string) (FreeSpace, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return FreeSpace{}, fmt.Errorf("无效路径 %q: %w", path, err)
	}
	var freeAvail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeAvail, &total, &totalFree); err != nil {
		return FreeSpace{}, fmt.Errorf("GetDiskFreeSpaceEx %s 失败: %w", path, err)
	}
	return FreeSpace{Total: int64(total), Available: int64(freeAvail)}, nil
}
