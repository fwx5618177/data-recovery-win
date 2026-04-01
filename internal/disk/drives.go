package disk

import "data-recovery/internal/types"

// ListDrives 返回系统中所有可用的驱动器
func ListDrives() ([]*types.DriveInfo, error) {
	return listDrivesPlatform()
}
