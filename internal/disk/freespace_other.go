//go:build !windows

package disk

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func getFreeSpacePlatform(path string) (FreeSpace, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return FreeSpace{}, fmt.Errorf("statfs %s 失败: %w", path, err)
	}
	bs := int64(st.Bsize)
	return FreeSpace{
		Total:     int64(st.Blocks) * bs,
		Available: int64(st.Bavail) * bs,
	}, nil
}
