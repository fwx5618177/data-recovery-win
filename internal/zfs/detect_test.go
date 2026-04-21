package zfs

import (
	"testing"

	"data-recovery/internal/testutil"
)

func TestDetect_ZFS_HitsSignals(t *testing.T) {
	disk := make([]byte, 256*1024)
	for _, sig := range []string{"zpool", "vdev_tree", "ZFS_BOOT", "name", "pool_guid"} {
		copy(disk[len(sig)*100:], []byte(sig))
	}
	// 实际上要让 bytes.Contains 找到，这种放法 OK（每个字符串落不同位置）
	copy(disk[1000:], []byte("zpool"))
	copy(disk[2000:], []byte("vdev_tree"))
	copy(disk[3000:], []byte("ZFS_BOOT"))
	copy(disk[4000:], []byte("pool_guid"))
	r := testutil.NewMemReader(disk)
	got, _ := Detect(r, 0)
	if got == nil {
		t.Fatal("应识别 ZFS")
	}
}

func TestDetect_NotZFS(t *testing.T) {
	r := testutil.NewMemReader(make([]byte, 256*1024))
	if g, _ := Detect(r, 0); g != nil {
		t.Error("空盘不是 ZFS")
	}
}
