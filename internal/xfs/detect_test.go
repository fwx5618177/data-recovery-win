package xfs

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

func TestDetect_XFS(t *testing.T) {
	disk := make([]byte, 512)
	binary.BigEndian.PutUint32(disk[0:4], xfsMagic)
	binary.BigEndian.PutUint32(disk[4:8], 4096)
	binary.BigEndian.PutUint64(disk[8:16], 1<<30)
	copy(disk[108:120], []byte("rhel-root"))
	r := testutil.NewMemReader(disk)
	got, err := Detect(r, 0)
	if err != nil || got == nil {
		t.Fatalf("Detect: %v %+v", err, got)
	}
	if got.BlockSize != 4096 || got.Label != "rhel-root" {
		t.Errorf("字段错: %+v", got)
	}
}

func TestDetect_NotXFS(t *testing.T) {
	r := testutil.NewMemReader(make([]byte, 512))
	if g, _ := Detect(r, 0); g != nil {
		t.Error("不是 XFS 应 nil")
	}
}
