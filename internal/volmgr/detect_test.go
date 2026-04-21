package volmgr

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

func TestDetectMDADM(t *testing.T) {
	disk := make([]byte, 16*1024)
	binary.LittleEndian.PutUint32(disk[4096:4100], 0xA92B4EFC)
	r := testutil.NewMemReader(disk)
	got, _ := DetectMDADM(r)
	if got == nil || got.Type != "mdadm" {
		t.Errorf("应识别 mdadm: %+v", got)
	}
}

func TestDetectLVM2(t *testing.T) {
	disk := make([]byte, 4096)
	copy(disk[512:520], []byte("LABELONE"))
	r := testutil.NewMemReader(disk)
	got, _ := DetectLVM2(r)
	if got == nil || got.Type != "lvm2" {
		t.Errorf("应识别 LVM2: %+v", got)
	}
}

func TestDetectStorageSpaces(t *testing.T) {
	disk := make([]byte, 4096)
	copy(disk[100:], []byte("Microsoft Storage Spaces"))
	r := testutil.NewMemReader(disk)
	got, _ := DetectStorageSpaces(r)
	if got == nil || got.Type != "storage-spaces" {
		t.Errorf("应识别 Storage Spaces: %+v", got)
	}
}

func TestDetectAll_Empty(t *testing.T) {
	r := testutil.NewMemReader(make([]byte, 16*1024))
	out := DetectAll(r)
	if len(out) != 0 {
		t.Errorf("空盘不应识别任何 vol mgr: %+v", out)
	}
}
