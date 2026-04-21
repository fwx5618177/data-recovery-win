package btrfs

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

func TestDetect_Btrfs_Roundtrip(t *testing.T) {
	const vol = 64 * 1024
	disk := make([]byte, vol+8192)
	sb := disk[vol:]
	copy(sb[64:72], []byte(superMagic))
	for i := 0; i < 16; i++ {
		sb[32+i] = byte(0xAA + i)
	}
	binary.LittleEndian.PutUint64(sb[104:112], 1<<40) // total bytes
	binary.LittleEndian.PutUint32(sb[180:184], 4096)
	binary.LittleEndian.PutUint32(sb[184:188], 16384)
	copy(sb[299:307], []byte("MyDrive"))

	r := testutil.NewMemReader(disk)
	got, err := Detect(r, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got == nil {
		t.Fatal("应识别 Btrfs")
	}
	if got.SectorSize != 4096 || got.NodeSize != 16384 {
		t.Errorf("字段错: %+v", got)
	}
	if got.Label != "MyDrive" {
		t.Errorf("Label=%q want MyDrive", got.Label)
	}
}

func TestDetect_NotBtrfs(t *testing.T) {
	r := testutil.NewMemReader(make([]byte, 128*1024))
	if got, _ := Detect(r, 0); got != nil {
		t.Error("不是 Btrfs 应返回 nil")
	}
}
