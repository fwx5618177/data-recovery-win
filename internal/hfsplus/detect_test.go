package hfsplus

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// 合成一张磁盘：前 1024 字节是 boot blocks（任意填），随后 512 字节是合法 HFS+ volume header。
func TestDetect_HFSPlus_Roundtrip(t *testing.T) {
	disk := make([]byte, 4*1024)
	// boot blocks 填一些非零字节避免被误判
	for i := 0; i < 1024; i++ {
		disk[i] = 0x55
	}
	// volume header @ +1024
	hdr := disk[1024:]
	binary.BigEndian.PutUint16(hdr[0:2], sigHFSPlus)
	binary.BigEndian.PutUint16(hdr[2:4], 4) // version
	binary.BigEndian.PutUint32(hdr[4:8], (1<<13))
	binary.BigEndian.PutUint32(hdr[32:36], 12)    // FolderCount
	binary.BigEndian.PutUint32(hdr[36:40], 345)   // FileCount
	binary.BigEndian.PutUint32(hdr[40:44], 4096)  // BlockSize
	binary.BigEndian.PutUint32(hdr[44:48], 100000)// TotalBlocks
	binary.BigEndian.PutUint32(hdr[48:52], 50000) // FreeBlocks
	binary.BigEndian.PutUint32(hdr[64:68], 16)    // NextCNID
	binary.BigEndian.PutUint32(hdr[68:72], 7)     // WriteCount

	r := testutil.NewMemReader(disk)
	v, err := Detect(r, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v == nil {
		t.Fatal("Detect 没识别出 HFS+")
	}
	if v.Signature != sigHFSPlus {
		t.Errorf("Signature 0x%X want 0x%X", v.Signature, sigHFSPlus)
	}
	if v.BlockSize != 4096 || v.TotalBlocks != 100000 || v.FreeBlocks != 50000 {
		t.Errorf("基本字段错: %+v", v)
	}
	if v.FolderCount != 12 || v.FileCount != 345 {
		t.Errorf("目录/文件计数错")
	}
	if !v.IsJournaled {
		t.Error("Attributes journaled bit 未识别")
	}
	if v.IsHFSX {
		t.Error("HFS+ 不应被识别为 HFSX")
	}
}

func TestDetect_HFSX_Recognized(t *testing.T) {
	disk := make([]byte, 4*1024)
	hdr := disk[1024:]
	binary.BigEndian.PutUint16(hdr[0:2], sigHFSX)
	binary.BigEndian.PutUint32(hdr[40:44], 4096)
	binary.BigEndian.PutUint32(hdr[44:48], 1)
	r := testutil.NewMemReader(disk)
	v, err := Detect(r, 0)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if v == nil || !v.IsHFSX {
		t.Fatal("HFSX 未识别")
	}
}

func TestDetect_NotHFS_ReturnsNil(t *testing.T) {
	r := testutil.NewMemReader(make([]byte, 4*1024)) // 全 0
	v, err := Detect(r, 0)
	if err != nil {
		t.Fatalf("err 应为 nil: %v", err)
	}
	if v != nil {
		t.Error("非 HFS+ 应返回 nil")
	}
}

func TestFindVolumes_FindsTwo(t *testing.T) {
	const (
		volSize = int64(8 * 1024 * 1024) // 每个卷 8MB
		junkBetween = int64(2 * 1024 * 1024)
	)
	totalSize := volSize + junkBetween + volSize
	disk := make([]byte, totalSize)

	makeHFS := func(buf []byte) {
		hdr := buf[1024:]
		binary.BigEndian.PutUint16(hdr[0:2], sigHFSPlus)
		binary.BigEndian.PutUint32(hdr[40:44], 4096)
		binary.BigEndian.PutUint32(hdr[44:48], 1024)
	}
	makeHFS(disk[0:volSize])
	makeHFS(disk[volSize+junkBetween:])

	r := testutil.NewMemReader(disk)
	vols, err := NewScanner(r).FindVolumes()
	if err != nil {
		t.Fatalf("FindVolumes: %v", err)
	}
	if len(vols) != 2 {
		t.Fatalf("应找到 2 个卷，实际 %d", len(vols))
	}
	if vols[0].Offset != 0 {
		t.Errorf("第一个 offset 错: %d", vols[0].Offset)
	}
	if vols[1].Offset != volSize+junkBetween {
		t.Errorf("第二个 offset 错: %d want %d", vols[1].Offset, volSize+junkBetween)
	}
}
