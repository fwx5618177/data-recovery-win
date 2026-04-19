package exfat

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// buildImageWithFAT 造一个带可控 FAT 表的最小 exFAT 镜像。
//
// 布局（sector 512B，cluster 1 sector）：
//   sector  0 : boot sector
//   sector  8..15 : FAT (8 sectors = 4096 bytes = 1024 entries)
//   sector 32..  : cluster heap（从 cluster 2 开始）
//
// fat 参数是直接要写到 FAT 表里的条目（从 entry 0 开始）。
// 比如 fat[5]=6 表示 cluster 5 的下一跳是 cluster 6。
func buildImageWithFAT(fat []uint32) []byte {
	img := make([]byte, 512*512)
	copy(img[0:512], buildBootSector(5, 0)) // root cluster = 5 (测试不看根目录)

	fatByteOffset := 8 * 512 // FatOffset=8 sector
	for i, entry := range fat {
		binary.LittleEndian.PutUint32(img[fatByteOffset+i*4:fatByteOffset+i*4+4], entry)
	}
	return img
}

func TestReadFATEntry_Basic(t *testing.T) {
	fat := make([]uint32, 20)
	fat[5] = 10
	fat[10] = 0xFFFFFFFF // EOC

	img := buildImageWithFAT(fat)
	reader := testutil.NewMemReader(img)
	boot, err := ParseBootSector(reader, 0)
	if err != nil {
		t.Fatalf("ParseBootSector: %v", err)
	}

	// cluster 5 → 10
	got, err := ReadFATEntry(reader, boot, 0, 5)
	if err != nil || got != 10 {
		t.Errorf("cluster 5 entry 错: got 0x%X err=%v, want 10", got, err)
	}

	// cluster 10 → EOC
	got, err = ReadFATEntry(reader, boot, 0, 10)
	if err != nil || got != FatEntryEOC {
		t.Errorf("cluster 10 entry 错: got 0x%X err=%v, want EOC", got, err)
	}
}

func TestReadFATEntry_RejectsReservedClusters(t *testing.T) {
	img := buildImageWithFAT(nil)
	reader := testutil.NewMemReader(img)
	boot, _ := ParseBootSector(reader, 0)

	for _, c := range []uint32{0, 1} {
		if _, err := ReadFATEntry(reader, boot, 0, c); err == nil {
			t.Errorf("cluster %d（保留）应被拒", c)
		}
	}
}

func TestFollowFATChain_SimpleChain(t *testing.T) {
	// 链：5 → 6 → 7 → 8 → EOC
	fat := make([]uint32, 20)
	fat[5] = 6
	fat[6] = 7
	fat[7] = 8
	fat[8] = FatEntryEOC

	img := buildImageWithFAT(fat)
	reader := testutil.NewMemReader(img)
	boot, _ := ParseBootSector(reader, 0)

	chain, err := FollowFATChain(reader, boot, 0, 5)
	if err != nil {
		t.Fatalf("FollowFATChain: %v", err)
	}
	want := []uint32{5, 6, 7, 8}
	if len(chain) != len(want) {
		t.Fatalf("chain 长度错: got %d want %d", len(chain), len(want))
	}
	for i, c := range want {
		if chain[i] != c {
			t.Errorf("chain[%d]=%d want %d", i, chain[i], c)
		}
	}
}

func TestFollowFATChain_DetectsCycle(t *testing.T) {
	// 病态链：5 → 6 → 5（环）
	fat := make([]uint32, 20)
	fat[5] = 6
	fat[6] = 5

	img := buildImageWithFAT(fat)
	reader := testutil.NewMemReader(img)
	boot, _ := ParseBootSector(reader, 0)

	chain, err := FollowFATChain(reader, boot, 0, 5)
	if err == nil {
		t.Error("环链应被检测到并返回错误")
	}
	// 返回的 chain 里应该至少有两个 cluster（已走过的部分）
	if len(chain) < 2 {
		t.Errorf("检测到环前应走完 5,6；实际 chain=%v", chain)
	}
}

func TestFollowFATChain_StopsAtBadCluster(t *testing.T) {
	fat := make([]uint32, 20)
	fat[5] = 6
	fat[6] = FatEntryBad // BAD

	img := buildImageWithFAT(fat)
	reader := testutil.NewMemReader(img)
	boot, _ := ParseBootSector(reader, 0)

	chain, err := FollowFATChain(reader, boot, 0, 5)
	// BAD 标记应停止但至少拿到前半段
	if err == nil {
		t.Error("BAD cluster 应返回错误")
	}
	if len(chain) < 2 {
		t.Errorf("BAD 前应已走过 5,6；实际 %v", chain)
	}
}

func TestFollowFATChain_OutOfRange(t *testing.T) {
	// cluster 5 指向超出 ClusterCount 的号
	fat := make([]uint32, 20)
	fat[5] = 99999999 // 远超 ClusterCount=128

	img := buildImageWithFAT(fat)
	reader := testutil.NewMemReader(img)
	boot, _ := ParseBootSector(reader, 0)

	_, err := FollowFATChain(reader, boot, 0, 5)
	if err == nil {
		t.Error("越界 cluster 应触发错误")
	}
}

func TestFileClusterList_NoFatChain_Contiguous(t *testing.T) {
	img := buildImageWithFAT(nil)
	reader := testutil.NewMemReader(img)
	boot, _ := ParseBootSector(reader, 0)

	// 一个 1500 字节的文件（ClusterSize=512），需要 3 个 cluster
	entry := &DirEntry{
		FirstCluster: 10,
		FileSize:     1500,
		NoFatChain:   true,
	}
	list, err := FileClusterList(reader, boot, 0, entry)
	if err != nil {
		t.Fatalf("FileClusterList: %v", err)
	}
	want := []uint32{10, 11, 12}
	if len(list) != len(want) {
		t.Fatalf("cluster 数错: got %v want %v", list, want)
	}
	for i, c := range want {
		if list[i] != c {
			t.Errorf("list[%d]=%d want %d", i, list[i], c)
		}
	}
}

func TestFileClusterList_WithFatChain(t *testing.T) {
	// 走 FAT 链：5 → 100 → 50 → EOC
	fat := make([]uint32, 200)
	fat[5] = 100
	fat[100] = 50
	fat[50] = FatEntryEOC

	img := buildImageWithFAT(fat)
	reader := testutil.NewMemReader(img)
	boot, _ := ParseBootSector(reader, 0)

	// 1024 字节文件（2 个 cluster）
	entry := &DirEntry{
		FirstCluster: 5,
		FileSize:     1024,
		NoFatChain:   false,
	}
	list, err := FileClusterList(reader, boot, 0, entry)
	if err != nil {
		t.Fatalf("FileClusterList: %v", err)
	}
	// 需要 2 个 cluster，链返回 3 个，应截断到 2
	want := []uint32{5, 100}
	if len(list) != len(want) {
		t.Fatalf("cluster 数错: got %v want %v", list, want)
	}
	for i, c := range want {
		if list[i] != c {
			t.Errorf("list[%d]=%d want %d", i, list[i], c)
		}
	}
}
