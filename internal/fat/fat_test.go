package fat

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// buildFAT32Boot 造一个最小合法的 FAT32 boot sector。
// 按 Microsoft 规范：ClusterCount >= 65525 时文件系统被判定为 FAT32。
// 所以 TotalSectors 必须足够大 —— 这里用 100000，确保 ClusterCount 约 99904。
// img 实际只造 64 个扇区数据（读 FAT 用），TotalSectors 字段只做类型判定不真读到末尾。
func buildFAT32Boot() []byte {
	bs := make([]byte, 512)
	binary.LittleEndian.PutUint16(bs[11:13], 512)
	bs[13] = 1
	binary.LittleEndian.PutUint16(bs[14:16], 32)
	bs[16] = 2
	binary.LittleEndian.PutUint16(bs[17:19], 0) // RootEntryCount=0 是 FAT32 惯例
	binary.LittleEndian.PutUint32(bs[32:36], 100000)
	binary.LittleEndian.PutUint32(bs[36:40], 32)
	binary.LittleEndian.PutUint32(bs[44:48], 2)
	binary.LittleEndian.PutUint16(bs[510:512], 0xAA55)
	return bs
}

// buildFAT16Boot 造最小合法的 FAT16 boot sector（小容量）
// 保证 ClusterCount 在 [4085, 65525) 区间从而被判定为 FAT16
func buildFAT16Boot() []byte {
	bs := make([]byte, 512)
	binary.LittleEndian.PutUint16(bs[11:13], 512) // BytesPerSector
	bs[13] = 1                                     // SectorsPerCluster=1
	binary.LittleEndian.PutUint16(bs[14:16], 1)    // ReservedSectors=1
	bs[16] = 2                                     // NumFATs=2
	binary.LittleEndian.PutUint16(bs[17:19], 512)  // RootEntryCount=512（非 FAT32）
	// TotalSectors: 用 16-bit 字段，填 10000
	binary.LittleEndian.PutUint16(bs[19:21], 10000)
	binary.LittleEndian.PutUint16(bs[22:24], 20) // FATSize16=20
	binary.LittleEndian.PutUint16(bs[510:512], 0xAA55)
	return bs
}

func TestParseBootSector_FAT32(t *testing.T) {
	reader := testutil.NewMemReader(buildFAT32Boot())
	bs, err := ParseBootSector(reader, 0)
	if err != nil {
		t.Fatalf("ParseBootSector: %v", err)
	}
	if bs.FSType != TypeFAT32 {
		t.Errorf("FSType 错: got %v want FAT32", bs.FSType)
	}
	if bs.RootCluster != 2 {
		t.Errorf("RootCluster 错: got %d", bs.RootCluster)
	}
	if bs.ClusterSize != 512 {
		t.Errorf("ClusterSize 错: got %d", bs.ClusterSize)
	}
}

func TestParseBootSector_FAT16(t *testing.T) {
	reader := testutil.NewMemReader(buildFAT16Boot())
	bs, err := ParseBootSector(reader, 0)
	if err != nil {
		t.Fatalf("ParseBootSector: %v", err)
	}
	if bs.FSType != TypeFAT16 {
		t.Errorf("FSType 错: got %v want FAT16 (ClusterCount=%d)", bs.FSType, bs.ClusterCount)
	}
	if bs.RootDirSectors == 0 {
		t.Error("FAT16 RootDirSectors 应 > 0")
	}
}

func TestParseBootSector_RejectsBadSignature(t *testing.T) {
	bs := buildFAT32Boot()
	bs[510] = 0x00 // 破坏 0xAA55
	reader := testutil.NewMemReader(bs)
	if _, err := ParseBootSector(reader, 0); err == nil {
		t.Error("非法 boot signature 应被拒")
	}
}

func TestReadFATEntry_FAT32(t *testing.T) {
	// 把整块镜像造出来：boot sector + FAT 表
	boot := buildFAT32Boot()
	img := make([]byte, 512*64)
	copy(img, boot)

	// FAT32 表从 sector 32 开始，cluster 5 的条目在 fatStart + 5*4
	fatStart := 32 * 512
	// 写 cluster 5 → next=10，cluster 10 → EOC
	binary.LittleEndian.PutUint32(img[fatStart+5*4:], 10)
	binary.LittleEndian.PutUint32(img[fatStart+10*4:], 0x0FFFFFFF)

	reader := testutil.NewMemReader(img)
	bs, _ := ParseBootSector(reader, 0)

	got, err := ReadFATEntry(reader, bs, 0, 5)
	if err != nil || got != 10 {
		t.Errorf("cluster 5 → %d err=%v, want 10", got, err)
	}
	got, err = ReadFATEntry(reader, bs, 0, 10)
	if err != nil || got != FatEntryEOC {
		t.Errorf("cluster 10 应是 EOC，got 0x%X err=%v", got, err)
	}
}

func TestFollowFATChain_FAT32_Simple(t *testing.T) {
	boot := buildFAT32Boot()
	img := make([]byte, 512*64)
	copy(img, boot)
	fatStart := 32 * 512

	// 链：5 → 7 → 9 → EOC
	binary.LittleEndian.PutUint32(img[fatStart+5*4:], 7)
	binary.LittleEndian.PutUint32(img[fatStart+7*4:], 9)
	binary.LittleEndian.PutUint32(img[fatStart+9*4:], 0x0FFFFFFF)

	reader := testutil.NewMemReader(img)
	bs, _ := ParseBootSector(reader, 0)

	chain, err := FollowFATChain(reader, bs, 0, 5)
	if err != nil {
		t.Fatalf("FollowFATChain: %v", err)
	}
	want := []uint32{5, 7, 9}
	if len(chain) != len(want) {
		t.Fatalf("链长度错: %v vs %v", chain, want)
	}
	for i, c := range want {
		if chain[i] != c {
			t.Errorf("chain[%d]=%d want %d", i, chain[i], c)
		}
	}
}

func TestFollowFATChain_DetectsCycle(t *testing.T) {
	boot := buildFAT32Boot()
	img := make([]byte, 512*64)
	copy(img, boot)
	fatStart := 32 * 512

	// 环：5 → 7 → 5
	binary.LittleEndian.PutUint32(img[fatStart+5*4:], 7)
	binary.LittleEndian.PutUint32(img[fatStart+7*4:], 5)

	reader := testutil.NewMemReader(img)
	bs, _ := ParseBootSector(reader, 0)
	_, err := FollowFATChain(reader, bs, 0, 5)
	if err == nil {
		t.Error("环链应返回错误")
	}
}

func TestParseShortName(t *testing.T) {
	cases := []struct {
		raw  []byte
		want string
	}{
		{[]byte{'H', 'E', 'L', 'L', 'O', ' ', ' ', ' ', 'T', 'X', 'T'}, "HELLO.TXT"},
		{[]byte{'N', 'A', 'M', 'E', ' ', ' ', ' ', ' ', ' ', ' ', ' '}, "NAME"},
		{[]byte{0x05, 'N', 'A', 'M', 'E', ' ', ' ', ' ', ' ', ' ', ' '}, "\xe5NAME"},
	}
	for _, c := range cases {
		got := parseShortName(c.raw)
		if got != c.want {
			t.Errorf("parseShortName(%v) = %q want %q", c.raw, got, c.want)
		}
	}
}

func TestParseFATDate(t *testing.T) {
	// 2020-06-15 14:30:00
	// year - 1980 = 40 (bit 9-15) = 0x50
	// month 6 (bits 5-8), day 15 (bits 0-4) → date = (40<<9) | (6<<5) | 15
	date := uint16((40 << 9) | (6 << 5) | 15)
	// hour 14 (bits 11-15), minute 30 (bits 5-10), sec 0 → tm = (14<<11) | (30<<5) | 0
	tm := uint16((14 << 11) | (30 << 5) | 0)
	got := parseFATDate(date, tm)
	if got == nil {
		t.Fatal("parseFATDate 应非 nil")
	}
	if got.Year() != 2020 || got.Month() != 6 || got.Day() != 15 {
		t.Errorf("日期解析错: %v", got)
	}
}

func TestParseDirEntries_DeletedFile(t *testing.T) {
	buf := make([]byte, 32)
	buf[0] = deletedMarker
	copy(buf[1:11], []byte("ELETETXT")) // 8 bytes name (pretend-delete of "DELETE.TXT")
	binary.LittleEndian.PutUint32(buf[28:32], 1234) // FileSize
	buf[20] = 0                                     // cluster high = 0
	buf[21] = 0
	buf[26] = 5                                     // cluster low = 5
	buf[27] = 0

	entries := parseDirEntries(buf)
	if len(entries) != 1 {
		t.Fatalf("应解析出 1 个条目，实际 %d", len(entries))
	}
	if !entries[0].IsDeleted {
		t.Error("应识别为已删除")
	}
	if entries[0].FileSize != 1234 {
		t.Errorf("FileSize 错: %d", entries[0].FileSize)
	}
	if entries[0].FirstCluster != 5 {
		t.Errorf("FirstCluster 错: %d", entries[0].FirstCluster)
	}
}
