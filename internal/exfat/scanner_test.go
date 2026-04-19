package exfat

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"data-recovery/internal/testutil"
)

// buildBootSector 造一个最小合法的 exFAT boot sector（512 字节）
func buildBootSector(firstClusterOfRoot uint32, sectorsPerClusterShift uint8) []byte {
	bs := make([]byte, 512)
	// 0-2: jump boot (EB 76 90)
	bs[0], bs[1], bs[2] = 0xEB, 0x76, 0x90
	// 3-10: OEM ID "EXFAT   "
	copy(bs[3:11], []byte(exFATSignature))
	// 64-71: PartitionOffset (sectors) — 0
	binary.LittleEndian.PutUint64(bs[64:72], 0)
	// 72-79: VolumeLength (sectors) — 1024
	binary.LittleEndian.PutUint64(bs[72:80], 1024)
	// 80-83: FatOffset (sectors) — 8
	binary.LittleEndian.PutUint32(bs[80:84], 8)
	// 84-87: FatLength (sectors) — 8
	binary.LittleEndian.PutUint32(bs[84:88], 8)
	// 88-91: ClusterHeapOffset (sectors) — 32
	binary.LittleEndian.PutUint32(bs[88:92], 32)
	// 92-95: ClusterCount — 128
	binary.LittleEndian.PutUint32(bs[92:96], 128)
	// 96-99: FirstClusterOfRootDirectory
	binary.LittleEndian.PutUint32(bs[96:100], firstClusterOfRoot)
	// 108: BytesPerSectorShift — 9 (512)
	bs[108] = 9
	// 109: SectorsPerClusterShift
	bs[109] = sectorsPerClusterShift
	// 110: NumberOfFats — 1
	bs[110] = 1
	// 510-511: 0xAA55
	binary.LittleEndian.PutUint16(bs[510:512], 0xAA55)
	return bs
}

// buildFileEntrySet 造一个完整的 "File + StreamExt + FileName" entry set，返回字节。
// deleted=true 时 primary type 变 0x05（模拟已删除）
func buildFileEntrySet(name string, size uint64, firstCluster uint32, noFatChain bool, deleted bool) []byte {
	// 把 UTF-16 码元数量算出来
	utf16Name := utf16.Encode([]rune(name))
	nameLen := len(utf16Name)
	fnChunks := (nameLen + 14) / 15 // 每条 FileName 条目最多 15 个码元
	secondaryCount := 1 + fnChunks  // 1 stream ext + N file names
	totalEntries := 1 + secondaryCount

	buf := make([]byte, totalEntries*32)

	// ---- primary: File Directory Entry ----
	if deleted {
		buf[0] = entryFileDeleted
	} else {
		buf[0] = entryFile
	}
	buf[1] = byte(secondaryCount)
	// byte 4-5: FileAttributes — 0 (普通文件)
	// byte 8-11: CreateTimestamp — 非零（避免 parseTimestamp 返回 nil）
	binary.LittleEndian.PutUint32(buf[8:12], 0x52EA8000)  // 2021-某时
	binary.LittleEndian.PutUint32(buf[12:16], 0x52EA8000) // ModifiedTime
	binary.LittleEndian.PutUint32(buf[16:20], 0x52EA8000)

	// ---- secondary #1: Stream Extension ----
	streamPos := 32
	if deleted {
		buf[streamPos] = entryStreamExtensionDeleted
	} else {
		buf[streamPos] = entryStreamExtension
	}
	// byte 1: GeneralSecondaryFlags
	// bit 0: AllocationPossible = 1
	// bit 1: NoFatChain = ?
	flags := uint8(0x01)
	if noFatChain {
		flags |= 0x02
	}
	buf[streamPos+1] = flags
	// byte 3: NameLength
	buf[streamPos+3] = byte(nameLen)
	// byte 8-15: ValidDataLength
	binary.LittleEndian.PutUint64(buf[streamPos+8:streamPos+16], size)
	// byte 20-23: FirstCluster
	binary.LittleEndian.PutUint32(buf[streamPos+20:streamPos+24], firstCluster)
	// byte 24-31: DataLength
	binary.LittleEndian.PutUint64(buf[streamPos+24:streamPos+32], size)

	// ---- secondary #2..N: FileName entries ----
	for i := 0; i < fnChunks; i++ {
		fnPos := 32 * (2 + i)
		if deleted {
			buf[fnPos] = entryFileNameDeleted
		} else {
			buf[fnPos] = entryFileName
		}
		// byte 2-31: 最多 15 个 UTF-16 码元
		start := i * 15
		for j := 0; j < 15 && start+j < nameLen; j++ {
			binary.LittleEndian.PutUint16(buf[fnPos+2+j*2:fnPos+2+j*2+2], utf16Name[start+j])
		}
	}

	return buf
}

// buildSyntheticExFATImage 造一块极简 exFAT 镜像：
//   - 512-byte sector, 1 sector/cluster (ClusterSize = 512)
//   - ClusterHeapOffset = 32 sectors
//   - Root cluster = 5
//   - Root 目录里放 3 个文件条目：1 个正常、1 个已删除、1 个长文件名
func buildSyntheticExFATImage(t *testing.T) []byte {
	t.Helper()

	// 512 sectors = 256KB 足够。每 sector 512 字节；簇大小 = 512
	totalSize := 512 * 512
	img := make([]byte, totalSize)

	// Boot sector
	copy(img[0:512], buildBootSector(5, 0))

	// 根目录位于 cluster 5 → byte offset = ClusterHeapOffset(32) * 512 + (5-2) * 512
	rootOffset := 32*512 + (5-2)*512

	// 往根目录写入三个 entry set
	pos := rootOffset
	// 1. 正常文件 "hello.txt" 100 字节，FirstCluster=20
	es1 := buildFileEntrySet("hello.txt", 100, 20, true, false)
	copy(img[pos:], es1)
	pos += len(es1)

	// 2. 已删除文件 "deleted.jpg" 5000 字节，FirstCluster=30
	es2 := buildFileEntrySet("deleted.jpg", 5000, 30, true, true)
	copy(img[pos:], es2)
	pos += len(es2)

	// 3. 长文件名（20 UTF-16 码元）"long_filename_example.pdf"
	es3 := buildFileEntrySet("long_filename_example.pdf", 200, 40, true, false)
	copy(img[pos:], es3)
	pos += len(es3)

	return img
}

func TestParseBootSector_Minimal(t *testing.T) {
	bs := buildBootSector(5, 0)
	reader := testutil.NewMemReader(bs)
	boot, err := ParseBootSector(reader, 0)
	if err != nil {
		t.Fatalf("ParseBootSector 失败: %v", err)
	}
	if boot.FirstClusterOfRootDirectory != 5 {
		t.Errorf("RootCluster 错: got %d want 5", boot.FirstClusterOfRootDirectory)
	}
	if boot.BytesPerSector != 512 {
		t.Errorf("BytesPerSector 错: got %d", boot.BytesPerSector)
	}
	if boot.ClusterSize != 512 {
		t.Errorf("ClusterSize 错: got %d", boot.ClusterSize)
	}
}

func TestParseBootSector_RejectsNonEXFAT(t *testing.T) {
	bs := make([]byte, 512)
	copy(bs[3:11], []byte("NTFS    "))
	binary.LittleEndian.PutUint16(bs[510:512], 0xAA55)

	reader := testutil.NewMemReader(bs)
	if _, err := ParseBootSector(reader, 0); err == nil {
		t.Error("非 exFAT 盘应拒绝")
	}
}

func TestParseEntrySet_NormalFile(t *testing.T) {
	data := buildFileEntrySet("test.txt", 42, 10, true, false)
	entry, consumed := ParseEntrySet(data, 0)
	if entry == nil {
		t.Fatal("正常文件条目应解析成功")
	}
	if entry.Name != "test.txt" {
		t.Errorf("文件名错: got %q", entry.Name)
	}
	if entry.FileSize != 42 {
		t.Errorf("FileSize 错: got %d", entry.FileSize)
	}
	if entry.FirstCluster != 10 {
		t.Errorf("FirstCluster 错: got %d", entry.FirstCluster)
	}
	if !entry.NoFatChain {
		t.Error("NoFatChain 应为 true")
	}
	if entry.IsDeleted {
		t.Error("未删除文件 IsDeleted 应为 false")
	}
	if consumed != len(data) {
		t.Errorf("consumed 错: got %d want %d", consumed, len(data))
	}
}

func TestParseEntrySet_DeletedFile(t *testing.T) {
	data := buildFileEntrySet("deleted.dat", 1024, 20, true, true)
	entry, _ := ParseEntrySet(data, 0)
	if entry == nil {
		t.Fatal("已删除文件条目应解析成功（我们要恢复它）")
	}
	if !entry.IsDeleted {
		t.Error("已删除文件 IsDeleted 应为 true")
	}
	if entry.Name != "deleted.dat" {
		t.Errorf("文件名错: got %q", entry.Name)
	}
}

func TestParseEntrySet_LongFilename(t *testing.T) {
	longName := "a_very_long_filename_over_15_utf16_code_units.ext"
	data := buildFileEntrySet(longName, 99, 7, true, false)
	entry, _ := ParseEntrySet(data, 0)
	if entry == nil {
		t.Fatal("长文件名条目应解析")
	}
	if entry.Name != longName {
		t.Errorf("长文件名错:\n  got  %q\n  want %q", entry.Name, longName)
	}
}

func TestScanDirectory_FindsAllFiles(t *testing.T) {
	img := buildSyntheticExFATImage(t)
	reader := testutil.NewMemReader(img)

	boot, err := ParseBootSector(reader, 0)
	if err != nil {
		t.Fatalf("ParseBootSector 失败: %v", err)
	}

	scanner := NewScanner(reader)
	var found []FoundFile
	err = scanner.ScanDirectory(context.Background(), boot, 0, func(ff FoundFile) {
		found = append(found, ff)
	})
	if err != nil {
		t.Fatalf("ScanDirectory 失败: %v", err)
	}

	if len(found) != 3 {
		t.Fatalf("应发现 3 个文件，实际 %d", len(found))
	}

	// 按名字索引好断言
	byName := make(map[string]FoundFile)
	for _, f := range found {
		byName[f.Entry.Name] = f
	}

	if hello, ok := byName["hello.txt"]; !ok {
		t.Error("未找到 hello.txt")
	} else if hello.Entry.IsDeleted {
		t.Error("hello.txt 不应被标记为已删除")
	} else if hello.Entry.FileSize != 100 {
		t.Errorf("hello.txt 大小错: got %d", hello.Entry.FileSize)
	}

	if del, ok := byName["deleted.jpg"]; !ok {
		t.Error("未找到已删除的 deleted.jpg")
	} else if !del.Entry.IsDeleted {
		t.Error("deleted.jpg 应标记为已删除")
	} else if del.Entry.FileSize != 5000 {
		t.Errorf("deleted.jpg 大小错: got %d", del.Entry.FileSize)
	}

	if longF, ok := byName["long_filename_example.pdf"]; !ok {
		t.Error("未找到长文件名 PDF")
	} else if longF.Entry.FileSize != 200 {
		t.Errorf("long_filename_example.pdf 大小错: got %d", longF.Entry.FileSize)
	}
}

func TestFindPartitions_Volume(t *testing.T) {
	img := buildSyntheticExFATImage(t)
	reader := testutil.NewMemReader(img)
	scanner := NewScanner(reader)

	parts, err := scanner.FindPartitions(context.Background())
	if err != nil {
		t.Fatalf("FindPartitions 失败: %v", err)
	}
	if len(parts) == 0 {
		t.Fatal("应至少找到一个 exFAT 分区")
	}
	// 第一个应该是 offset=0 的整盘分区
	if parts[0].Offset != 0 {
		t.Errorf("第一个分区偏移应为 0，实际 %d", parts[0].Offset)
	}
}

func TestParseTimestamp_Zero(t *testing.T) {
	if parseTimestamp(0) != nil {
		t.Error("零时间戳应返回 nil")
	}
}

func TestClusterToByteOffset(t *testing.T) {
	boot := &BootSector{
		BytesPerSector:    512,
		SectorsPerCluster: 1,
		ClusterSize:       512,
		ClusterHeapOffset: 32,
	}
	// cluster 2 = 簇堆第一个 = 32 sector * 512 = 16384
	got := boot.ClusterToByteOffset(2, 0)
	if got != 16384 {
		t.Errorf("cluster 2 offset 错: got %d want 16384", got)
	}
	// cluster 5 = 16384 + 3*512 = 17920
	got = boot.ClusterToByteOffset(5, 0)
	if got != 17920 {
		t.Errorf("cluster 5 offset 错: got %d want 17920", got)
	}
	// cluster < 2 应返回 -1
	if boot.ClusterToByteOffset(1, 0) != -1 {
		t.Error("cluster=1 应返回 -1")
	}
}

// 回归：buildFileEntrySet 生成的数据满足 bytes.Contains 匹配，保证测试 harness 可信
func TestBuildFileEntrySet_SanityCheck(t *testing.T) {
	data := buildFileEntrySet("foo.bin", 1, 2, true, false)
	// primary type = 0x85
	if data[0] != entryFile {
		t.Errorf("primary type 错: got 0x%X", data[0])
	}
	// stream extension 在 offset 32
	if data[32] != entryStreamExtension {
		t.Errorf("stream ext type 错: got 0x%X", data[32])
	}
	// 第一个 FileName entry 在 offset 64
	if data[64] != entryFileName {
		t.Errorf("filename type 错: got 0x%X", data[64])
	}
	// 文件名 UTF-16 "foo.bin" 在 offset 66 开始
	if !bytes.Equal(data[66:68], []byte{'f', 0}) {
		t.Errorf("UTF-16 'f' 错: got %v", data[66:68])
	}
}
