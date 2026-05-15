package ext4

import (
	"context"
	"encoding/binary"
	"testing"

	"data-recovery/internal/testutil"
)

// 造一个最小可用的 ext4 镜像：1 个块组、根目录里 1 个文件。
//
// 布局（block_size=1024，便于手工对齐）：
//
//	block 0: padding（前 1024 字节，BIOS 引导扇区位置）
//	block 1: superblock
//	block 2: group descriptor table
//	block 3: data block bitmap
//	block 4: inode bitmap
//	block 5..N: inode table（256 字节 inode × InodesPerGroup）
//	block N+1...: 数据块
//
// 我们重点造：超块 + GD + 几个 inode（root + 一个普通文件）+ root 目录数据 + 文件数据
func buildMinimalExt4Image(t *testing.T) []byte {
	t.Helper()

	const (
		blockSize       = 1024
		inodeSize       = 256
		inodesPerGroup  = 64
		inodeTableBlock = 5
		fileDataBlock   = 50
		rootDirBlock    = 49
	)

	// 总大小：留够给 inode table（64 inode * 256 = 16KB = 16 blocks）+ 数据块
	totalBlocks := uint64(64)
	img := make([]byte, totalBlocks*blockSize)

	// === SUPERBLOCK at offset 1024 (block 1) ===
	sb := img[1024:2048]
	binary.LittleEndian.PutUint32(sb[sbInodesCount:], inodesPerGroup)
	binary.LittleEndian.PutUint32(sb[sbBlocksCount:], uint32(totalBlocks))
	binary.LittleEndian.PutUint32(sb[sbFirstDataBlock:], 1) // block_size=1024 时是 1
	binary.LittleEndian.PutUint32(sb[sbLogBlockSize:], 0)   // 1024 << 0 = 1024
	binary.LittleEndian.PutUint32(sb[sbBlocksPerGroup:], uint32(totalBlocks))
	binary.LittleEndian.PutUint32(sb[sbInodesPerGroup:], inodesPerGroup)
	binary.LittleEndian.PutUint16(sb[sbMagic:], ext2Magic)
	binary.LittleEndian.PutUint32(sb[sbRevLevel:], 1) // dynamic
	binary.LittleEndian.PutUint32(sb[sbFirstInode:], 11)
	binary.LittleEndian.PutUint16(sb[sbInodeSize:], inodeSize)
	// 0x0002 = INCOMPAT_FILETYPE（目录项有 file_type 字节，ext3+ 默认开启）
	binary.LittleEndian.PutUint32(sb[sbFeatureIncompat:], incompatExtents|0x0002)
	copy(sb[sbVolumeName:sbVolumeName+10], []byte("test-vol"))

	// === GROUP DESCRIPTOR at block 2 ===
	gd := img[2*blockSize : 2*blockSize+32]
	binary.LittleEndian.PutUint32(gd[0x08:], inodeTableBlock)  // inode_table_lo
	binary.LittleEndian.PutUint16(gd[0x0E:], inodesPerGroup-2) // free_inodes_count_lo

	// === ROOT INODE = inode #2，在 inode table 第 1 个位置（offset = 0）===
	rootInodeOff := inodeTableBlock*blockSize + (2-1)*inodeSize
	rootInode := img[rootInodeOff : rootInodeOff+inodeSize]
	binary.LittleEndian.PutUint16(rootInode[0x00:], imodeDir|0o755) // mode
	binary.LittleEndian.PutUint32(rootInode[0x04:], blockSize)      // size
	binary.LittleEndian.PutUint16(rootInode[0x1A:], 2)              // links_count
	binary.LittleEndian.PutUint32(rootInode[0x1C:], blockSize/512)  // blocks (512-byte sectors)
	binary.LittleEndian.PutUint32(rootInode[0x20:], 0x80000)        // EXT4_EXTENTS_FL

	// 根目录用 extent tree：一个 leaf extent 指向 rootDirBlock
	ext := rootInode[0x28 : 0x28+60]
	binary.LittleEndian.PutUint16(ext[0:2], extentMagic)
	binary.LittleEndian.PutUint16(ext[2:4], 1) // entries
	binary.LittleEndian.PutUint16(ext[4:6], 4) // max
	binary.LittleEndian.PutUint16(ext[6:8], 0) // depth=0 (leaf)
	// 第一条 extent at offset 12: ee_block=0, ee_len=1, start=rootDirBlock
	binary.LittleEndian.PutUint32(ext[12:16], 0) // ee_block
	binary.LittleEndian.PutUint16(ext[16:18], 1) // ee_len
	binary.LittleEndian.PutUint16(ext[18:20], 0) // ee_start_hi
	binary.LittleEndian.PutUint32(ext[20:24], rootDirBlock)

	// === 文件 INODE = inode #12 ===
	fileInodeOff := inodeTableBlock*blockSize + (12-1)*inodeSize
	fileInode := img[fileInodeOff : fileInodeOff+inodeSize]
	const fileSize = 256
	binary.LittleEndian.PutUint16(fileInode[0x00:], imodeRegular|0o644)
	binary.LittleEndian.PutUint32(fileInode[0x04:], fileSize)
	binary.LittleEndian.PutUint16(fileInode[0x1A:], 1) // links_count=1
	binary.LittleEndian.PutUint32(fileInode[0x1C:], 1) // 1 个 512 字节扇区
	binary.LittleEndian.PutUint32(fileInode[0x20:], 0x80000)
	// extent → fileDataBlock
	fext := fileInode[0x28 : 0x28+60]
	binary.LittleEndian.PutUint16(fext[0:2], extentMagic)
	binary.LittleEndian.PutUint16(fext[2:4], 1)
	binary.LittleEndian.PutUint16(fext[4:6], 4)
	binary.LittleEndian.PutUint16(fext[6:8], 0)
	binary.LittleEndian.PutUint32(fext[12:16], 0)
	binary.LittleEndian.PutUint16(fext[16:18], 1)
	binary.LittleEndian.PutUint16(fext[18:20], 0)
	binary.LittleEndian.PutUint32(fext[20:24], fileDataBlock)

	// === 文件数据放在 fileDataBlock，写一段标记字节 ===
	for i := 0; i < fileSize; i++ {
		img[fileDataBlock*blockSize+i] = byte(i & 0xFF)
	}

	// === ROOT 目录数据（block 49）：含 . / .. / "hello.txt" 三个目录项 ===
	dir := img[rootDirBlock*blockSize : (rootDirBlock+1)*blockSize]
	pos := 0
	// "." entry: inode=2, rec_len=12, name_len=1, file_type=2 (dir), name="."
	binary.LittleEndian.PutUint32(dir[pos:], 2)    // inode
	binary.LittleEndian.PutUint16(dir[pos+4:], 12) // rec_len
	dir[pos+6] = 1                                 // name_len
	dir[pos+7] = 2                                 // file_type
	dir[pos+8] = '.'
	pos += 12
	// ".." entry
	binary.LittleEndian.PutUint32(dir[pos:], 2)
	binary.LittleEndian.PutUint16(dir[pos+4:], 12)
	dir[pos+6] = 2
	dir[pos+7] = 2
	dir[pos+8] = '.'
	dir[pos+9] = '.'
	pos += 12
	// "hello.txt" entry: inode=12, rec_len=blockSize-pos (吞剩余空间)
	const fname = "hello.txt"
	nameLen := len(fname)
	recLen := blockSize - pos
	binary.LittleEndian.PutUint32(dir[pos:], 12)
	binary.LittleEndian.PutUint16(dir[pos+4:], uint16(recLen))
	dir[pos+6] = byte(nameLen)
	dir[pos+7] = ftRegular
	copy(dir[pos+8:], []byte(fname))

	return img
}

func TestParseSuperblock_Minimal(t *testing.T) {
	img := buildMinimalExt4Image(t)
	reader := testutil.NewMemReader(img)
	sb, err := ParseSuperblock(reader, 0)
	if err != nil {
		t.Fatalf("ParseSuperblock: %v", err)
	}
	if sb.Variant != VariantEXT4 {
		t.Errorf("Variant 错: %v", sb.Variant)
	}
	if sb.BlockSize != 1024 {
		t.Errorf("BlockSize 错: %d", sb.BlockSize)
	}
	if sb.InodeSize != 256 {
		t.Errorf("InodeSize 错: %d", sb.InodeSize)
	}
	if sb.VolumeName != "test-vol" {
		t.Errorf("VolumeName 错: %q", sb.VolumeName)
	}
	if !sb.HasExtents {
		t.Error("应识别 HasExtents=true")
	}
}

func TestReadInode_RootAndFile(t *testing.T) {
	img := buildMinimalExt4Image(t)
	reader := testutil.NewMemReader(img)
	sb, _ := ParseSuperblock(reader, 0)
	gds, err := ReadGroupDescriptors(reader, sb)
	if err != nil {
		t.Fatalf("ReadGroupDescriptors: %v", err)
	}
	ir := NewInodeReader(reader, sb, gds)

	root, err := ir.ReadInode(2)
	if err != nil {
		t.Fatalf("ReadInode(2): %v", err)
	}
	if !root.IsDirectory {
		t.Error("inode 2 应是目录")
	}
	if !root.UseExtents {
		t.Error("inode 2 应启用 extents")
	}

	file, err := ir.ReadInode(12)
	if err != nil {
		t.Fatalf("ReadInode(12): %v", err)
	}
	if !file.IsRegularFile {
		t.Error("inode 12 应是普通文件")
	}
	if file.Size != 256 {
		t.Errorf("inode 12 size 错: %d", file.Size)
	}
}

func TestCollectFileBlocks_Extent(t *testing.T) {
	img := buildMinimalExt4Image(t)
	reader := testutil.NewMemReader(img)
	sb, _ := ParseSuperblock(reader, 0)
	gds, _ := ReadGroupDescriptors(reader, sb)
	ir := NewInodeReader(reader, sb, gds)

	file, _ := ir.ReadInode(12)
	ranges, err := CollectFileBlocks(reader, sb, file)
	if err != nil {
		t.Fatalf("CollectFileBlocks: %v", err)
	}
	if len(ranges) != 1 {
		t.Fatalf("应得 1 段 extent，实际 %d", len(ranges))
	}
	if ranges[0].PhysicalBlock != 50 {
		t.Errorf("PhysicalBlock 错: %d", ranges[0].PhysicalBlock)
	}
	if ranges[0].Length != 1 {
		t.Errorf("Length 错: %d", ranges[0].Length)
	}
}

func TestScanFiles_FindsHelloTxt(t *testing.T) {
	img := buildMinimalExt4Image(t)
	reader := testutil.NewMemReader(img)
	scanner := NewScanner(reader)

	parts, err := scanner.FindPartitions(context.Background(), FindOptions{})
	if err != nil {
		t.Fatalf("FindPartitions: %v", err)
	}
	if len(parts) == 0 {
		t.Fatal("应找到 ext 分区")
	}

	var found []FoundFile
	if err := scanner.ScanFiles(context.Background(), parts[0], func(ff FoundFile) {
		found = append(found, ff)
	}); err != nil {
		t.Fatalf("ScanFiles: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("应至少找到 hello.txt")
	}
	var hello *FoundFile
	for i := range found {
		if found[i].FullPath == "hello.txt" {
			hello = &found[i]
			break
		}
	}
	if hello == nil {
		t.Fatalf("没找到 hello.txt；找到的是: %v", paths(found))
	}
	if hello.Inode.Size != 256 {
		t.Errorf("hello.txt 大小错: %d", hello.Inode.Size)
	}
}

func paths(ff []FoundFile) []string {
	out := make([]string, 0, len(ff))
	for _, f := range ff {
		out = append(out, f.FullPath)
	}
	return out
}
