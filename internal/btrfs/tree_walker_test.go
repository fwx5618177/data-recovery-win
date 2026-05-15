package btrfs

import (
	"encoding/binary"
	"testing"

	"data-recovery/internal/disk"
	"data-recovery/internal/testutil"
)

// 构造一个 leaf block：header + items + 反向打包的 data 区。
// items 按 key 顺序排好；data 区从 block 末尾向前增长。
func buildLeafBlock(t *testing.T, items []LeafItem, payloads [][]byte) []byte {
	t.Helper()
	if len(items) != len(payloads) {
		t.Fatalf("items / payloads 长度不一致")
	}
	block := make([]byte, btrfsNodeSize)
	// header.NumItems
	binary.LittleEndian.PutUint32(block[96:100], uint32(len(items)))
	// header.Level = 0 (leaf)
	block[100] = 0

	// 数据从 block 末尾向前打包
	dataEnd := btrfsNodeSize
	for i, p := range payloads {
		dataEnd -= len(p)
		copy(block[dataEnd:], p)
		// 写 item header
		off := btrfsHeaderSize + i*btrfsItemSize
		binary.LittleEndian.PutUint64(block[off:off+8], items[i].Key.ObjectID)
		block[off+8] = items[i].Key.Type
		binary.LittleEndian.PutUint64(block[off+9:off+17], items[i].Key.Offset)
		// data offset 是相对 block payload 区起点（即 header 之后）
		binary.LittleEndian.PutUint32(block[off+17:off+21], uint32(dataEnd-btrfsHeaderSize))
		binary.LittleEndian.PutUint32(block[off+21:off+25], uint32(len(p)))
	}
	return block
}

// 单 leaf 的 walker：放 1 个 INODE_ITEM + 2 个 EXTENT_DATA，验证 WalkFSTree 聚合
func TestWalkFSTree_SingleLeafAggregation(t *testing.T) {
	// 1) 构造 leaf payload
	inoBytes := make([]byte, 160)
	binary.LittleEndian.PutUint64(inoBytes[16:24], 1234) // size = 1234
	binary.LittleEndian.PutUint32(inoBytes[52:56], 0o100644)
	binary.LittleEndian.PutUint64(inoBytes[136:144], 1700000000) // mtime

	extBytes := make([]byte, 53)
	binary.LittleEndian.PutUint64(extBytes[8:16], 4096) // ram_bytes
	extBytes[16] = 0                                    // no compression
	extBytes[20] = byte(ExtentDataRegular)
	binary.LittleEndian.PutUint64(extBytes[21:29], 50000) // disk_bytenr
	binary.LittleEndian.PutUint64(extBytes[45:53], 4096)  // num_bytes

	items := []LeafItem{
		{Key: Key{ObjectID: 256, Type: keyTypeInodeItem, Offset: 0}},
		{Key: Key{ObjectID: 256, Type: keyTypeExtentData, Offset: 0}},
		{Key: Key{ObjectID: 256, Type: keyTypeExtentData, Offset: 4096}},
	}
	payloads := [][]byte{inoBytes, extBytes, extBytes}

	leaf := buildLeafBlock(t, items, payloads)

	// 2) 把 leaf 放在镜像里某个 physical 偏移；构造 sysChunk 让 logical→physical
	const physOff int64 = 1024 * 1024 // 1MB
	const logicalAddr uint64 = 0x10000000

	img := make([]byte, physOff+int64(len(leaf)))
	copy(img[physOff:], leaf)
	reader := testutil.NewMemReader(img)

	sb := &ExtendedSuperblock{
		Superblock: &Superblock{NodeSize: btrfsNodeSize},
		SysChunks: []ChunkMapping{{
			LogicalStart: logicalAddr,
			Length:       1 << 20,
			NumStripes:   1,
			Stripes:      []ChunkStripe{{DevID: 1, Offset: uint64(physOff)}},
		}},
	}

	// 3) 走 FS tree，预期收到 1 个 FSItem with 2 extents
	var got []*FSItem
	if err := WalkFSTree(reader, sb, logicalAddr, func(it *FSItem) bool {
		got = append(got, it)
		return true
	}); err != nil {
		t.Fatalf("WalkFSTree: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("应聚合成 1 个 FSItem, got %d", len(got))
	}
	it := got[0]
	if it.ObjectID != 256 {
		t.Errorf("objectid = %d", it.ObjectID)
	}
	if it.INode == nil || it.INode.Size != 1234 {
		t.Errorf("INode 解析错: %+v", it.INode)
	}
	if len(it.Extents) != 2 {
		t.Errorf("extents 数: got %d want 2", len(it.Extents))
	}
	if it.Extents[0].DiskByteNr != 50000 {
		t.Errorf("extent disk_bytenr = %d", it.Extents[0].DiskByteNr)
	}
}

// 多 inode（不同 objectid）应被拆成多个 FSItem
func TestWalkFSTree_MultipleInodes(t *testing.T) {
	mkInode := func(size uint64) []byte {
		b := make([]byte, 160)
		binary.LittleEndian.PutUint64(b[16:24], size)
		return b
	}
	items := []LeafItem{
		{Key: Key{ObjectID: 100, Type: keyTypeInodeItem}},
		{Key: Key{ObjectID: 200, Type: keyTypeInodeItem}},
		{Key: Key{ObjectID: 300, Type: keyTypeInodeItem}},
	}
	payloads := [][]byte{mkInode(1), mkInode(2), mkInode(3)}
	leaf := buildLeafBlock(t, items, payloads)

	img := make([]byte, 1024*1024+len(leaf))
	copy(img[1024*1024:], leaf)
	sb := &ExtendedSuperblock{
		Superblock: &Superblock{NodeSize: btrfsNodeSize},
		SysChunks: []ChunkMapping{{
			LogicalStart: 0x10000,
			Length:       1 << 20,
			NumStripes:   1,
			Stripes:      []ChunkStripe{{Offset: 1024 * 1024}},
		}},
	}
	reader := testutil.NewMemReader(img)
	var seen []uint64
	WalkFSTree(reader, sb, 0x10000, func(it *FSItem) bool {
		seen = append(seen, it.ObjectID)
		return true
	})
	if len(seen) != 3 || seen[0] != 100 || seen[1] != 200 || seen[2] != 300 {
		t.Errorf("多 inode 聚合错: %v", seen)
	}
}

// callback 返回 false 应立即停止
func TestWalkFSTree_StopsOnFalse(t *testing.T) {
	mkInode := func(size uint64) []byte {
		b := make([]byte, 160)
		binary.LittleEndian.PutUint64(b[16:24], size)
		return b
	}
	items := []LeafItem{
		{Key: Key{ObjectID: 100, Type: keyTypeInodeItem}},
		{Key: Key{ObjectID: 200, Type: keyTypeInodeItem}},
	}
	payloads := [][]byte{mkInode(1), mkInode(2)}
	leaf := buildLeafBlock(t, items, payloads)
	img := make([]byte, 1024*1024+len(leaf))
	copy(img[1024*1024:], leaf)
	sb := &ExtendedSuperblock{
		Superblock: &Superblock{NodeSize: btrfsNodeSize},
		SysChunks: []ChunkMapping{{
			LogicalStart: 0x10000, Length: 1 << 20, NumStripes: 1,
			Stripes: []ChunkStripe{{Offset: 1024 * 1024}},
		}},
	}
	reader := testutil.NewMemReader(img)
	count := 0
	WalkFSTree(reader, sb, 0x10000, func(it *FSItem) bool {
		count++
		return false // 立即停
	})
	if count != 1 {
		t.Errorf("应只回调 1 次然后停, got %d", count)
	}
}

// ParseINodeItem / ParseExtentData / ParseRootItem 单元测试
func TestParseINodeItem_Layout(t *testing.T) {
	b := make([]byte, 160)
	binary.LittleEndian.PutUint64(b[0:8], 999)            // generation
	binary.LittleEndian.PutUint64(b[16:24], 12345)        // size
	binary.LittleEndian.PutUint32(b[44:48], 1000)         // uid
	binary.LittleEndian.PutUint32(b[48:52], 1000)         // gid
	binary.LittleEndian.PutUint32(b[52:56], 0o100644)     // mode
	binary.LittleEndian.PutUint64(b[136:144], 1700000000) // mtime
	ino, err := ParseINodeItem(b)
	if err != nil {
		t.Fatal(err)
	}
	if ino.Generation != 999 || ino.Size != 12345 || ino.UID != 1000 ||
		ino.Mode != 0o100644 || ino.Mtime != 1700000000 {
		t.Errorf("ParseINodeItem 字段错: %+v", ino)
	}
}

func TestParseExtentData_Inline(t *testing.T) {
	b := make([]byte, 30)
	binary.LittleEndian.PutUint64(b[8:16], 9)
	b[16] = 1 // zlib
	b[20] = byte(ExtentDataInline)
	copy(b[21:], []byte("inlineDAT"))
	e, err := ParseExtentData(b)
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != ExtentDataInline || e.Compression != 1 || string(e.InlineData) != "inlineDAT" {
		t.Errorf("inline extent 解析错: %+v", e)
	}
}

func TestParseExtentData_Regular(t *testing.T) {
	b := make([]byte, 53)
	binary.LittleEndian.PutUint64(b[8:16], 4096)
	b[20] = byte(ExtentDataRegular)
	binary.LittleEndian.PutUint64(b[21:29], 0xDEAD)
	binary.LittleEndian.PutUint64(b[29:37], 4096)
	binary.LittleEndian.PutUint64(b[37:45], 0)
	binary.LittleEndian.PutUint64(b[45:53], 4096)
	e, err := ParseExtentData(b)
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != ExtentDataRegular || e.DiskByteNr != 0xDEAD || e.NumBytes != 4096 {
		t.Errorf("regular extent 解析错: %+v", e)
	}
}

func TestParseRootItem_ByteNr(t *testing.T) {
	b := make([]byte, 220)
	binary.LittleEndian.PutUint64(b[160:168], 42)         // generation
	binary.LittleEndian.PutUint64(b[168:176], 256)        // root_dirid
	binary.LittleEndian.PutUint64(b[176:184], 0xCAFEBABE) // bytenr
	r, err := ParseRootItem(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Generation != 42 || r.RootDirID != 256 || r.ByteNr != 0xCAFEBABE {
		t.Errorf("ParseRootItem 错: %+v", r)
	}
}

// 死循环防护：构造一个 inner node 指向自己的 logical 地址，应在 maxDepth 处 error
func TestWalkTree_DepthLimit(t *testing.T) {
	// 构造一个 inner node block，level=1, NumItems=1, child 指向自己 logical
	const selfLogical = uint64(0x100000)
	const physOff = int64(1 * 1024 * 1024)
	block := make([]byte, btrfsNodeSize)
	binary.LittleEndian.PutUint32(block[96:100], 1)
	block[100] = 1 // level=1 (inner)
	// keyptr: key(17) + blockptr(8)，写在 header 之后
	binary.LittleEndian.PutUint64(block[btrfsHeaderSize+btrfsKeySize:btrfsHeaderSize+btrfsKeySize+8], selfLogical)

	img := make([]byte, physOff+int64(len(block)))
	copy(img[physOff:], block)
	sb := &ExtendedSuperblock{
		Superblock: &Superblock{NodeSize: btrfsNodeSize},
		SysChunks: []ChunkMapping{{
			LogicalStart: selfLogical,
			Length:       1 << 20,
			NumStripes:   1,
			Stripes:      []ChunkStripe{{Offset: uint64(physOff)}},
		}},
	}
	reader := testutil.NewMemReader(img)
	err := WalkTree(reader, sb, selfLogical, func(k Key, d []byte) bool { return true })
	if err == nil {
		t.Errorf("自指 inner node 应触发 maxDepth error")
	}
}

// 桥接确认 disk.DiskReader 接口仍然成立（编译期断言）
var _ disk.DiskReader = (*testutil.MemReader)(nil)

// ParseDirItem 单元：单条 entry
func TestParseDirItem_Single(t *testing.T) {
	name := "hello.txt"
	data := make([]byte, 30+len(name))
	binary.LittleEndian.PutUint64(data[0:8], 257) // child objectid
	binary.LittleEndian.PutUint16(data[25:27], 0) // data_len
	binary.LittleEndian.PutUint16(data[27:29], uint16(len(name)))
	data[29] = BTRFS_FT_REG
	copy(data[30:], name)

	entries, err := ParseDirItem(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("应解出 1 条 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.ChildObjectID != 257 || e.Name != name || e.ChildType != BTRFS_FT_REG {
		t.Errorf("entry 字段错: %+v", e)
	}
}

// ParseDirItem 多条 (hash 冲突链)
func TestParseDirItem_MultipleEntries(t *testing.T) {
	build := func(childID uint64, name string, ft uint8) []byte {
		b := make([]byte, 30+len(name))
		binary.LittleEndian.PutUint64(b[0:8], childID)
		binary.LittleEndian.PutUint16(b[27:29], uint16(len(name)))
		b[29] = ft
		copy(b[30:], name)
		return b
	}
	data := append(build(100, "alice.txt", BTRFS_FT_REG), build(200, "bob.txt", BTRFS_FT_REG)...)
	entries, err := ParseDirItem(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("应解 2 条, got %d", len(entries))
	}
	if entries[0].Name != "alice.txt" || entries[1].Name != "bob.txt" {
		t.Errorf("entries: %+v", entries)
	}
}

// BuildPathMap：构造 root → "subdir" → "file.txt" 三层 + 验证完整路径还原
func TestBuildPathMap_NestedDirs(t *testing.T) {
	// root (256) → "subdir" (257)
	// subdir (257) → "file.txt" (258)
	mkDirEntry := func(childID uint64, name string, ft uint8) []byte {
		b := make([]byte, 30+len(name))
		binary.LittleEndian.PutUint64(b[0:8], childID)
		binary.LittleEndian.PutUint16(b[27:29], uint16(len(name)))
		b[29] = ft
		copy(b[30:], name)
		return b
	}
	// items 必须按 key 顺序：(objectid, type, offset)
	items := []LeafItem{
		{Key: Key{ObjectID: FSTreeRootObjectID, Type: keyTypeDirItem, Offset: 1}},
		{Key: Key{ObjectID: 257, Type: keyTypeDirItem, Offset: 1}},
	}
	payloads := [][]byte{
		mkDirEntry(257, "subdir", BTRFS_FT_DIR),
		mkDirEntry(258, "file.txt", BTRFS_FT_REG),
	}
	leaf := buildLeafBlock(t, items, payloads)
	const physOff = int64(1024 * 1024)
	const logical = uint64(0x10000)
	img := make([]byte, physOff+int64(len(leaf)))
	copy(img[physOff:], leaf)
	sb := &ExtendedSuperblock{
		Superblock: &Superblock{NodeSize: btrfsNodeSize},
		SysChunks: []ChunkMapping{{
			LogicalStart: logical, Length: 1 << 20, NumStripes: 1,
			Stripes: []ChunkStripe{{Offset: uint64(physOff)}},
		}},
	}
	reader := testutil.NewMemReader(img)
	paths, err := BuildPathMap(reader, sb, logical)
	if err != nil {
		t.Fatal(err)
	}
	if got := paths[257]; got != "/subdir" {
		t.Errorf("subdir path = %q, want /subdir", got)
	}
	if got := paths[258]; got != "/subdir/file.txt" {
		t.Errorf("file.txt path = %q, want /subdir/file.txt", got)
	}
}

// 损坏 dir item（声称的 nameLen 越界）应被静默跳过
func TestParseDirItem_CorruptNameLen(t *testing.T) {
	data := make([]byte, 30)
	binary.LittleEndian.PutUint64(data[0:8], 100)
	binary.LittleEndian.PutUint16(data[27:29], 9999) // 远超剩余长度
	entries, err := ParseDirItem(data)
	if err != nil {
		t.Fatalf("不应 error，应返回空: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("应跳过损坏 entry, got %d", len(entries))
	}
}
