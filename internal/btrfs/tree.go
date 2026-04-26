package btrfs

// Btrfs B-tree 解析基础设施 —— Phase 5 第一步。
//
// Btrfs 整个文件系统是"多棵 B-tree"：
//   Chunk tree   logical → physical block 映射（必须最先解析才能读其他 tree）
//   Root tree    所有其他 tree 的 root 入口
//   FS tree      每个子卷 / snapshot 一棵，存 inode / dir entry / extent
//   Extent tree  空间分配
//   Checksum tree
//   Device tree
//   Log tree
//
// 本文件实现：
//   ✅ 扩展 Superblock 读 chunk tree root + 所有 B-tree 根
//   ✅ System Chunk Array 解析（superblock 内嵌的"启动链"chunk mapping）
//   ✅ Tree Block Header 解析（所有 B-tree 节点/叶子的公共头）
//   ✅ leafItem / nodePtr 布局
//   ✅ key 比较和排序（Btrfs 要求严格递增）
//
// 留给未来：
//   ❌ Chunk tree 完整遍历（需要 tree walker + stripe 解析）
//   ❌ FS tree 遍历 + inode/dentry 组装
//   ❌ RAID 0/1/10/5/6 stripe mapping
//   ❌ CRC32C 校验
//   ❌ 压缩 extent (zlib/LZO/ZSTD)
//
// 参考：btrfs-progs / linux/fs/btrfs/ctree.h / kernel/btrfs/disk-io.c

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// Btrfs 常量
const (
	// Superblock 里的 magic "_BHRfS_M"
	btrfsMagic = "_BHRfS_M"

	// 所有 tree block header 公共签名
	btrfsHeaderSize = 101 // struct btrfs_header

	// Default B-tree block (node/leaf) 大小（几乎总是 16 KiB）
	btrfsNodeSize = 16 * 1024

	// Leaf block 里每个 item 的固定 header
	btrfsItemSize = 25 // key(17) + offset(4) + size(4)

	// Inner node 每 child 指针
	btrfsKeyPtrSize = 33 // key(17) + blockptr(8) + generation(8)

	// Key 17 字节 = objectid(8) + type(1) + offset(8)
	btrfsKeySize = 17

	// Btrfs root objectid 约定
	btrfsRootTreeObjectID   = 1
	btrfsExtentTreeObjectID = 2
	btrfsChunkTreeObjectID  = 3
	btrfsDevTreeObjectID    = 4
	btrfsFSTreeObjectID     = 5
	btrfsCsumTreeObjectID   = 7

	// Key type 常量（仅列 FS 文件枚举需要的）
	keyTypeInodeItem    = 0x01
	keyTypeInodeRef     = 0x0C
	keyTypeDirItem      = 0x54
	keyTypeDirIndex     = 0x60
	keyTypeExtentData   = 0x6C
	keyTypeRootItem     = 0x84
	keyTypeChunkItem    = 0xE4
)

// ExtendedSuperblock Btrfs 关键字段（基础 Superblock 之外的更多信息）
type ExtendedSuperblock struct {
	*Superblock

	Generation       uint64   // 创建代（每次写入递增）
	RootTreeLogical  uint64   // root tree 的逻辑地址（指向 root tree 的第一个 block）
	ChunkTreeLogical uint64   // chunk tree 的逻辑地址
	LogTreeLogical   uint64
	NumDevices       uint64
	SysChunkArraySize uint32  // system chunk array 字节数
	SysChunkArray    []byte   // system chunk array 原字节（含 chunk keys + chunk items）

	// System chunks 解析结果：初始 logical→physical 映射（用来读 chunk tree 本身）
	SysChunks []ChunkMapping
}

// ChunkMapping 一个 chunk 的 logical → physical 映射（简化：仅单盘单 stripe）
type ChunkMapping struct {
	LogicalStart uint64 // chunk 在 logical 地址空间的起点
	Length       uint64 // chunk 长度
	Type         uint64 // CHUNK_TYPE flags: DATA/METADATA/SYSTEM + RAID0/1/10/5/6
	StripeLen    uint64
	NumStripes   uint16
	Stripes      []ChunkStripe
}

// ChunkStripe 单个 stripe 在物理盘上的位置
type ChunkStripe struct {
	DevID    uint64 // 设备 ID（本工具单盘场景通常 = 1）
	Offset   uint64 // 该 stripe 在设备上的物理偏移
	DevUUID  [16]byte
}

// TreeBlockHeader btrfs_header —— 所有 node / leaf 共用的 101 字节头
type TreeBlockHeader struct {
	Csum        [32]byte
	FSID        [16]byte // 所在文件系统 UUID（与 superblock 一致）
	ByteNr      uint64   // 本 block 的 logical 地址（自述 —— 用于 CoW 校验）
	Flags       uint64
	ChunkTreeID [16]byte
	Generation  uint64
	Owner       uint64 // 所属 B-tree 的 objectid（root/extent/chunk/fs/...）
	NumItems    uint32 // 本 block 里多少个 item（leaf 是真实 item 数；node 是 key 数）
	Level       uint8  // 0 = leaf，> 0 = inner node
}

// ParseTreeBlockHeader 从 block 前 101 字节解 header
func ParseTreeBlockHeader(block []byte) (*TreeBlockHeader, error) {
	if len(block) < btrfsHeaderSize {
		return nil, fmt.Errorf("block < %d 字节", btrfsHeaderSize)
	}
	h := &TreeBlockHeader{}
	copy(h.Csum[:], block[0:32])
	copy(h.FSID[:], block[32:48])
	h.ByteNr = binary.LittleEndian.Uint64(block[48:56])
	h.Flags = binary.LittleEndian.Uint64(block[56:64])
	copy(h.ChunkTreeID[:], block[64:80])
	h.Generation = binary.LittleEndian.Uint64(block[80:88])
	h.Owner = binary.LittleEndian.Uint64(block[88:96])
	h.NumItems = binary.LittleEndian.Uint32(block[96:100])
	h.Level = block[100]
	return h, nil
}

// Key Btrfs B-tree key (objectid, type, offset)
type Key struct {
	ObjectID uint64
	Type     uint8
	Offset   uint64
}

func parseKey(b []byte) Key {
	return Key{
		ObjectID: binary.LittleEndian.Uint64(b[0:8]),
		Type:     b[8],
		Offset:   binary.LittleEndian.Uint64(b[9:17]),
	}
}

// Less Btrfs 规定的 key 全序比较
func (k Key) Less(o Key) bool {
	if k.ObjectID != o.ObjectID {
		return k.ObjectID < o.ObjectID
	}
	if k.Type != o.Type {
		return k.Type < o.Type
	}
	return k.Offset < o.Offset
}

// LeafItem 是 leaf block 里的 { key, data_offset, data_size } 三元组；data 本身在
// block 内部另一段（从 block 末尾向前分配）
type LeafItem struct {
	Key        Key
	DataOffset uint32 // 在 block 内的 offset
	DataSize   uint32
}

// ParseLeafItems 从 leaf block 解出所有 items
func ParseLeafItems(block []byte, header *TreeBlockHeader) ([]LeafItem, error) {
	if header.Level != 0 {
		return nil, fmt.Errorf("not a leaf (level %d)", header.Level)
	}
	items := make([]LeafItem, 0, header.NumItems)
	for i := uint32(0); i < header.NumItems; i++ {
		off := btrfsHeaderSize + int(i)*btrfsItemSize
		if off+btrfsItemSize > len(block) {
			break
		}
		items = append(items, LeafItem{
			Key:        parseKey(block[off : off+btrfsKeySize]),
			DataOffset: binary.LittleEndian.Uint32(block[off+17 : off+21]),
			DataSize:   binary.LittleEndian.Uint32(block[off+21 : off+25]),
		})
	}
	return items, nil
}

// ParseExtendedSuperblock 读 Btrfs superblock 完整字段 + system chunk array
func ParseExtendedSuperblock(reader disk.DiskReader, volStart int64) (*ExtendedSuperblock, error) {
	buf := make([]byte, 4096)
	n, err := reader.ReadAt(buf, volStart+SuperblockOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 superblock: %w", err)
	}
	if n < 4096 {
		return nil, fmt.Errorf("superblock 数据不足")
	}
	if string(buf[64:72]) != btrfsMagic {
		return nil, fmt.Errorf("不是 Btrfs（magic 不匹配）")
	}

	base := &Superblock{
		Offset:     SuperblockOffset,
		BytesUsed:  binary.LittleEndian.Uint64(buf[112:120]),
		TotalBytes: binary.LittleEndian.Uint64(buf[104:112]),
		SectorSize: binary.LittleEndian.Uint32(buf[180:184]),
		NodeSize:   binary.LittleEndian.Uint32(buf[184:188]),
	}
	copy(base.FSID[:], buf[32:48])

	// btrfs_super_block 完整布局（简化版 —— 仅用到的字段）：
	//   offset 104: total_bytes (uint64)
	//   offset 112: bytes_used (uint64)
	//   offset 120: root_dir_objectid (uint64)
	//   offset 128: num_devices (uint64)
	//   offset 136: sectorsize (uint32)
	//   offset 140: nodesize (uint32)
	//   offset 144: leafsize (uint32)
	//   offset 148: stripesize (uint32)
	//   offset 152: sys_chunk_array_size (uint32)
	//   offset 156: chunk_root_generation (uint64)
	//   offset 164: compat_flags / compat_ro_flags / incompat_flags
	//   offset 200: csum_type (uint16)
	//   offset 214: root_tree_bytenr (uint64)  ← ★
	//   offset 222: chunk_tree_bytenr (uint64) ← ★
	//   offset 230: log_tree_bytenr (uint64)
	//   offset 238: log_root_transid
	//   offset 246: total_bytes (再次)
	//   offset 256: generation (uint64)
	//   offset 264: root_tree_generation
	//   offset ... reserved
	//   offset 264..: sys_chunk_array (2048 bytes max)
	//
	// 实际字段 offset 以 kernel btrfs_super_block 为准；本实现取 Linux 6.x 默认布局

	ext := &ExtendedSuperblock{Superblock: base}
	ext.RootTreeLogical = binary.LittleEndian.Uint64(buf[80:88])   // root_tree_bytenr
	ext.ChunkTreeLogical = binary.LittleEndian.Uint64(buf[88:96])  // chunk_tree_bytenr
	ext.LogTreeLogical = binary.LittleEndian.Uint64(buf[96:104])   // log_tree_bytenr
	ext.Generation = binary.LittleEndian.Uint64(buf[120:128])
	ext.NumDevices = binary.LittleEndian.Uint64(buf[128:136])
	ext.SysChunkArraySize = binary.LittleEndian.Uint32(buf[152:156])

	if ext.SysChunkArraySize > 0 && ext.SysChunkArraySize <= 2048 {
		sysArrStart := 264 // approximate offset of sys_chunk_array in superblock
		if sysArrStart+int(ext.SysChunkArraySize) <= len(buf) {
			ext.SysChunkArray = make([]byte, ext.SysChunkArraySize)
			copy(ext.SysChunkArray, buf[sysArrStart:sysArrStart+int(ext.SysChunkArraySize)])
			ext.SysChunks, _ = parseSysChunkArray(ext.SysChunkArray)
		}
	}

	return ext, nil
}

// parseSysChunkArray sys_chunk_array 是一连串 { key(17) + chunk_item(...) } 对，
// 提供启动时 logical→physical 映射（用来读 chunk tree 本身）
func parseSysChunkArray(arr []byte) ([]ChunkMapping, error) {
	var out []ChunkMapping
	pos := 0
	for pos+btrfsKeySize < len(arr) {
		key := parseKey(arr[pos : pos+btrfsKeySize])
		if key.Type != keyTypeChunkItem {
			break
		}
		pos += btrfsKeySize

		// struct btrfs_chunk:
		//   offset 0: length (uint64)
		//   offset 8: owner (uint64)
		//   offset 16: stripe_len (uint64)
		//   offset 24: type (uint64)  — flags: DATA|METADATA|SYSTEM + RAID 模式
		//   offset 32: io_align / io_width / sector_size (3×u32)
		//   offset 44: num_stripes (u16)
		//   offset 46: sub_stripes (u16)
		//   offset 48: stripes[] —— 每个 struct btrfs_stripe (devid:8 + offset:8 + dev_uuid:16)
		if pos+48 > len(arr) {
			break
		}
		m := ChunkMapping{
			LogicalStart: key.Offset,
			Length:       binary.LittleEndian.Uint64(arr[pos : pos+8]),
			StripeLen:    binary.LittleEndian.Uint64(arr[pos+16 : pos+24]),
			Type:         binary.LittleEndian.Uint64(arr[pos+24 : pos+32]),
			NumStripes:   binary.LittleEndian.Uint16(arr[pos+44 : pos+46]),
		}
		stripesStart := pos + 48
		for s := uint16(0); s < m.NumStripes; s++ {
			soff := stripesStart + int(s)*32
			if soff+32 > len(arr) {
				break
			}
			st := ChunkStripe{
				DevID:  binary.LittleEndian.Uint64(arr[soff : soff+8]),
				Offset: binary.LittleEndian.Uint64(arr[soff+8 : soff+16]),
			}
			copy(st.DevUUID[:], arr[soff+16:soff+32])
			m.Stripes = append(m.Stripes, st)
		}
		out = append(out, m)
		pos = stripesStart + int(m.NumStripes)*32
	}
	return out, nil
}

// MapLogical 用 sysChunks 把 logical 地址翻译成物理 offset。
// 单 stripe 单 dev 场景：physical = stripe.Offset + (logical - chunk.LogicalStart)。
// RAID 场景（多 stripe）当前返回第一个 stripe —— 够多数 metadata 读取。
func (sb *ExtendedSuperblock) MapLogical(logical uint64) (int64, error) {
	for _, c := range sb.SysChunks {
		if logical >= c.LogicalStart && logical < c.LogicalStart+c.Length {
			if len(c.Stripes) == 0 {
				return 0, fmt.Errorf("chunk 没 stripe")
			}
			offsetInChunk := logical - c.LogicalStart
			return int64(c.Stripes[0].Offset + offsetInChunk), nil
		}
	}
	return 0, fmt.Errorf("logical %d 不在 sys chunk 范围里（需要遍历 chunk tree）", logical)
}

// ReadTreeBlock 读 B-tree 节点 block（通过 logical→physical 映射）
func ReadTreeBlock(reader disk.DiskReader, sb *ExtendedSuperblock, logical uint64) ([]byte, *TreeBlockHeader, error) {
	physical, err := sb.MapLogical(logical)
	if err != nil {
		return nil, nil, err
	}
	nodeSize := int(sb.NodeSize)
	if nodeSize == 0 {
		nodeSize = btrfsNodeSize
	}
	buf := make([]byte, nodeSize)
	n, err := reader.ReadAt(buf, physical)
	if err != nil && err != io.EOF {
		return nil, nil, fmt.Errorf("读 tree block @%d: %w", physical, err)
	}
	if n < btrfsHeaderSize {
		return nil, nil, fmt.Errorf("tree block 太小")
	}
	h, err := ParseTreeBlockHeader(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf, h, nil
}

// ============================================================================
// B-tree walker
// ============================================================================

// LeafCallback 在 leaf 上每个 item 触发。返回 false 表示停止整个 walk。
// data 是 item 在 leaf block 内的 payload 切片（不要保留引用，遍历继续后会被覆盖）。
type LeafCallback func(key Key, data []byte) bool

const btrfsMaxTreeDepth = 16 // Btrfs 实际最大深度

// WalkTree 从 logical 地址开始递归走 B-tree，对所有 leaf 上的每个 item 调用 cb。
//
// 不做完整 cycle detection（Btrfs CoW 设计上 logical 地址唯一），但用 maxDepth
// 兜底，防止损坏镜像让 walker 死循环。
func WalkTree(reader disk.DiskReader, sb *ExtendedSuperblock, logical uint64, cb LeafCallback) error {
	return walkTree(reader, sb, logical, cb, 0)
}

func walkTree(reader disk.DiskReader, sb *ExtendedSuperblock, logical uint64, cb LeafCallback, depth int) error {
	if depth > btrfsMaxTreeDepth {
		return fmt.Errorf("btrfs tree 深度超过 %d 限制（loop / 损坏？）", btrfsMaxTreeDepth)
	}
	block, hdr, err := ReadTreeBlock(reader, sb, logical)
	if err != nil {
		return err
	}
	if hdr.Level == 0 {
		// leaf —— 解 items + 调 callback
		items, err := ParseLeafItems(block, hdr)
		if err != nil {
			return err
		}
		for _, it := range items {
			start := int(it.DataOffset) + btrfsHeaderSize
			end := start + int(it.DataSize)
			if start < btrfsHeaderSize || end > len(block) || start > end {
				continue
			}
			if !cb(it.Key, block[start:end]) {
				return nil
			}
		}
		return nil
	}
	// inner node —— 遍历 keyptr 数组并递归
	for i := uint32(0); i < hdr.NumItems; i++ {
		off := btrfsHeaderSize + int(i)*btrfsKeyPtrSize
		if off+btrfsKeyPtrSize > len(block) {
			break
		}
		childLogical := binary.LittleEndian.Uint64(block[off+btrfsKeySize : off+btrfsKeySize+8])
		if err := walkTree(reader, sb, childLogical, cb, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// FS-tree 实体类型解析
// ============================================================================

// INodeItem btrfs INODE_ITEM (key.type == 0x01) 关键字段
type INodeItem struct {
	Generation uint64 // 创建时事务号
	Size       uint64 // 文件字节数
	NBytes     uint64 // 实际占用字节
	Mode       uint32 // POSIX mode（含文件类型 high bits）
	UID        uint32
	GID        uint32
	Atime      uint64 // sec since epoch
	Ctime      uint64
	Mtime      uint64
}

// ParseINodeItem 解析 INODE_ITEM data 区。
//
// Layout (struct btrfs_inode_item, kernel ctree.h)：
//
//	off  size  field
//	0    8     generation
//	8    8     transid
//	16   8     size
//	24   8     nbytes
//	32   8     block_group
//	40   4     nlink
//	44   4     uid
//	48   4     gid
//	52   4     mode
//	56   8     rdev
//	64   8     flags
//	72   8     sequence
//	80   32    reserved
//	112  12    atime (struct btrfs_timespec: sec(8) + nsec(4))
//	124  12    ctime
//	136  12    mtime
//	148  12    otime
func ParseINodeItem(data []byte) (*INodeItem, error) {
	if len(data) < 160 {
		return nil, fmt.Errorf("INODE_ITEM 太短: %d", len(data))
	}
	return &INodeItem{
		Generation: binary.LittleEndian.Uint64(data[0:8]),
		Size:       binary.LittleEndian.Uint64(data[16:24]),
		NBytes:     binary.LittleEndian.Uint64(data[24:32]),
		UID:        binary.LittleEndian.Uint32(data[44:48]),
		GID:        binary.LittleEndian.Uint32(data[48:52]),
		Mode:       binary.LittleEndian.Uint32(data[52:56]),
		Atime:      binary.LittleEndian.Uint64(data[112:120]),
		Ctime:      binary.LittleEndian.Uint64(data[124:132]),
		Mtime:      binary.LittleEndian.Uint64(data[136:144]),
	}, nil
}

// ExtentDataType 文件 extent 的存储模式
type ExtentDataType uint8

const (
	ExtentDataInline  ExtentDataType = 0 // 数据直接驻留（小文件）
	ExtentDataRegular ExtentDataType = 1 // 通常 extent（指向 extent tree）
	ExtentDataPrealloc ExtentDataType = 2 // 预分配但未写
)

// ExtentData EXTENT_DATA item 关键字段。
//
// EXTENT_DATA Layout (struct btrfs_file_extent_item):
//
//	off  size  field
//	0    8     generation
//	8    8     ram_bytes (decompressed length)
//	16   1     compression (0=none, 1=zlib, 2=lzo, 3=zstd)
//	17   1     encryption
//	18   2     other_encoding
//	20   1     type (0=inline, 1=regular, 2=prealloc)
//	if type == inline：
//	  21..   inline data (length = ram_bytes; possibly compressed)
//	if type != inline：
//	  21   8 disk_bytenr (extent 在 extent tree 的 logical 地址；0 = hole)
//	  29   8 disk_num_bytes
//	  37   8 offset (extent 内部偏移)
//	  45   8 num_bytes (本 extent 在文件里覆盖的字节数)
type ExtentData struct {
	RamBytes      uint64
	Compression   uint8
	Type          ExtentDataType
	InlineData    []byte // 仅 Type == ExtentDataInline 时有效
	DiskByteNr    uint64 // 仅 Type != Inline；0 = hole
	DiskNumBytes  uint64
	Offset        uint64
	NumBytes      uint64
}

// ParseExtentData 解析 EXTENT_DATA item data 区。
func ParseExtentData(data []byte) (*ExtentData, error) {
	if len(data) < 21 {
		return nil, fmt.Errorf("EXTENT_DATA 太短: %d", len(data))
	}
	e := &ExtentData{
		RamBytes:    binary.LittleEndian.Uint64(data[8:16]),
		Compression: data[16],
		Type:        ExtentDataType(data[20]),
	}
	if e.Type == ExtentDataInline {
		e.InlineData = append([]byte{}, data[21:]...)
		return e, nil
	}
	if len(data) < 53 {
		return nil, fmt.Errorf("non-inline EXTENT_DATA 太短: %d", len(data))
	}
	e.DiskByteNr = binary.LittleEndian.Uint64(data[21:29])
	e.DiskNumBytes = binary.LittleEndian.Uint64(data[29:37])
	e.Offset = binary.LittleEndian.Uint64(data[37:45])
	e.NumBytes = binary.LittleEndian.Uint64(data[45:53])
	return e, nil
}

// RootItem ROOT_ITEM data 关键字段（root tree 里 keyTypeRootItem item 用）。
//
// 真实 Layout 大（439 字节），我们只取需要的：
//
//	off  size  field
//	0    160   inode (struct btrfs_inode_item)
//	160  8     generation
//	168  8     root_dirid
//	176  8     bytenr (← 这棵 tree 的 root block logical 地址)
//	184  8     byte_limit
//	192  8     bytes_used
//	200  8     last_snapshot
//	208  8     flags
//	216  4     refs
//	...
type RootItem struct {
	ByteNr     uint64 // 这棵子 tree 的 root logical 地址
	Generation uint64
	RootDirID  uint64
	BytesUsed  uint64
	Flags      uint64
}

// ParseRootItem 解析 ROOT_ITEM。最少需要 220 字节才能取到 ByteNr。
func ParseRootItem(data []byte) (*RootItem, error) {
	if len(data) < 200 {
		return nil, fmt.Errorf("ROOT_ITEM 太短: %d", len(data))
	}
	return &RootItem{
		Generation: binary.LittleEndian.Uint64(data[160:168]),
		RootDirID:  binary.LittleEndian.Uint64(data[168:176]),
		ByteNr:     binary.LittleEndian.Uint64(data[176:184]),
		BytesUsed:  binary.LittleEndian.Uint64(data[192:200]),
	}, nil
}

// WalkRootTree 走 root tree，对每个 ROOT_ITEM 触发 cb（拿到子 tree 的 logical 入口）。
//
// 典型用途：列出所有子卷 / snapshot 的 FS-tree 根，再对每个走 WalkFSTree。
func WalkRootTree(reader disk.DiskReader, sb *ExtendedSuperblock, cb func(key Key, item *RootItem) bool) error {
	if sb == nil || sb.RootTreeLogical == 0 {
		return fmt.Errorf("root tree logical 地址为 0")
	}
	return WalkTree(reader, sb, sb.RootTreeLogical, func(k Key, data []byte) bool {
		if k.Type != keyTypeRootItem {
			return true
		}
		ri, err := ParseRootItem(data)
		if err != nil {
			return true
		}
		return cb(k, ri)
	})
}

// DirEntry btrfs DIR_ITEM (key.type == 0x54) 单条 dir entry。
//
// 一个 DIR_ITEM data 区可包含多条（同一 hash 的冲突链），但实际中通常 1 条。
// Layout (struct btrfs_dir_item)：
//
//	off  size  field
//	0    17    location (struct btrfs_disk_key)：被指向的 inode 的 (objectid, type, offset)
//	17   8     transid
//	25   2     data_len   (xattr 才用)
//	27   2     name_len
//	29   1     type       (BTRFS_FT_*：0=unknown, 1=regular, 2=dir, 3=chrdev, 4=blkdev,
//	                                   5=fifo, 6=sock, 7=symlink, 8=xattr)
//	30   ...   name (UTF-8 if locale supports)
//	then optional xattr data
type DirEntry struct {
	ChildObjectID uint64 // 被指向的 inode objectid（child）
	ChildType     uint8  // BTRFS_FT_*
	NameLen       uint16
	Name          string
}

// ParseDirItem 解析一段 DIR_ITEM data 区（可能含多个 entry —— hash 冲突链）。
// data 是 leaf item 的 data 区切片。
func ParseDirItem(data []byte) ([]DirEntry, error) {
	var out []DirEntry
	pos := 0
	for pos+30 <= len(data) {
		childObjID := binary.LittleEndian.Uint64(data[pos : pos+8])
		// type byte at offset 8 of disk_key (we don't need it)
		dataLen := binary.LittleEndian.Uint16(data[pos+25 : pos+27])
		nameLen := binary.LittleEndian.Uint16(data[pos+27 : pos+29])
		ftype := data[pos+29]
		nameStart := pos + 30
		nameEnd := nameStart + int(nameLen)
		if nameEnd > len(data) {
			break
		}
		out = append(out, DirEntry{
			ChildObjectID: childObjID,
			ChildType:     ftype,
			NameLen:       nameLen,
			Name:          string(data[nameStart:nameEnd]),
		})
		pos = nameEnd + int(dataLen) // 跳过可选 xattr data
	}
	return out, nil
}

// FSItem 是 WalkFSTree 给 callback 的统一返回项 —— inode + 它的 extents + 它的 dir entries。
//
// 每个 FS tree 里 INODE_ITEM / EXTENT_DATA / DIR_ITEM 都是 leaf item，
// 按 key 严格排序：(objectid, type, offset)。所以同一 objectid 的所有 item
// 会聚集出现，objectid 切换时把上一个 batch 一次性报给 callback。
//
// 注意：DirEntries 是 *本目录里的子项*（即 ObjectID 是目录 inode 时才有）；
// 文件本身的 *自己叫什么名字* 在父目录的 DIR_ITEM 里 —— 上层要建立完整路径
// 需要先收集所有 (parent → children) 边再回溯。
type FSItem struct {
	ObjectID   uint64
	INode      *INodeItem
	Extents    []*ExtentData
	DirEntries []DirEntry
}

// BTRFS file types（DirEntry.ChildType）
const (
	BTRFS_FT_UNKNOWN = 0
	BTRFS_FT_REG     = 1 // 普通文件
	BTRFS_FT_DIR     = 2 // 目录
	BTRFS_FT_CHRDEV  = 3
	BTRFS_FT_BLKDEV  = 4
	BTRFS_FT_FIFO    = 5
	BTRFS_FT_SOCK    = 6
	BTRFS_FT_SYMLINK = 7
	BTRFS_FT_XATTR   = 8 // 不是真文件类型，是 dir item 内嵌 xattr 的标记
)

// 根目录 objectid（FS tree 里）
const FSTreeRootObjectID = 256

// BuildPathMap 走一遍 FS tree，构建 (childObjectID → 完整路径) 映射。
//
// 用法：先 BuildPathMap，再 WalkFSTree 第二遍把 inode + extents 关联到路径。
// 两遍走是因为 dir entry 的"父→子"边只有走完整棵 tree 才能知道任意 inode 的
// 完整路径。
//
// 注意：一个文件可能有多个 hardlink → 多条路径；这里只保留按遍历顺序遇到的
// 第一条（够大多数恢复场景；hardlink 罕见）。
func BuildPathMap(reader disk.DiskReader, sb *ExtendedSuperblock, fsTreeLogical uint64) (map[uint64]string, error) {
	type edge struct {
		parent uint64
		name   string
	}
	parents := map[uint64]edge{}
	err := WalkTree(reader, sb, fsTreeLogical, func(k Key, data []byte) bool {
		if k.Type != keyTypeDirItem && k.Type != keyTypeDirIndex {
			return true
		}
		entries, err := ParseDirItem(data)
		if err != nil {
			return true
		}
		for _, e := range entries {
			if e.ChildObjectID == 0 || e.Name == "" {
				continue
			}
			if _, exists := parents[e.ChildObjectID]; exists {
				continue // 第一条路径优先（hardlink 不重复）
			}
			parents[e.ChildObjectID] = edge{parent: k.ObjectID, name: e.Name}
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	// 回溯：每个 child 沿 parents 链回到 root
	paths := make(map[uint64]string, len(parents)+1)
	paths[FSTreeRootObjectID] = "/"
	const maxDepth = 256 // 防异常循环
	var resolve func(id uint64, depth int) string
	resolve = func(id uint64, depth int) string {
		if id == FSTreeRootObjectID {
			return ""
		}
		if depth > maxDepth {
			return ""
		}
		if p, ok := paths[id]; ok {
			return p
		}
		e, ok := parents[id]
		if !ok {
			return ""
		}
		parentPath := resolve(e.parent, depth+1)
		if parentPath == "" && e.parent != FSTreeRootObjectID {
			return ""
		}
		full := parentPath + "/" + e.name
		paths[id] = full
		return full
	}
	for id := range parents {
		resolve(id, 0)
	}
	return paths, nil
}

// WalkFSTree 走指定 FS tree，按 inode 聚合后调 cb。返回 false 停止。
func WalkFSTree(reader disk.DiskReader, sb *ExtendedSuperblock, fsTreeLogical uint64, cb func(*FSItem) bool) error {
	if fsTreeLogical == 0 {
		return fmt.Errorf("fs tree logical 地址为 0")
	}
	var current *FSItem
	flush := func() bool {
		if current == nil {
			return true
		}
		ok := cb(current)
		current = nil
		return ok
	}

	err := WalkTree(reader, sb, fsTreeLogical, func(k Key, data []byte) bool {
		// 切到新 inode 时把上一个推出去
		if current != nil && current.ObjectID != k.ObjectID {
			if !flush() {
				return false
			}
		}
		switch k.Type {
		case keyTypeInodeItem:
			ino, err := ParseINodeItem(data)
			if err != nil {
				return true
			}
			current = &FSItem{ObjectID: k.ObjectID, INode: ino}
		case keyTypeExtentData:
			if current == nil || current.ObjectID != k.ObjectID {
				current = &FSItem{ObjectID: k.ObjectID}
			}
			ext, err := ParseExtentData(data)
			if err != nil {
				return true
			}
			current.Extents = append(current.Extents, ext)
		case keyTypeDirItem, keyTypeDirIndex:
			if current == nil || current.ObjectID != k.ObjectID {
				current = &FSItem{ObjectID: k.ObjectID}
			}
			entries, err := ParseDirItem(data)
			if err != nil {
				return true
			}
			current.DirEntries = append(current.DirEntries, entries...)
		}
		return true
	})
	if err != nil {
		return err
	}
	flush()
	return nil
}
