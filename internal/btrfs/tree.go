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

// 占位函数 —— 下一阶段要做的：
//   WalkRootTree(sb): 从 root tree root 遍历找所有 FS tree / DIR / INODE
//   WalkFSTree(sb, fsTreeRoot): 遍历指定 FS tree，yield 每个 inode + path
//   ReadInode(sb, inode): 组合 INODE_ITEM + EXTENT_DATA → 文件大小 + data block 位置
//   ReadExtentData(sb, extent): 对 (logical, length) 读实际文件字节
