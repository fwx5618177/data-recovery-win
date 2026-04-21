package ext4

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"data-recovery/internal/disk"
)

// inode 模式（i_mode）的文件类型字段（高 4 位）
const (
	imodeRegular uint16 = 0x8000
	imodeDir     uint16 = 0x4000
	imodeSymlink uint16 = 0xA000
	imodeFifo    uint16 = 0x1000
	imodeChar    uint16 = 0x2000
	imodeBlock   uint16 = 0x6000
	imodeSocket  uint16 = 0xC000

	imodeTypeMask uint16 = 0xF000
)

// Inode 索引节点 —— 一个文件 / 目录 / 链接的元数据中心。
//
// 字段（按 ext4 spec，128-byte rev0 + 后续扩展字段）：
//
//	+0x00  i_mode             uint16  类型 + 权限
//	+0x02  i_uid_lo           uint16
//	+0x04  i_size_lo          uint32  文件大小低 32 位
//	+0x08  i_atime            uint32
//	+0x0C  i_ctime            uint32
//	+0x10  i_mtime            uint32
//	+0x14  i_dtime            uint32  删除时间（非零 = 已删除文件）
//	+0x18  i_gid_lo           uint16
//	+0x1A  i_links_count      uint16  硬链接数（删除后清 0）
//	+0x1C  i_blocks_lo        uint32  占用 512 字节扇区数（注意是扇区不是块）
//	+0x20  i_flags            uint32  bit 19 = use extents
//	+0x28  i_block[15]        60 字节  data pointers / extent header
//	+0x68  i_size_hi          uint32  ext4 文件大小高 32 位
//	(后续字段省略)
type Inode struct {
	Number          uint64
	Mode            uint16
	IsDirectory     bool
	IsRegularFile   bool
	IsSymlink       bool
	IsDeleted       bool   // dtime != 0
	LinksCount      uint16
	Size            int64
	AccessTime      time.Time
	ChangeTime      time.Time
	ModifyTime      time.Time
	DeleteTime      time.Time
	BlockCount512   uint64 // 占用 512 字节扇区数
	Flags           uint32
	UseExtents      bool

	// 60 字节 i_block 区域的原始内容（extent tree header / indirect block 起点都在这）
	BlockField [60]byte
}

// InodeReader 把"按 inode 号读 inode"封装好（涉及块组定位 + inode 表偏移计算）
type InodeReader struct {
	reader      disk.DiskReader
	sb          *SuperBlock
	groupDescs  []GroupDesc
}

func NewInodeReader(reader disk.DiskReader, sb *SuperBlock, groupDescs []GroupDesc) *InodeReader {
	return &InodeReader{reader: reader, sb: sb, groupDescs: groupDescs}
}

// ReadInode 读取给定 inode 号的元数据。
//
// inode 号是 1-based（root 目录 = 2）。inode 在第 (inum-1) / InodesPerGroup 个块组的
// inode 表里，组内偏移 = (inum-1) % InodesPerGroup * InodeSize。
func (ir *InodeReader) ReadInode(inum uint64) (*Inode, error) {
	if inum == 0 {
		return nil, fmt.Errorf("inode 号 0 不合法")
	}
	if inum-1 >= uint64(ir.sb.InodesPerGroup)*uint64(len(ir.groupDescs)) {
		return nil, fmt.Errorf("inode 号 %d 超出范围", inum)
	}

	groupIndex := (inum - 1) / uint64(ir.sb.InodesPerGroup)
	offsetInGroup := (inum - 1) % uint64(ir.sb.InodesPerGroup)

	if groupIndex >= uint64(len(ir.groupDescs)) {
		return nil, fmt.Errorf("group 索引越界: %d", groupIndex)
	}
	gd := ir.groupDescs[groupIndex]

	inodeAbsByte := ir.sb.BlockToByteOffset(gd.InodeTable) + int64(offsetInGroup)*int64(ir.sb.InodeSize)
	buf := make([]byte, ir.sb.InodeSize)
	n, err := ir.reader.ReadAt(buf, inodeAbsByte)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 inode %d 失败: %w", inum, err)
	}
	if n < int(ir.sb.InodeSize) {
		return nil, fmt.Errorf("inode %d 数据不足: %d", inum, n)
	}

	in := &Inode{
		Number:        inum,
		Mode:          binary.LittleEndian.Uint16(buf[0x00:0x02]),
		Size:          int64(binary.LittleEndian.Uint32(buf[0x04:0x08])),
		LinksCount:    binary.LittleEndian.Uint16(buf[0x1A:0x1C]),
		BlockCount512: uint64(binary.LittleEndian.Uint32(buf[0x1C:0x20])),
		Flags:         binary.LittleEndian.Uint32(buf[0x20:0x24]),
	}
	// 时间戳
	atime := binary.LittleEndian.Uint32(buf[0x08:0x0C])
	ctime := binary.LittleEndian.Uint32(buf[0x0C:0x10])
	mtime := binary.LittleEndian.Uint32(buf[0x10:0x14])
	dtime := binary.LittleEndian.Uint32(buf[0x14:0x18])
	if atime > 0 {
		in.AccessTime = time.Unix(int64(atime), 0)
	}
	if ctime > 0 {
		in.ChangeTime = time.Unix(int64(ctime), 0)
	}
	if mtime > 0 {
		in.ModifyTime = time.Unix(int64(mtime), 0)
	}
	if dtime > 0 {
		in.DeleteTime = time.Unix(int64(dtime), 0)
		in.IsDeleted = true
	}

	// ext4 高 32 位文件大小
	if ir.sb.Variant == VariantEXT4 && len(buf) >= 0x6C {
		sizeHi := binary.LittleEndian.Uint32(buf[0x6C:0x70])
		in.Size |= int64(sizeHi) << 32
	}

	// 解析 mode 类型
	switch in.Mode & imodeTypeMask {
	case imodeRegular:
		in.IsRegularFile = true
	case imodeDir:
		in.IsDirectory = true
	case imodeSymlink:
		in.IsSymlink = true
	}

	// extent 标志
	in.UseExtents = in.Flags&0x80000 != 0 // EXT4_EXTENTS_FL = 0x80000

	copy(in.BlockField[:], buf[0x28:0x28+60])

	return in, nil
}
