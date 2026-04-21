package ext4

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// GroupDesc 块组描述符。
//
// ext2/3 是 32 字节；ext4 + 64bit feature 是 64 字节，多了高 32 位字段。
//
// 字段（按 ext4 spec，64-byte 版本完整）：
//
//	+0x00  bg_block_bitmap_lo       (uint32)  块位图 block 号低 32 位
//	+0x04  bg_inode_bitmap_lo       (uint32)  inode 位图 block 号低 32 位
//	+0x08  bg_inode_table_lo        (uint32)  inode 表 block 号低 32 位 ⭐ 我们最关心
//	+0x0C  bg_free_blocks_count_lo  (uint16)
//	+0x0E  bg_free_inodes_count_lo  (uint16)
//	+0x10  bg_used_dirs_count_lo    (uint16)
//	+0x12  bg_flags                 (uint16)
//	+0x14  bg_exclude_bitmap_lo     (uint32)
//	+0x18  bg_block_bitmap_csum_lo  (uint16)
//	+0x1A  bg_inode_bitmap_csum_lo  (uint16)
//	+0x1C  bg_itable_unused_lo      (uint16)
//	+0x1E  bg_checksum              (uint16)
//	------- 64-byte（64bit feature）---------
//	+0x20  bg_block_bitmap_hi       (uint32)
//	+0x24  bg_inode_bitmap_hi       (uint32)
//	+0x28  bg_inode_table_hi        (uint32) ⭐
//	+0x2C..0x3F: free block hi / free inode hi / dirs hi / itable_unused hi / 余下 csum
type GroupDesc struct {
	BlockBitmap uint64 // 块位图所在块号
	InodeBitmap uint64
	InodeTable  uint64 // inode 表起始块号
	FreeBlocks  uint32
	FreeInodes  uint32
	UsedDirs    uint32
}

// ReadGroupDescriptors 读所有块组描述符。
//
// 描述符表紧跟 superblock 所在块之后；总条目数 = sb.GroupCount。
// 一次性把整个表读进来，避免后续按 inode 号查找时反复 IO。
func ReadGroupDescriptors(reader disk.DiskReader, sb *SuperBlock) ([]GroupDesc, error) {
	if sb.GroupCount == 0 {
		return nil, fmt.Errorf("GroupCount=0")
	}
	totalBytes := int64(sb.GroupDescSize) * int64(sb.GroupCount)
	buf := make([]byte, totalBytes)
	abs := sb.BlockToByteOffset(sb.GroupDescBlock)
	n, err := reader.ReadAt(buf, abs)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读块组描述符表失败: %w", err)
	}
	if int64(n) < totalBytes {
		return nil, fmt.Errorf("块组描述符表读不完整: %d / %d", n, totalBytes)
	}

	out := make([]GroupDesc, sb.GroupCount)
	for i := uint64(0); i < sb.GroupCount; i++ {
		off := int64(i) * int64(sb.GroupDescSize)
		entry := buf[off : off+int64(sb.GroupDescSize)]

		gd := GroupDesc{
			BlockBitmap: uint64(binary.LittleEndian.Uint32(entry[0x00:0x04])),
			InodeBitmap: uint64(binary.LittleEndian.Uint32(entry[0x04:0x08])),
			InodeTable:  uint64(binary.LittleEndian.Uint32(entry[0x08:0x0C])),
			FreeBlocks:  uint32(binary.LittleEndian.Uint16(entry[0x0C:0x0E])),
			FreeInodes:  uint32(binary.LittleEndian.Uint16(entry[0x0E:0x10])),
			UsedDirs:    uint32(binary.LittleEndian.Uint16(entry[0x10:0x12])),
		}

		// 64bit：上半部分在 +0x20 起
		if sb.Has64Bit && sb.GroupDescSize >= 64 {
			gd.BlockBitmap |= uint64(binary.LittleEndian.Uint32(entry[0x20:0x24])) << 32
			gd.InodeBitmap |= uint64(binary.LittleEndian.Uint32(entry[0x24:0x28])) << 32
			gd.InodeTable |= uint64(binary.LittleEndian.Uint32(entry[0x28:0x2C])) << 32
			gd.FreeBlocks |= uint32(binary.LittleEndian.Uint16(entry[0x2C:0x2E])) << 16
			gd.FreeInodes |= uint32(binary.LittleEndian.Uint16(entry[0x2E:0x30])) << 16
			gd.UsedDirs |= uint32(binary.LittleEndian.Uint16(entry[0x30:0x32])) << 16
		}

		out[i] = gd
	}

	return out, nil
}
