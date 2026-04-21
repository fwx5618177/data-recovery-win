package ext4

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// ext4 用 extent tree 取代 ext2/3 的 indirect block 系统。
// 一个 extent = 一段"连续物理块映射"：(starting logical block, length, starting physical block)。
//
// extent header（12 字节）：
//
//	+0  eh_magic    (uint16)  = 0xF30A
//	+2  eh_entries  (uint16)  本节点中条目数
//	+4  eh_max      (uint16)  本节点最多容纳条目数
//	+6  eh_depth    (uint16)  深度（叶子=0；内部=1+）
//	+8  eh_generation (uint32)
//
// 后续是 12 字节条目：
//   - 叶子（depth=0）= ext4_extent：
//       +0  ee_block    (uint32)  起始 logical block
//       +4  ee_len      (uint16)  连续块数（>= 1，初始化时 ≤32768；> 32768 表示未初始化的 extent）
//       +6  ee_start_hi (uint16)  物理块号高 16 位
//       +8  ee_start_lo (uint32)  物理块号低 32 位
//   - 内部（depth>0）= ext4_extent_idx：
//       +0  ei_block    (uint32)  覆盖的 logical 起点
//       +4  ei_leaf_lo  (uint32)  下一层节点物理块号低 32 位
//       +8  ei_leaf_hi  (uint16)
//       +10 ei_unused   (uint16)
//
// 60 字节的 i_block[] 区域：12 字节 header + 4 个条目（48 字节）。

const extentMagic uint16 = 0xF30A

// PhysicalRange 表示文件中一段逻辑块到物理块的映射
type PhysicalRange struct {
	LogicalBlock  uint32 // 文件内逻辑起始块号
	Length        uint32 // 连续块数
	PhysicalBlock uint64 // 磁盘起始物理块号；0 = 稀疏（hole）
}

// extentHeader 解析后的 extent header
type extentHeader struct {
	entries uint16
	depth   uint16
}

// CollectFileBlocks 从一个 inode 出发，把整个文件的所有物理块映射收集出来。
// 自动判断 extent vs indirect block 路径。
//
// 返回的 PhysicalRange 列表按 logical block 递增排序，调用方可根据 file size 做截断。
func CollectFileBlocks(reader disk.DiskReader, sb *SuperBlock, in *Inode) ([]PhysicalRange, error) {
	if in.UseExtents {
		return walkExtentTree(reader, sb, in.BlockField[:])
	}
	return walkIndirectBlocks(reader, sb, in)
}

// walkExtentTree 递归走 extent 树，叶子节点把 (ee_block, ee_len, ee_start) 收成 PhysicalRange
func walkExtentTree(reader disk.DiskReader, sb *SuperBlock, node []byte) ([]PhysicalRange, error) {
	if len(node) < 12 {
		return nil, fmt.Errorf("extent 节点头部不足")
	}
	magic := binary.LittleEndian.Uint16(node[0:2])
	if magic != extentMagic {
		return nil, fmt.Errorf("extent magic 错: 0x%X", magic)
	}
	hdr := extentHeader{
		entries: binary.LittleEndian.Uint16(node[2:4]),
		depth:   binary.LittleEndian.Uint16(node[6:8]),
	}
	// 防恶意输入：限制深度和条目数
	if hdr.depth > 5 || hdr.entries > 1024 {
		return nil, fmt.Errorf("extent 节点异常 depth=%d entries=%d", hdr.depth, hdr.entries)
	}

	var out []PhysicalRange

	for i := uint16(0); i < hdr.entries; i++ {
		entryOff := 12 + int(i)*12
		if entryOff+12 > len(node) {
			break
		}
		entry := node[entryOff : entryOff+12]

		if hdr.depth == 0 {
			// 叶子：ext4_extent
			ee := PhysicalRange{
				LogicalBlock: binary.LittleEndian.Uint32(entry[0:4]),
				Length:       uint32(binary.LittleEndian.Uint16(entry[4:6])),
				PhysicalBlock: uint64(binary.LittleEndian.Uint16(entry[6:8]))<<32 |
					uint64(binary.LittleEndian.Uint32(entry[8:12])),
			}
			// > 32768 表示未初始化（preallocated）的 extent；视作稀疏
			if ee.Length > 32768 {
				ee.Length -= 32768
				ee.PhysicalBlock = 0 // 标记为稀疏
			}
			out = append(out, ee)
		} else {
			// 内部：ext4_extent_idx，下一层指针
			leaf := uint64(binary.LittleEndian.Uint32(entry[4:8])) |
				uint64(binary.LittleEndian.Uint16(entry[8:10]))<<32
			child, err := readBlock(reader, sb, leaf)
			if err != nil {
				continue
			}
			sub, err := walkExtentTree(reader, sb, child)
			if err != nil {
				continue
			}
			out = append(out, sub...)
		}
	}

	return out, nil
}

// walkIndirectBlocks 走 ext2/3 的 12 直接 + 1 一级间接 + 1 二级 + 1 三级 间接块结构。
//
// i_block[0..11] 是 12 个直接物理块号（uint32）
// i_block[12]    指向一级间接块
// i_block[13]    指向二级间接块
// i_block[14]    指向三级间接块
func walkIndirectBlocks(reader disk.DiskReader, sb *SuperBlock, in *Inode) ([]PhysicalRange, error) {
	field := in.BlockField[:]
	pointersPerBlock := uint32(sb.BlockSize) / 4

	var out []PhysicalRange
	var logical uint32

	addBlock := func(physical uint32) {
		if physical == 0 {
			// 稀疏块：保留逻辑块号但物理块为 0
			out = append(out, PhysicalRange{
				LogicalBlock: logical, Length: 1, PhysicalBlock: 0,
			})
		} else {
			out = append(out, PhysicalRange{
				LogicalBlock: logical, Length: 1, PhysicalBlock: uint64(physical),
			})
		}
		logical++
	}

	// 12 个直接块
	for i := 0; i < 12; i++ {
		ptr := binary.LittleEndian.Uint32(field[i*4 : i*4+4])
		addBlock(ptr)
	}

	// 一级间接（如果存在）
	indirect1 := binary.LittleEndian.Uint32(field[12*4 : 13*4])
	if indirect1 != 0 {
		walkIndirect(reader, sb, uint64(indirect1), 1, &logical, &out, pointersPerBlock)
	}
	// 二级间接
	indirect2 := binary.LittleEndian.Uint32(field[13*4 : 14*4])
	if indirect2 != 0 {
		walkIndirect(reader, sb, uint64(indirect2), 2, &logical, &out, pointersPerBlock)
	}
	// 三级间接
	indirect3 := binary.LittleEndian.Uint32(field[14*4 : 15*4])
	if indirect3 != 0 {
		walkIndirect(reader, sb, uint64(indirect3), 3, &logical, &out, pointersPerBlock)
	}

	return out, nil
}

// walkIndirect 递归走 N 级间接块。每级间接块包含 pointersPerBlock 个 uint32 指针。
// 0-pointer 视为稀疏块，仍然占一个逻辑位置（保持 logical block 编号正确）。
func walkIndirect(
	reader disk.DiskReader, sb *SuperBlock,
	blockNum uint64, level int,
	logical *uint32, out *[]PhysicalRange, perBlock uint32,
) {
	data, err := readBlock(reader, sb, blockNum)
	if err != nil {
		return
	}
	for i := uint32(0); i < perBlock; i++ {
		off := i * 4
		if off+4 > uint32(len(data)) {
			break
		}
		ptr := binary.LittleEndian.Uint32(data[off : off+4])
		if level == 1 {
			if ptr == 0 {
				*out = append(*out, PhysicalRange{LogicalBlock: *logical, Length: 1})
			} else {
				*out = append(*out, PhysicalRange{LogicalBlock: *logical, Length: 1, PhysicalBlock: uint64(ptr)})
			}
			*logical++
		} else {
			if ptr != 0 {
				walkIndirect(reader, sb, uint64(ptr), level-1, logical, out, perBlock)
			} else {
				// 稀疏的间接块：跳过一整片虚拟逻辑块
				skip := uint32(1)
				for k := 1; k < level; k++ {
					skip *= perBlock
				}
				*logical += skip
			}
		}
	}
}

// readBlock 读取一个块的内容
func readBlock(reader disk.DiskReader, sb *SuperBlock, blockNum uint64) ([]byte, error) {
	buf := make([]byte, sb.BlockSize)
	n, err := reader.ReadAt(buf, sb.BlockToByteOffset(blockNum))
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}
