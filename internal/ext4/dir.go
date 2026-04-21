package ext4

import (
	"encoding/binary"
)

// 目录项的两种结构：
//
//   ext2 经典结构（rec_len + name_len uint16）：
//     +0  inode      uint32
//     +4  rec_len    uint16  本条目占用字节数（含头 + 名字 + 对齐 padding）
//     +6  name_len   uint16
//     +8  name (rec_len-8 字节)
//
//   ext3+ rev1 结构（FILETYPE feature, name_len 缩成 uint8 + file_type uint8）：
//     +0  inode      uint32
//     +4  rec_len    uint16
//     +6  name_len   uint8
//     +7  file_type  uint8
//     +8  name
//
// 目录文件本身的"数据"就是这一长串目录项；通过 inode 拿到目录的 PhysicalRange，
// 把所有块的内容拼起来，再 parse 出条目。

// DirEntry 解析后的目录条目
type DirEntry struct {
	Inode     uint64 // inode 号；0 表示已删除（rec_len 仍然占位置但 inode 被清零）
	Name      string
	FileType  uint8 // 1=regular, 2=dir, 7=symlink, 等（rev1 起有效）
	IsDeleted bool
}

// 文件类型常量
const (
	ftRegular  uint8 = 1
	ftDir      uint8 = 2
	ftSymlink  uint8 = 7
)

// parseDirBlock 解析一段目录数据（一个或多个块拼起来）
//
// 已删除条目的判定：
//   1. inode == 0 → 该位置被显式标记为空
//   2. rec_len 比 ceil(8 + name_len, 4) 大很多 → 前一条 unlink 时 rec_len 被合并扩张，
//      把"被删除条目"的字节范围吃掉了。这种情况下，"被吃掉"的旧条目仍然能在数据里读到，
//      只要扫描把 rec_len 当作"逻辑跳跃距离"而不是"上次的物理大小"。
//
// 这个函数会同时返回 in-use 和 partially-overwritten deleted entries（用 IsDeleted 区分），
// 给恢复层最大灵活度。
func parseDirBlock(buf []byte, hasFileType bool) []DirEntry {
	out := make([]DirEntry, 0, 16)
	pos := 0
	for pos+8 <= len(buf) {
		inode := binary.LittleEndian.Uint32(buf[pos+0 : pos+4])
		recLen := int(binary.LittleEndian.Uint16(buf[pos+4 : pos+6]))
		if recLen < 8 || pos+recLen > len(buf) {
			break
		}

		var nameLen int
		var fileType uint8
		if hasFileType {
			nameLen = int(buf[pos+6])
			fileType = buf[pos+7]
		} else {
			nameLen = int(binary.LittleEndian.Uint16(buf[pos+6 : pos+8]))
		}

		if nameLen > 0 && pos+8+nameLen <= len(buf) {
			name := string(buf[pos+8 : pos+8+nameLen])
			if inode != 0 && (name != "." && name != "..") {
				out = append(out, DirEntry{
					Inode:    uint64(inode),
					Name:     name,
					FileType: fileType,
				})
			}
		}

		// 启发：如果 rec_len 比"理论占用"（ceil((8+nameLen)/4) * 4）大，剩余部分可能是
		// 一个被 unlink 后被前一条 rec_len 吞并的旧条目。我们回过头去再扫一次。
		theoryLen := ((8 + nameLen) + 3) &^ 3
		if recLen-theoryLen >= 8 && nameLen > 0 {
			// 试着在 [pos+theoryLen, pos+recLen) 区间里再找已删除条目
			subStart := pos + theoryLen
			subEnd := pos + recLen
			for subStart+8 <= subEnd {
				ghostInode := binary.LittleEndian.Uint32(buf[subStart+0 : subStart+4])
				ghostRecLen := int(binary.LittleEndian.Uint16(buf[subStart+4 : subStart+6]))
				if ghostRecLen < 8 || subStart+ghostRecLen > subEnd {
					break
				}
				var ghostNameLen int
				var ghostFileType uint8
				if hasFileType {
					ghostNameLen = int(buf[subStart+6])
					ghostFileType = buf[subStart+7]
				} else {
					ghostNameLen = int(binary.LittleEndian.Uint16(buf[subStart+6 : subStart+8]))
				}
				if ghostNameLen > 0 && subStart+8+ghostNameLen <= subEnd {
					ghostName := string(buf[subStart+8 : subStart+8+ghostNameLen])
					// 鬼目录项：inode 字段已被清零的情况下也要捕获
					out = append(out, DirEntry{
						Inode:     uint64(ghostInode),
						Name:      ghostName,
						FileType:  ghostFileType,
						IsDeleted: true,
					})
				}
				subStart += ghostRecLen
				if ghostRecLen == 0 {
					break
				}
			}
		}

		pos += recLen
	}
	return out
}
