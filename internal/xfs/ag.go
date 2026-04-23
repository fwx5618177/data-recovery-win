package xfs

// XFS Allocation Group (AG) + inode 基础解析 —— Phase 6 基础设施。
//
// XFS 结构（Red Hat / CentOS 默认 FS）:
//   卷被分成 N 个 AG（allocation group）；每个 AG 约 1 TB，独立管理 inodes / extents。
//   每个 AG 前 4 个 sector 有：
//     sector 0: SB (superblock 副本)
//     sector 1: AGF (Allocation Group Free space info)
//     sector 2: AGI (Allocation Group Inode info) ★
//     sector 3: AGFL (Allocation Group Free List)
//
//   AGI 指向 inode B+tree root（存 inode chunk 映射）
//   inode chunk 里每个 inode 固定 256/512 字节
//
// 本文件实现：
//   ✅ 扩展 Superblock 读 AG 数量 / AG 大小 / inode 大小
//   ✅ AGI header 解析（ibno/bno B+tree roots）
//   ✅ inode 结构基础字段（di_mode/di_size/di_nblocks/di_mtime/di_format/di_u）
//   ✅ 本地（di_format = INLINE）短数据 inline 解
//
// 留给未来（工作量 1500+ 行）：
//   ❌ inode B+tree 完整遍历（inobt / finobt）
//   ❌ extent B+tree 遍历（data extents）
//   ❌ 目录 block 解析（dir2 short form / block form / leaf form / node form）
//   ❌ 实时卷（realtime subvolume）
//   ❌ CRC32C 校验
//   ❌ reflink / dedupe
//
// 参考：xfsprogs / linux/fs/xfs/libxfs/xfs_format.h + xfs_da_format.h
//
// 注意：所有 XFS 多字节字段都是 **big-endian**

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

const (
	xfsAGIMagic uint32 = 0x58414749 // "XAGI"
	xfsAGFMagic uint32 = 0x58414746 // "XAGF"
	xfsINOMagic uint16 = 0x494E     // "IN" prefix in v5 inode
	xfsINOMagicV5 uint16 = 0x494E   // 同上（CRC v5 加了其他校验字段）

	// inode 内 di_format 枚举
	xfsDinodeFmtDev     = 0 // 设备号
	xfsDinodeFmtLocal   = 1 // 内容 inline 在 inode 的 di_u
	xfsDinodeFmtExtents = 2 // extent 列表 inline
	xfsDinodeFmtBtree   = 3 // B+tree
	xfsDinodeFmtUUID    = 4
)

// ExtendedSuperblock 完整 XFS superblock 关键字段
type ExtendedSuperblock struct {
	*Superblock

	UUID          [16]byte
	LogStart      uint64  // 日志起始 block
	RootIno       uint64  // 根目录 inode 号
	InodeSize     uint16  // 通常 256 或 512
	InodesPerBlk  uint16
	AgBlocks      uint32  // 每个 AG 的 block 数
	AgCount       uint32
	SectorSize    uint16
	DirBlkLog     uint8   // log2(dir block size / fs block size)
	Features2     uint32  // v5 特性
	Version       uint16  // 最低 4 bits = 版本
}

// ParseExtendedSuperblock 扩展解析主 superblock
func ParseExtendedSuperblock(reader disk.DiskReader, volStart int64) (*ExtendedSuperblock, error) {
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, volStart)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 superblock: %w", err)
	}
	if n < 256 {
		return nil, fmt.Errorf("superblock 数据不足")
	}
	if binary.BigEndian.Uint32(buf[0:4]) != xfsMagic {
		return nil, fmt.Errorf("不是 XFS")
	}

	base := &Superblock{
		Offset:     volStart,
		BlockSize:  binary.BigEndian.Uint32(buf[4:8]),
		BlockCount: binary.BigEndian.Uint64(buf[8:16]),
	}

	// xfs_dsb 布局（big-endian）：
	//   offset 0: magicnum (uint32)
	//   offset 4: blocksize (uint32)
	//   offset 8: dblocks (uint64) — 总 block
	//   offset 16: rblocks (uint64) — realtime blocks
	//   offset 24: rextents (uint64)
	//   offset 32: uuid (16 bytes)
	//   offset 48: logstart (uint64)
	//   offset 56: rootino (uint64)
	//   offset 64: rbmino / rsumino
	//   offset 80: rextsize (uint32)
	//   offset 84: agblocks (uint32)
	//   offset 88: agcount (uint32)
	//   offset 92: rbmblocks / logblocks
	//   offset 100: versionnum (uint16)
	//   offset 102: sectsize (uint16)
	//   offset 104: inodesize (uint16)
	//   offset 106: inopblock (uint16)
	//   offset 108: fname[12]
	//   offset 120: blocklog / sectlog / inodelog (u8)
	//   offset 123: inopblog / agblklog / rextslog (u8)
	//   offset 126: inprogress / imax_pct (u8)
	//   offset 128..: icount / ifree / fdblocks / frextents
	//   offset 196: features2 (uint32) (v5)

	ext := &ExtendedSuperblock{Superblock: base}
	copy(ext.UUID[:], buf[32:48])
	ext.LogStart = binary.BigEndian.Uint64(buf[48:56])
	ext.RootIno = binary.BigEndian.Uint64(buf[56:64])
	ext.AgBlocks = binary.BigEndian.Uint32(buf[84:88])
	ext.AgCount = binary.BigEndian.Uint32(buf[88:92])
	ext.Version = binary.BigEndian.Uint16(buf[100:102])
	ext.SectorSize = binary.BigEndian.Uint16(buf[102:104])
	ext.InodeSize = binary.BigEndian.Uint16(buf[104:106])
	ext.InodesPerBlk = binary.BigEndian.Uint16(buf[106:108])
	if n >= 196+4 {
		ext.Features2 = binary.BigEndian.Uint32(buf[196:200])
	}

	// fname label
	if n >= 120 {
		raw := buf[108:120]
		end := 0
		for ; end < len(raw); end++ {
			if raw[end] == 0 {
				break
			}
		}
		base.Label = string(raw[:end])
	}

	return ext, nil
}

// AGI Allocation Group Inode header
type AGI struct {
	Magic      uint32
	Versionnum uint32
	SeqNo      uint32 // AG index
	Length     uint32 // AG size in blocks
	Count      uint32 // allocated inodes in this AG
	Root       uint32 // inode B+tree (inobt) root block
	Level      uint32 // B+tree level
	FreeCount  uint32
	NewIno     uint32 // 最新分配 inode
	DirIno     uint32
}

// ReadAGI 读指定 AG（按 AG 编号）的 AGI
func ReadAGI(reader disk.DiskReader, sb *ExtendedSuperblock, agIndex uint32) (*AGI, error) {
	agStart := sb.Offset + int64(agIndex)*int64(sb.AgBlocks)*int64(sb.BlockSize)
	agiOff := agStart + 2*int64(sb.SectorSize) // sector 2

	buf := make([]byte, sb.SectorSize)
	n, err := reader.ReadAt(buf, agiOff)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 AGI @%d: %w", agiOff, err)
	}
	if n < 64 {
		return nil, fmt.Errorf("AGI 数据不足")
	}
	if binary.BigEndian.Uint32(buf[0:4]) != xfsAGIMagic {
		return nil, fmt.Errorf("AGI magic 不匹配（期望 XAGI）")
	}

	return &AGI{
		Magic:      binary.BigEndian.Uint32(buf[0:4]),
		Versionnum: binary.BigEndian.Uint32(buf[4:8]),
		SeqNo:      binary.BigEndian.Uint32(buf[8:12]),
		Length:     binary.BigEndian.Uint32(buf[12:16]),
		Count:      binary.BigEndian.Uint32(buf[16:20]),
		Root:       binary.BigEndian.Uint32(buf[24:28]),
		Level:      binary.BigEndian.Uint32(buf[28:32]),
		FreeCount:  binary.BigEndian.Uint32(buf[32:36]),
		NewIno:     binary.BigEndian.Uint32(buf[36:40]),
		DirIno:     binary.BigEndian.Uint32(buf[40:44]),
	}, nil
}

// Inode 简化 XFS inode（含 core + inline data 支持）
type Inode struct {
	Ino       uint64  // inode 号（跨 AG 唯一）
	Mode      uint16  // Unix mode
	Size      uint64  // di_size
	NBlocks   uint64  // di_nblocks
	Format    uint8   // di_format
	NExtents  uint32  // extents 数
	MTime     int64
	IsDir     bool
	IsSymlink bool
	InlineData []byte // 仅 format=LOCAL 时有效
}

// ParseInodeCore 从 inode 原 bytes 里解基础字段
func ParseInodeCore(buf []byte, inoNumber uint64) (*Inode, error) {
	if len(buf) < 96 {
		return nil, fmt.Errorf("inode 数据 < 96 字节")
	}
	// struct xfs_dinode_core（big-endian）:
	//   offset 0: di_magic (uint16) — "IN"
	//   offset 2: di_mode (uint16)
	//   offset 4: di_version (u8)
	//   offset 5: di_format (u8)
	//   offset 6: di_onlink (uint16)
	//   offset 8: di_uid (uint32)
	//   offset 12: di_gid (uint32)
	//   offset 16: di_nlink (uint32)
	//   offset 20: di_projid (uint16)
	//   offset 22: di_pad[8]
	//   offset 30: di_flushiter (uint16)
	//   offset 32: di_atime (sec:4 + nsec:4)
	//   offset 40: di_mtime
	//   offset 48: di_ctime
	//   offset 56: di_size (uint64)
	//   offset 64: di_nblocks (uint64)
	//   offset 72: di_extsize (uint32)
	//   offset 76: di_nextents (uint32)
	//   offset 80: di_anextents (uint16)
	//   offset 82: di_forkoff (u8)
	//   offset 83: di_aformat (u8)
	//   offset 84: di_dmevmask (uint32)
	//   offset 88: di_dmstate (uint16)
	//   offset 90: di_flags (uint16)
	//   offset 92: di_gen (uint32)
	// v5 (CRC) additions: +8 di_crc + 8 bytes etc.
	magic := binary.BigEndian.Uint16(buf[0:2])
	if magic != xfsINOMagic {
		return nil, fmt.Errorf("inode magic 不匹配: 0x%04X", magic)
	}

	in := &Inode{Ino: inoNumber}
	in.Mode = binary.BigEndian.Uint16(buf[2:4])
	in.Format = buf[5]
	in.Size = binary.BigEndian.Uint64(buf[56:64])
	in.NBlocks = binary.BigEndian.Uint64(buf[64:72])
	in.NExtents = binary.BigEndian.Uint32(buf[76:80])
	in.MTime = int64(binary.BigEndian.Uint32(buf[40:44])) // secs only

	switch in.Mode & 0xF000 {
	case 0x4000:
		in.IsDir = true
	case 0xA000:
		in.IsSymlink = true
	}

	// LOCAL format: 内容直接在 di_u 区（从 offset 96 或 v5 +176 开始）
	if in.Format == xfsDinodeFmtLocal && in.Size > 0 && int(in.Size) < len(buf)-96 {
		dataStart := 96 // v4；v5 会多 a few 字段但 LOCAL 对短文件仍从 di_u 区起
		if dataStart+int(in.Size) <= len(buf) {
			in.InlineData = make([]byte, in.Size)
			copy(in.InlineData, buf[dataStart:dataStart+int(in.Size)])
		}
	}

	return in, nil
}
