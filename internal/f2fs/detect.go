// Package f2fs 检测 F2FS (Flash-Friendly File System) — Android 闪存 / Samsung
// 设备 / 一些嵌入式 Linux 用。
//
// F2FS superblock 在偏移 +0x400 (1024)：
//   +0x00 magic = 0xF2F52010 (LE uint32)
//   +0x04 major_ver / minor_ver (各 uint16)
//   +0x08 log_sectorsize (uint32)
//   +0x0C log_sectors_per_block (uint32)
//   +0x10 log_blocksize (uint32)
//   +0x14 log_blocks_per_seg (uint32)
//   +0x18 segs_per_sec (uint32)
package f2fs

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

const (
	SuperblockOffset int64  = 1024
	f2fsMagic        uint32 = 0xF2F52010
)

type Superblock struct {
	Offset       int64
	MajorVersion uint16
	MinorVersion uint16
	LogBlockSize uint32
	BlockSize    uint32 // 1 << LogBlockSize
}

func Detect(reader disk.DiskReader, volStart int64) (*Superblock, error) {
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, volStart+SuperblockOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 F2FS superblock: %w", err)
	}
	if n < 32 {
		return nil, nil
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != f2fsMagic {
		return nil, nil
	}
	sb := &Superblock{
		Offset:       volStart + SuperblockOffset,
		MajorVersion: binary.LittleEndian.Uint16(buf[4:6]),
		MinorVersion: binary.LittleEndian.Uint16(buf[6:8]),
		LogBlockSize: binary.LittleEndian.Uint32(buf[16:20]),
	}
	if sb.LogBlockSize > 16 {
		return nil, nil
	}
	sb.BlockSize = 1 << sb.LogBlockSize
	return sb, nil
}
