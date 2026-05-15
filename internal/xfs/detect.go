// Package xfs 检测 XFS 卷 — Red Hat / CentOS / RHEL 默认。
//
// XFS superblock 在卷起点 (offset 0)：
//
//	+0x00 magic "XFSB" (0x58465342)
//	+0x04 blocksize  (uint32, 通常 4096)
//	+0x08 dblocks    (uint64, 总块数)
//	+0x20 fname[12]  (UTF-8 NUL-terminated label)
//
// **本包仅做检测**：完整 XFS B+tree / AG (allocation group) 解析另外几千行工作量。
package xfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

const xfsMagic uint32 = 0x58465342 // "XFSB"

type Superblock struct {
	Offset     int64
	BlockSize  uint32
	BlockCount uint64
	Label      string
}

func Detect(reader disk.DiskReader, volStart int64) (*Superblock, error) {
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, volStart)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 XFS superblock: %w", err)
	}
	if n < 64 {
		return nil, nil
	}
	if binary.BigEndian.Uint32(buf[0:4]) != xfsMagic {
		return nil, nil
	}
	sb := &Superblock{
		Offset:     volStart,
		BlockSize:  binary.BigEndian.Uint32(buf[4:8]),
		BlockCount: binary.BigEndian.Uint64(buf[8:16]),
	}
	if sb.BlockSize < 512 || sb.BlockSize > 65536 {
		return nil, nil
	}
	// label @ +108 (0x6C)，12 字节
	if n >= 120 {
		raw := buf[108:120]
		end := 0
		for ; end < len(raw); end++ {
			if raw[end] == 0 {
				break
			}
		}
		sb.Label = string(raw[:end])
	}
	return sb, nil
}
