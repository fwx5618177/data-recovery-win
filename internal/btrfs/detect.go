// Package btrfs 检测 Btrfs (B-tree File System) 卷 —— Linux 较新发行版默认
// (Fedora 33+, openSUSE)、Synology NAS、Facebook 服务器都用。
//
// **本包当前实现的边界**：
//
//	✅ 检测主 superblock (magic "_BHRfS_M" @ offset 0x10000)
//	✅ 解关键字段：bytenr / fsid / nodesize / sectorsize / total_bytes / 文件系统标签
//	❌ 完整 B-tree 文件枚举 — 1-2 周工作量；调用方要读 Btrfs 文件需要专业工具
//
// 价值：让用户在 Linux 盘上看到"这是一个 Btrfs 卷，X GB"，配合 carver 仍可恢复
// 大部分非碎片化文件。
//
// 参考：btrfs-progs / linux/fs/btrfs/disk-io.c
package btrfs

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"data-recovery/internal/disk"
)

// ProgressFn 是 Btrfs 全盘 brute-force 期间的进度回调（取证模式专用）
type ProgressFn = func(scanned, total int64)

// FindOptions 控制 Btrfs 卷检测策略。
//
// 默认 BruteForce=false：只跑 offset 0 的 superblock 检测。
// BruteForce=true：全盘步进搜 _BHRfS_M magic 找已删除/孤立的 Btrfs 卷。
type FindOptions struct {
	OnProgress ProgressFn
	BruteForce bool
}

const (
	// Btrfs 主 superblock 在物理偏移 64KB；备份 superblock 在 64MB / 256GB / 1PB
	SuperblockOffset int64 = 0x10000
	// magic = "_BHRfS_M"
	superMagic = "_BHRfS_M"
)

// Superblock Btrfs 主超块解析结果（btrfs_super_block 关键字段）。
type Superblock struct {
	Offset     int64    // 在卷里的字节偏移（始终 0x10000）
	FSID       [16]byte // 文件系统 UUID
	BytesUsed  uint64
	TotalBytes uint64
	SectorSize uint32
	NodeSize   uint32
	LeafSize   uint32
	StripeSize uint32
	Label      string // 用户可见的文件系统标签
}

// Detect 在给定 volStart 处尝试识别 Btrfs。
// 不是 Btrfs 时返回 nil + nil error。
func Detect(reader disk.DiskReader, volStart int64) (*Superblock, error) {
	const probe = 4096
	buf := make([]byte, probe)
	n, err := reader.ReadAt(buf, volStart+SuperblockOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 Btrfs superblock: %w", err)
	}
	if n < probe {
		return nil, nil
	}
	// magic @ +64 (0x40)：btrfs_super_block.magic = u8[8]
	if string(buf[64:72]) != superMagic {
		return nil, nil
	}
	sb := &Superblock{
		Offset:     SuperblockOffset,
		BytesUsed:  binary.LittleEndian.Uint64(buf[112:120]),
		TotalBytes: binary.LittleEndian.Uint64(buf[104:112]),
		// btrfs_super_block 字段偏移（可能版本差异）
		SectorSize: binary.LittleEndian.Uint32(buf[180:184]),
		NodeSize:   binary.LittleEndian.Uint32(buf[184:188]),
		LeafSize:   binary.LittleEndian.Uint32(buf[188:192]),
		StripeSize: binary.LittleEndian.Uint32(buf[192:196]),
	}
	copy(sb.FSID[:], buf[32:48])
	// 标签 @ +0x12B (299)，最长 256 字节，UTF-8 NUL-terminated
	if probe >= 299+256 {
		raw := buf[299 : 299+256]
		end := 0
		for ; end < len(raw); end++ {
			if raw[end] == 0 {
				break
			}
		}
		sb.Label = string(raw[:end])
	}
	if sb.SectorSize == 0 || sb.NodeSize == 0 {
		return nil, nil // 字段异常 — 假阳性
	}
	return sb, nil
}

// Scanner 全盘搜 Btrfs superblock
type Scanner struct{ reader disk.DiskReader }

func NewScanner(r disk.DiskReader) *Scanner { return &Scanner{reader: r} }

// FindVolumes 定位 Btrfs 卷。
//
// 策略（v2.8.11 修订）：
//  1. offset 0 检测（fast path）
//  2. 16MB 步进全盘扫 _BHRfS_M magic —— **仅 opts.BruteForce=true 启用**
func (s *Scanner) FindVolumes(ctx context.Context, opts FindOptions) ([]*Superblock, error) {
	size, err := s.reader.Size()
	if err != nil {
		return nil, err
	}
	var out []*Superblock

	// fast path
	if sb, _ := Detect(s.reader, 0); sb != nil {
		sb.Offset = SuperblockOffset
		out = append(out, sb)
	}

	if !opts.BruteForce {
		return out, nil
	}

	const step int64 = 16 * 1024 * 1024
	const progressEmitInterval = 500 * time.Millisecond
	lastEmit := time.Now()

	for off := int64(0); off+SuperblockOffset+4096 < size; off += step {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if off > 0 {
			if sb, _ := Detect(s.reader, off); sb != nil {
				sb.Offset = off + SuperblockOffset
				out = append(out, sb)
			}
		}
		if opts.OnProgress != nil && time.Since(lastEmit) >= progressEmitInterval {
			opts.OnProgress(off, size)
			lastEmit = time.Now()
		}
	}
	if opts.OnProgress != nil {
		opts.OnProgress(size, size)
	}
	return out, nil
}
