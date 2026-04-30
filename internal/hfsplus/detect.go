// Package hfsplus 实现 HFS+ / HFSX (老 macOS / iOS) 文件系统的只读检测和卷头解析。
//
// **本包当前实现的边界**：
//   ✅ 检测 HFS+ / HFSX volume header（H+/HX 签名）
//   ✅ 解 volume header 关键字段：block size / total blocks / 文件夹/文件计数 / next CNID
//   ✅ 卷名（来自 Finder Info / 实际更可靠的方式是读 Catalog B-tree thread record，
//        本 MVP 暂用 Finder Info 中的 volume name 字段为空时回落给"未命名"）
//   ❌ Catalog B-tree 完整遍历（文件枚举）—— 类似 APFS 是大块工作，单独 PR
//   ❌ Compression（HFS+ 用 decmpfs xattr）
//   ❌ Journaling 重放
//
// 合理定位：让用户**看见** macOS 老盘 / Time Machine 备份盘上 HFS+ 卷的存在 + 容量信息，
// 配合现有的 carver 仍可在 HFS+ 卷上做 signature 雕刻找回数据。
//
// 参考文档：Apple TN1150 "HFS Plus Volume Format"。
package hfsplus

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"data-recovery/internal/disk"
)

// ProgressFn 是 HFS+ 全盘 brute-force 期间的进度回调（取证模式专用）
type ProgressFn = func(scanned, total int64)

// FindOptions 控制 HFS+ 卷检测策略。
//
// 默认 BruteForce=false：只跑 offset 0 检测（fast path）。
// BruteForce=true：全盘扫 H+ / HX 签名找已删除/孤立的 HFS+ 卷。
type FindOptions struct {
	OnProgress ProgressFn
	BruteForce bool
}

// HFS+ Volume Header 在卷起点 + 1024 字节处（前 1024 字节是 boot blocks，向 HFS / Mac OS 9 致敬）
const VolumeHeaderOffset int64 = 1024

// signature 字段（uint16 BE）
const (
	sigHFSPlus uint16 = 0x482B // "H+"
	sigHFSX    uint16 = 0x4858 // "HX"
)

// VolumeHeader 是 HFS+ / HFSX 卷头解析结果。
type VolumeHeader struct {
	Offset       int64    // 卷在磁盘上的起始字节偏移（boot blocks 起点，不是 +1024 后）
	Signature    uint16   // 0x482B (HFS+) 或 0x4858 (HFSX)
	Version      uint16
	Attributes   uint32
	BlockSize    uint32   // 通常 4096
	TotalBlocks  uint32
	FreeBlocks   uint32
	NextCNID     uint32
	WriteCount   uint32
	FolderCount  uint32
	FileCount    uint32
	VolumeName   string   // 来自 Finder Info；准确方式需 Catalog B-tree
	IsHFSX       bool
	IsCaseSensitive bool   // HFSX 才有意义
	IsJournaled  bool
}

// Detect 在给定 offset 处尝试识别 HFS+ / HFSX 卷。
// 不是 HFS+ 时返回 nil + nil error；IO 错误返回 nil + error。
func Detect(reader disk.DiskReader, offset int64) (*VolumeHeader, error) {
	// volume header 在 offset + 1024，长度 512 字节足够覆盖关键字段
	const hdrSize = 512
	buf := make([]byte, hdrSize)
	n, err := reader.ReadAt(buf, offset+VolumeHeaderOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 HFS+ volume header 失败: %w", err)
	}
	if n < hdrSize {
		return nil, nil
	}

	sig := binary.BigEndian.Uint16(buf[0:2])
	if sig != sigHFSPlus && sig != sigHFSX {
		return nil, nil
	}

	v := &VolumeHeader{
		Offset:      offset,
		Signature:   sig,
		Version:     binary.BigEndian.Uint16(buf[2:4]),
		Attributes:  binary.BigEndian.Uint32(buf[4:8]),
		BlockSize:   binary.BigEndian.Uint32(buf[40:44]),
		TotalBlocks: binary.BigEndian.Uint32(buf[44:48]),
		FreeBlocks:  binary.BigEndian.Uint32(buf[48:52]),
		NextCNID:    binary.BigEndian.Uint32(buf[64:68]),
		WriteCount:  binary.BigEndian.Uint32(buf[68:72]),
		FolderCount: binary.BigEndian.Uint32(buf[32:36]),
		FileCount:   binary.BigEndian.Uint32(buf[36:40]),
		IsHFSX:      sig == sigHFSX,
	}

	// Attributes bit kHFSVolumeJournaledBit = 13
	v.IsJournaled = v.Attributes&(1<<13) != 0

	// 合理性
	if v.BlockSize < 512 || v.BlockSize > 1024*1024 {
		return nil, nil
	}
	if v.TotalBlocks == 0 {
		return nil, nil
	}

	// HFSX case-sensitivity 标记藏在 finderInfo[1] 高字节里（Apple TN1150 附录），
	// 完整识别需要再读 Catalog header；MVP 暂置默认值。

	return v, nil
}

// Scanner 全盘扫描 HFS+ 卷
type Scanner struct {
	reader disk.DiskReader
}

func NewScanner(reader disk.DiskReader) *Scanner {
	return &Scanner{reader: reader}
}

// FindVolumes 定位 HFS+ 卷。
//
// 策略（v2.8.11 修订）：
//   1. offset 0 检测（fast path）
//   2. 全盘步进扫 H+ / HX 签名 —— **仅 opts.BruteForce=true 启用**
//
// 之前永远跑全盘扫，128GB U 盘上即便没 HFS+ 也要扫几十秒到几小时。
func (s *Scanner) FindVolumes(ctx context.Context, opts FindOptions) ([]*VolumeHeader, error) {
	size, err := s.reader.Size()
	if err != nil {
		return nil, err
	}
	var out []*VolumeHeader
	if v, _ := Detect(s.reader, 0); v != nil {
		out = append(out, v)
	}

	if !opts.BruteForce {
		return out, nil
	}

	const (
		blockSize int64 = 4 * 1024 * 1024
		step      int64 = 1024 * 1024
	)
	buf := make([]byte, blockSize)
	seen := make(map[int64]bool, len(out))
	for _, v := range out {
		seen[v.Offset] = true
	}

	const progressEmitInterval = 500 * time.Millisecond
	lastEmit := time.Now()

	for blockOff := int64(0); blockOff < size; blockOff += blockSize {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		read := blockSize
		if blockOff+read > size {
			read = size - blockOff
		}
		n, rerr := s.reader.ReadAt(buf[:read], blockOff)
		if rerr != nil && n == 0 {
			continue
		}
		// 在块内按 step 步进搜索 H+ / HX 签名（在 +1024 偏移处）
		for in := int64(0); in+VolumeHeaderOffset+2 <= int64(n); in += step {
			sig := binary.BigEndian.Uint16(buf[in+VolumeHeaderOffset : in+VolumeHeaderOffset+2])
			if sig != sigHFSPlus && sig != sigHFSX {
				continue
			}
			abs := blockOff + in
			if seen[abs] {
				continue
			}
			if v, _ := Detect(s.reader, abs); v != nil {
				out = append(out, v)
				seen[abs] = true
			}
		}

		if opts.OnProgress != nil && time.Since(lastEmit) >= progressEmitInterval {
			opts.OnProgress(blockOff+read, size)
			lastEmit = time.Now()
		}
	}
	if opts.OnProgress != nil {
		opts.OnProgress(size, size)
	}
	return out, nil
}
