// Package refs 实现 Microsoft ReFS（Resilient File System，Server 2012+ / Win 11 Pro for
// Workstations）的只读检测和卷头解析。
//
// **本包当前实现的边界**：
//   ✅ 检测 ReFS volume boot record（"ReFS" 签名 + 关键字段）
//   ✅ 解 boot sector：bytes/sector / sectors/cluster / total sectors / 容器号 / version
//   ❌ Minstore B-tree 遍历（文件枚举）—— ReFS 内部用 Minstore，文档极度匮乏，工作量大
//   ❌ Integrity Streams 校验
//   ❌ Block clone / dedupe
//
// 合理定位：让用户**看见** Server / Pro for Workstations 盘上 ReFS 卷的存在 + 容量，
// 配合 carver 仍可在 ReFS 卷上做 signature 雕刻找回大部分非碎片化文件。
//
// 参考：libfsrefs 文档（无官方公开规范）+ Microsoft "Resilient File System overview"。
package refs

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"data-recovery/internal/disk"
)

// ReFS Volume Boot Record（VBR）在卷起点（offset 0）。
// 关键字段（完全由社区逆向得出）：
//
//	+0x00  jump (3)
//	+0x03  oem_id "ReFS\x00\x00\x00\x00"        — 8 bytes，签名
//	+0x0B  reserved (5)
//	+0x10  fs_signature "FSRS"                  — 4 bytes
//	+0x14  reserved (4)
//	+0x18  bytes_per_sector       uint16
//	+0x1A  sectors_per_cluster    uint8
//	+0x1B  reserved (15)
//	+0x20  total_sectors          uint64
//	+0x28  container_number       uint64        ReFS 内部"容器"概念
//	+0x30  major_version          uint8
//	+0x31  minor_version          uint8
//	+0x32  reserved (大量)
//	+0x1FE 0x55 0xAA              boot signature
const (
	refsOEMID    = "ReFS\x00\x00\x00\x00" // 8 bytes
	refsFSSignature = "FSRS"              // 4 bytes
)

// VolumeHeader 是 ReFS VBR 解析结果。
type VolumeHeader struct {
	Offset            int64
	BytesPerSector    uint16
	SectorsPerCluster uint8
	TotalSectors      uint64
	ContainerNumber   uint64
	MajorVersion      uint8
	MinorVersion      uint8
}

// Detect 在给定 offset 处尝试识别 ReFS 卷。
// 不是 ReFS 时返回 nil + nil error；IO 错误返回 nil + error。
func Detect(reader disk.DiskReader, offset int64) (*VolumeHeader, error) {
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 ReFS VBR 失败: %w", err)
	}
	if n < 512 {
		return nil, nil
	}

	// 同时校验 OEM ID 和 FS signature 才认；只有签名容易和"碰巧"撞上
	if string(buf[3:11]) != refsOEMID {
		return nil, nil
	}
	if string(buf[16:20]) != refsFSSignature {
		return nil, nil
	}
	// boot signature
	if buf[510] != 0x55 || buf[511] != 0xAA {
		return nil, nil
	}

	v := &VolumeHeader{
		Offset:            offset,
		BytesPerSector:    binary.LittleEndian.Uint16(buf[24:26]),
		SectorsPerCluster: buf[26],
		TotalSectors:      binary.LittleEndian.Uint64(buf[32:40]),
		ContainerNumber:   binary.LittleEndian.Uint64(buf[40:48]),
		MajorVersion:      buf[48],
		MinorVersion:      buf[49],
	}

	// 合理性
	if v.BytesPerSector == 0 || v.BytesPerSector > 8192 {
		return nil, nil
	}
	if v.SectorsPerCluster == 0 {
		return nil, nil
	}
	if v.TotalSectors == 0 {
		return nil, nil
	}

	return v, nil
}

// Scanner 全盘扫 ReFS 卷
type Scanner struct {
	reader disk.DiskReader
}

func NewScanner(reader disk.DiskReader) *Scanner {
	return &Scanner{reader: reader}
}

// FindOptions 控制 ReFS 卷扫描行为。
//
// v2.8.26 引入 —— 之前 FindVolumes 永远做全盘 4MB 步进扫描，没 ctx 没开关。
// 这是用户报"取消扫描后磁盘 IO 不停"的真正根因：每次在 welcome 页选盘，
// app.ScanEncryptedVolumes 都会调本 scanner，对 2TB SSD 跑 ~11 分钟全盘 read。
// 与 apfs / hfsplus / btrfs 等同套 FindOptions 的 fast/brute-force 选项对齐。
type FindOptions struct {
	// BruteForce=false 时只检测 offset 0（ReFS 卷必然位于分区起点 / 整盘起点）。
	// 默认 false —— 用户选盘的"加密卷预警"诊断只需要 fast path。
	BruteForce bool
	// OnProgress brute-force 模式下每 500ms 上报一次进度。
	OnProgress func(curr, total int64)
}

// FindVolumes 定位 ReFS 卷。
//
// 策略（v2.8.26 修订）：
//   1. offset 0 检测（fast path）
//   2. 1MB 步进全盘扫 OEM ID + FS signature —— **仅 opts.BruteForce=true 启用**
//
// 之前没 opt-in 默认做全盘扫，2TB SSD 跑 ~11 分钟。诊断路径（ScanEncryptedVolumes）
// 现在走 BruteForce=false，秒级返回。
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
		// v2.8.26: ctx 检查，让 brute-force 扫描可被 Stop 取消
		if ctx != nil && ctx.Err() != nil {
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
		for in := int64(0); in+512 <= int64(n); in += step {
			if string(buf[in+3:in+11]) != refsOEMID {
				continue
			}
			if string(buf[in+16:in+20]) != refsFSSignature {
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
