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
	"encoding/binary"
	"fmt"
	"io"

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

// FindVolumes 全盘步进搜索 ReFS 签名
func (s *Scanner) FindVolumes() ([]*VolumeHeader, error) {
	size, err := s.reader.Size()
	if err != nil {
		return nil, err
	}
	var out []*VolumeHeader
	if v, _ := Detect(s.reader, 0); v != nil {
		out = append(out, v)
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
	for blockOff := int64(0); blockOff < size; blockOff += blockSize {
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
	}
	return out, nil
}
