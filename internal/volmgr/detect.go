// Package volmgr 卷管理器 metadata 识别 —— mdadm / LVM2 / Storage Spaces。
//
// **本包只做识别**：完整解析每种卷管理器要 1-2 周，且每种 metadata 格式都有版本演化。
// 给用户/取证人员的最低价值是"这个盘是某 RAID/LVM 阵列的成员，单独扫不出文件，
// 必须先用相应工具组装"。
package volmgr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// Member 是单盘里识别出的卷管理器成员标识
type Member struct {
	Type string // "mdadm" / "lvm2" / "storage-spaces"
	Hint string // 给用户的引导
}

// DetectAll 在盘的几个常见位置扫所有支持的 metadata 签名
func DetectAll(reader disk.DiskReader) []Member {
	var out []Member
	if m, _ := DetectMDADM(reader); m != nil {
		out = append(out, *m)
	}
	if m, _ := DetectLVM2(reader); m != nil {
		out = append(out, *m)
	}
	if m, _ := DetectStorageSpaces(reader); m != nil {
		out = append(out, *m)
	}
	return out
}

// DetectMDADM Linux mdadm 软件 RAID 成员。
// metadata 1.x 在盘的 4 KiB / 8 KiB 偏移；0.90 在盘尾。
//
// magic = 0xA92B4EFC (LE) "Mdadm" 标识
func DetectMDADM(reader disk.DiskReader) (*Member, error) {
	const magic uint32 = 0xA92B4EFC
	for _, off := range []int64{4096, 8 * 1024, 4 * 4096} {
		buf := make([]byte, 8)
		n, err := reader.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			continue
		}
		if n < 8 {
			continue
		}
		if binary.LittleEndian.Uint32(buf[0:4]) == magic {
			return &Member{
				Type: "mdadm",
				Hint: fmt.Sprintf("mdadm RAID 成员 (metadata @ +0x%X)。请在 Linux 上跑：mdadm --assemble --scan", off),
			}, nil
		}
	}
	return nil, nil
}

// DetectLVM2 Linux LVM2 物理卷标签。
// PV label 在前 4 个 sector 之一（通常 sector 1，offset 512）。
//
// magic = "LABELONE" (8 bytes)
func DetectLVM2(reader disk.DiskReader) (*Member, error) {
	for _, off := range []int64{0, 512, 1024, 1536} {
		buf := make([]byte, 32)
		n, err := reader.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			continue
		}
		if n < 8 {
			continue
		}
		if bytes.HasPrefix(buf, []byte("LABELONE")) {
			return &Member{
				Type: "lvm2",
				Hint: fmt.Sprintf("LVM2 物理卷 (label @ +%d)。请用 vgscan + vgchange -ay + 挂载逻辑卷再扫。", off),
			}, nil
		}
	}
	return nil, nil
}

// DetectStorageSpaces Windows Storage Spaces 物理盘。
// SBR (Storage Spaces) magic 在盘头部之外的特定位置；社区文档不全，本实现只识别
// 少数公开特征字符串。
func DetectStorageSpaces(reader disk.DiskReader) (*Member, error) {
	buf := make([]byte, 4096)
	n, err := reader.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, nil
	}
	if n < 32 {
		return nil, nil
	}
	// Storage Spaces 在前若干扇区会含 "SP" magic 或 "Spaces" 字面值
	// 是非常 best-effort 识别，假阳性可能性高
	if bytes.Contains(buf[:n], []byte("Microsoft Storage Spaces")) ||
		bytes.Contains(buf[:n], []byte("SPACES_CONFIG")) {
		return &Member{
			Type: "storage-spaces",
			Hint: "Windows Storage Spaces 池成员。请在 Windows 装回原存储池后挂载虚拟盘再扫。",
		}, nil
	}
	return nil, nil
}
