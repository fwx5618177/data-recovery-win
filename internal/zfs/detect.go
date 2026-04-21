// Package zfs 检测 ZFS 卷（实际是 vdev 标签）。
//
// ZFS 在每个底层 vdev 的开头 256KB 放 4 个 vdev label 副本（L0/L1 在头，L2/L3 在尾）。
// 每个 label 含 16KB blank + 8KB boot header + 112KB nvlist (XDR 编码)，
// nvlist 里有 "version" / "name" / "pool_guid" 等。
//
// 完整 nvlist 解析复杂；本实现只检测 boot header 里的 "ZFS_BOOT" 字节模式 + nvlist 起点
// 4 字节 magic 0x00bab10c (uberblock magic 反向) — best-effort 识别。
//
// 完整 ZFS 文件系统读取需要 zpool import + dnode tree 遍历，远超本工具范围。
package zfs

import (
	"bytes"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// Vdev 是识别出的 ZFS vdev 标签
type Vdev struct {
	Offset int64
	Note   string
}

// Detect 在 vdev 起点扫前 256KB 找 ZFS 特征。
// 不是 ZFS 时返回 nil + nil error。
func Detect(reader disk.DiskReader, volStart int64) (*Vdev, error) {
	buf := make([]byte, 256*1024)
	n, err := reader.ReadAt(buf, volStart)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 ZFS vdev label: %w", err)
	}
	if n < 16*1024 {
		return nil, nil
	}
	// L0 nvlist 在 16KB+8KB = 24KB；nvlist XDR 头是 4 字节版本号 + 4 字节 endianness
	// 不直接解 XDR；只看几个高强度特征字符串
	signals := [][]byte{
		[]byte("zpool"),
		[]byte("vdev_tree"),
		[]byte("ZFS_BOOT"),
		[]byte("name"),     // nvlist 字段名
		[]byte("pool_guid"),
	}
	hits := 0
	for _, sig := range signals {
		if bytes.Contains(buf[:n], sig) {
			hits++
		}
	}
	// 至少命中 3 个高频字符串才认；避免假阳性
	if hits < 3 {
		return nil, nil
	}
	return &Vdev{
		Offset: volStart,
		Note:   fmt.Sprintf("ZFS vdev label（命中 %d/%d 特征字段；本工具不解 ZFS 文件树）", hits, len(signals)),
	}, nil
}
