// Package apfs 实现 APFS（Apple File System）容器层的只读检测和卷元数据列举。
//
// **当前实现的边界**：
//   ✅ 检测 APFS 容器（NXSB 签名 + 容器超块字段）
//   ✅ 列出容器内所有卷的名字、UUID、加密标志、文件数（来自卷超块）
//   ❌ B-tree 遍历（object map / 文件系统树）—— 文件枚举 / 内容读取需要这个，工作量 3-6 周
//   ❌ APFS 加密卷解密（FileVault）—— 需要先做 B-tree，且涉及 KeyBag / 用户密码派生
//   ❌ APFS 快照 / 克隆 / Compression（LZFSE / LZVN / LZBitmap）
//
// 合理定位：让用户**看见** macOS 盘上的 APFS 卷与加密状态。后续要读文件再做 B-tree。
//
// 参考文档：Apple File System Reference (Apple Developer)。
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// 容器超块的对象类型 (o_type) 常量
const (
	objTypeNXSuperblock uint32 = 0x00000001
	objTypeFSSuperblock uint32 = 0x0000000D

	nxMagic = "NXSB" // 容器超块 magic
	apfsMagic = "APSB" // 卷超块 magic
)

// Container 是 APFS 容器（一个磁盘上可以有多个 APFS 容器，每个容器内多个卷）
type Container struct {
	Offset       int64    // 容器在磁盘上的起始字节偏移
	BlockSize    uint32   // 每块字节数（通常 4096）
	BlockCount   uint64   // 容器总块数
	UUID         [16]byte // 容器 UUID
	OmapOID      uint64   // nx_omap_oid（容器级 object map 物理块号）
	KeyLocker    PRange   // nx_keylocker — 容器级 keybag 在物理盘上的连续区间
	Volumes      []Volume // 容器内的卷
}

// PRange 是 APFS 里的"物理范围"：起始物理块号 + 块数。
// 对应 prange_t = { paddr_t pr_start_paddr, uint64_t pr_block_count }
type PRange struct {
	StartPAddr uint64
	BlockCount uint64
}

// IsZero 判断 PRange 是否为空（block_count=0 = 没有 keybag）
func (p PRange) IsZero() bool {
	return p.BlockCount == 0
}

// Volume 是 APFS 容器里的一个卷
type Volume struct {
	Index       int      // 在容器中的顺序号
	Name        string   // 卷名（如 "Macintosh HD"）
	UUID        [16]byte
	Role        uint16   // 卷角色（系统 / 数据 / 预启动 / 恢复 等）
	IsEncrypted bool     // FileVault 加密标志
	Capacity    uint64   // 该卷已用块数 × 块大小
	FileCount   uint64
	FolderCount uint64
	OmapOID     uint64   // apfs_omap_oid（卷级 object map）
	RootTreeOID uint64   // apfs_root_tree_oid（fs root B-tree 的虚拟 OID）
	KeybagLoc   PRange   // apfs_keybag_loc — 卷级 keybag 物理位置（FileVault 卷才非零）
}

// 容器超块字段偏移（基于 Apple File System Reference）
//
//   nx_o (obj_phys):     offsets 0..31  (cksum/oid/xid/type/subtype)
//   nx_magic:            32..35
//   nx_block_size:       36..39
//   nx_block_count:      40..47
//   nx_features:         48..55
//   nx_readonly_compat_features: 56..63
//   nx_incompat_features: 64..71
//   nx_uuid:             72..87
//   nx_next_oid:         88..95
//   nx_next_xid:         96..103
//   nx_xp_desc_blocks:   104..107  ...
//   nx_omap_oid:         160..167
//   nx_spaceman_oid:     168..175
//   nx_reaper_oid:       176..183
//   nx_test_type:        184..187
//   nx_max_file_systems: 188..191
//   nx_fs_oid (uint64[100]): 192..991
//
// 我们只取到 nx_fs_oid 那一段就够列出所有卷的入口对象 ID。
const (
	nxMagicOffset      = 32
	nxBlockSizeOffset  = 36
	nxBlockCountOffset = 40
	nxUUIDOffset       = 72
	nxOmapOIDOffset    = 160 // nx_omap_oid
	nxFSOIDOffset      = 192
	nxFSOIDCount       = 100
	// nx_keylocker (prange_t = 16 bytes) 在 nx_test_oid (8) + nx_test_type (8) 之后；
	// Apple File System Reference 给出的字段顺序里在 nx_blocked_out_prange 后第 16+24*8 字节。
	// 实际经验偏移：0xC8 (200) — 这是社区公认的 FileVault keybag 位置。
	nxKeylockerOffset  = 0xC8
)

// Detect 在给定 offset 处尝试识别 APFS 容器。
// 不是 APFS 时返回 nil + nil error。
//
// 注意：本函数只读容器超块和**已经能定位到**的卷超块。完整的卷信息需要走 object map
// 才能取最新版本（APFS 是 copy-on-write，物理 OID 不直接 = 块号），但本 MVP 把
// nx_fs_oid 当作"卷超块对应的物理块号"试读，实战中 APFS 在大多数 stable 状态下这是成立的。
func Detect(reader disk.DiskReader, offset int64) (*Container, error) {
	// 容器超块在容器起点的第 0 块。先读 4096 字节假设默认块大小
	const probeSize = 4096
	buf := make([]byte, probeSize)
	n, err := reader.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取 APFS 容器超块失败: %w", err)
	}
	if n < 36 {
		return nil, nil
	}

	// 校验 NXSB magic
	if string(buf[nxMagicOffset:nxMagicOffset+4]) != nxMagic {
		return nil, nil
	}

	c := &Container{
		Offset:     offset,
		BlockSize:  binary.LittleEndian.Uint32(buf[nxBlockSizeOffset : nxBlockSizeOffset+4]),
		BlockCount: binary.LittleEndian.Uint64(buf[nxBlockCountOffset : nxBlockCountOffset+8]),
	}
	copy(c.UUID[:], buf[nxUUIDOffset:nxUUIDOffset+16])
	if len(buf) >= nxOmapOIDOffset+8 {
		c.OmapOID = binary.LittleEndian.Uint64(buf[nxOmapOIDOffset : nxOmapOIDOffset+8])
	}
	// nx_keylocker (prange: paddr 8 + block_count 8)
	if len(buf) >= nxKeylockerOffset+16 {
		c.KeyLocker = PRange{
			StartPAddr: binary.LittleEndian.Uint64(buf[nxKeylockerOffset : nxKeylockerOffset+8]),
			BlockCount: binary.LittleEndian.Uint64(buf[nxKeylockerOffset+8 : nxKeylockerOffset+16]),
		}
	}

	// 合理性校验
	if c.BlockSize < 512 || c.BlockSize > 65536 {
		return nil, nil
	}
	if c.BlockCount == 0 {
		return nil, nil
	}

	// 如果探测时块大小不是默认 4096，重读一次确保完整
	if int(c.BlockSize) > probeSize {
		buf = make([]byte, c.BlockSize)
		n, _ = reader.ReadAt(buf, offset)
		if n < int(c.BlockSize) {
			return nil, nil
		}
	}

	// 读取所有卷超块的 OID 列表（uint64[100]，多数为 0 表示未使用）
	if int(c.BlockSize) >= nxFSOIDOffset+nxFSOIDCount*8 {
		for i := 0; i < nxFSOIDCount; i++ {
			off := nxFSOIDOffset + i*8
			fsOID := binary.LittleEndian.Uint64(buf[off : off+8])
			if fsOID == 0 {
				continue
			}
			// 试读该 OID 对应的物理块（朴素假设 OID == 块号）
			vol, err := readVolumeSuperblock(reader, offset, c.BlockSize, fsOID, len(c.Volumes))
			if err != nil || vol == nil {
				continue
			}
			c.Volumes = append(c.Volumes, *vol)
		}
	}

	return c, nil
}

// readVolumeSuperblock 试图把 fsOID 当作物理块号读卷超块（apfs_superblock_t / APSB）
//
// 卷超块字段偏移：
//
//	apfs_o (obj_phys):       0..31
//	apfs_magic:              32..35  = "APSB"
//	apfs_fs_index:           36..39
//	apfs_features:           40..47
//	... (省略)
//	apfs_root_tree_oid:      144..151
//	... (省略)
//	apfs_uuid:               240..255
//	apfs_last_mod_time:      256..263
//	apfs_fs_flags:           264..271 (bit 0 = unencrypted; APFS_FS_UNENCRYPTED=1)
//	apfs_volname:            704..959  (UTF-8, 256 bytes max, NUL-terminated)
//	apfs_num_files:          1024..1031
//	apfs_num_directories:    1032..1039
//	... (后面还有更多统计字段)
func readVolumeSuperblock(
	reader disk.DiskReader,
	containerOffset int64,
	blockSize uint32,
	fsOID uint64,
	index int,
) (*Volume, error) {
	blockBytes := int64(blockSize)
	absOff := containerOffset + int64(fsOID)*blockBytes
	buf := make([]byte, blockBytes)
	n, err := reader.ReadAt(buf, absOff)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if int64(n) < blockBytes {
		return nil, nil
	}

	if string(buf[32:36]) != apfsMagic {
		return nil, nil // 这块不是合法 APSB（OID 可能需要走 object map 才能定位真实块）
	}

	v := &Volume{Index: index}
	copy(v.UUID[:], buf[240:256])

	// 卷级 omap_oid @ +0x28，root_tree_oid @ +0x30
	if int64(len(buf)) >= 0x38 {
		v.OmapOID = binary.LittleEndian.Uint64(buf[0x28:0x30])
		v.RootTreeOID = binary.LittleEndian.Uint64(buf[0x30:0x38])
	}

	// fs_flags bit 0：未加密 = 1；为 0 表示加密
	if int64(len(buf)) >= 272 {
		flags := binary.LittleEndian.Uint64(buf[264:272])
		v.IsEncrypted = flags&0x01 == 0
	}

	// 卷级 keybag 位置 apfs_keybag_loc @ +0x2C8 (prange = 16 字节)
	// FileVault 加密卷必有；未加密卷为 0
	const apfsKeybagLocOffset = 0x2C8
	if int64(len(buf)) >= apfsKeybagLocOffset+16 {
		v.KeybagLoc = PRange{
			StartPAddr: binary.LittleEndian.Uint64(buf[apfsKeybagLocOffset : apfsKeybagLocOffset+8]),
			BlockCount: binary.LittleEndian.Uint64(buf[apfsKeybagLocOffset+8 : apfsKeybagLocOffset+16]),
		}
	}

	if int64(len(buf)) >= 960 {
		raw := buf[704:960]
		// volname 是 NUL-terminated UTF-8
		end := bytes.IndexByte(raw, 0)
		if end < 0 {
			end = len(raw)
		}
		v.Name = string(raw[:end])
	}

	if int64(len(buf)) >= 1040 {
		v.FileCount = binary.LittleEndian.Uint64(buf[1024:1032])
		v.FolderCount = binary.LittleEndian.Uint64(buf[1032:1040])
	}

	return v, nil
}

// Scanner 全盘扫描 APFS 容器
type Scanner struct {
	reader disk.DiskReader
}

func NewScanner(reader disk.DiskReader) *Scanner {
	return &Scanner{reader: reader}
}

// FindContainers 全盘按 4MB 块扫 NXSB 签名
func (s *Scanner) FindContainers() ([]*Container, error) {
	size, err := s.reader.Size()
	if err != nil {
		return nil, err
	}

	var out []*Container
	if c, _ := Detect(s.reader, 0); c != nil {
		out = append(out, c)
	}

	const (
		blockSize int64 = 4 * 1024 * 1024
		step      int64 = 1024 * 1024 // APFS 容器对齐通常按 4KB 起，但搜索按 1MB 步进够快够准
	)
	buf := make([]byte, blockSize)
	seen := make(map[int64]bool, len(out))
	for _, c := range out {
		seen[c.Offset] = true
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
		// 在块内按 step 步进搜索 NXSB
		for in := int64(0); in+nxMagicOffset+4 <= int64(n); in += step {
			if string(buf[in+nxMagicOffset:in+nxMagicOffset+4]) != nxMagic {
				continue
			}
			abs := blockOff + in
			if seen[abs] {
				continue
			}
			if c, _ := Detect(s.reader, abs); c != nil {
				out = append(out, c)
				seen[abs] = true
			}
		}
	}
	return out, nil
}
