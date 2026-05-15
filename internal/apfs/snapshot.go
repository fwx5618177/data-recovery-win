package apfs

import (
	"encoding/binary"
	"fmt"

	"data-recovery/internal/disk"
)

// APFS Snapshot —— APFS 的 copy-on-write 让快照天然可读：
// 每个 snapshot 在 fs tree 里有自己的 SnapMetadata + SnapName record，
// 配合 omap 里 xid <= snapshot.xid 的版本就能看到那个时间点的文件树。
//
// **本文件实现**：
//   - 在卷的 fs tree leaf 里枚举所有 SnapMetadata + SnapName 记录
//   - 给上层一个 (name, xid, createTime) 列表
//   - **不**实现"穿越快照读历史文件" —— 那需要按 snapshot.xid 重做 omap walk，
//     未来需要时再加 LoadOmapAtXID(maxXID) helper
//
// 实战价值：用户有 macOS Time Machine / Apple "本地快照" 时，能列出那些 snapshot，
// 提示"重装前的旧数据可能在 snap-xxxxx 里"。

// Snapshot 是单个 APFS 快照的元数据。
//
// v2.8.33 加 JSON tag —— 之前裸字段，前端读 snapshot.xid/name/createTime 全 undefined，
// "📸 APFS 时光快照"工具的 toast 显示"容器 0xXXX: undefined 个 snapshot"。
type Snapshot struct {
	XID        uint64 `json:"xid"`        // 快照创建时的 transaction id
	CreateTime uint64 `json:"createTime"` // ns 单位（Unix epoch + 0）
	ChangeTime uint64 `json:"changeTime"`
	Name       string `json:"name"` // 快照名（"com.apple.TimeMachine.2026-04-21-..." 或用户自定义）
	InodeNum   uint64 `json:"inodeNum"` // SnapMetadata 的关联 inode
	Flags      uint32 `json:"flags"`
}

// EnumerateSnapshots 把 fs tree 里所有 SnapMetadata + SnapName 记录关联起来。
//
// 用法：
//
//	crawler := NewFSTreeCrawler(reader, c.Offset, c.BlockSize, omap)
//	crawler.Crawl(v.RootTreeOID)
//	snapshots := EnumerateSnapshotsFromCrawler(crawler)
//
// SnapMetadata key (j_key + xid)：
//   +0x00 obj_id_and_type  uint64  type=JTypeSnapMetadata
//   value:
//     +0x00 extentref_tree_oid uint64
//     +0x08 sblock_oid         uint64
//     +0x10 create_time        uint64
//     +0x18 change_time        uint64
//     +0x20 inode_num          uint64
//     +0x28 extentref_tree_type uint32
//     +0x2C flags              uint32
//     +0x30 name_len           uint16
//     +0x32 name               UTF-8（NUL-terminated）
//
// SnapName key (j_key + name)：
//   +0x00 obj_id_and_type  uint64  type=JTypeSnapName，obj_id 即 xid
//   +0x08 name_len         uint16
//   +0x0A name             UTF-8
type snapshotMetaRecord struct {
	xid        uint64
	createTime uint64
	changeTime uint64
	inodeNum   uint64
	flags      uint32
	name       string
}

// EnumerateSnapshotsFromCrawler 直接复用已经 Crawl 完的 FSTreeCrawler 内部缓存
// （inodes / dirents / extents 已经走完了所有 leaf）。但 SnapMetadata 不在这三个 map
// 里，所以需要 crawler 多收一次。本函数走 reader + omap + rootTreeOID 重新走一次 leaf
// 节点专门收 snapshot record。
func EnumerateSnapshotsFromCrawler(_ *FSTreeCrawler) []Snapshot {
	// FSTreeCrawler 当前 consumeLeafEntry 不收 SnapMetadata —— 见 fs_tree.go switch。
	// 给一个 nil 实现说明：完整实现需要扩 consumeLeafEntry 加 case JTypeSnapMetadata。
	// 调用方现在请用 EnumerateSnapshots(reader, container, volume, omap)。
	return nil
}

// LoadOmapAtXID 与 LoadOmap 几乎相同，但只收 xid <= maxXID 的映射，
// 用来"穿越快照看那个时间点的文件树"。
//
// 流程跟 LoadOmap 一致，唯一差别是 leaf entry 选取规则：
//   - 不再"取最高 xid"
//   - 而是"取 xid <= maxXID 中最大的那个"
func LoadOmapAtXID(reader disk.DiskReader, containerOffset int64, blockSize uint32, omapOID uint64, maxXID uint64) (map[uint64]OmapEntry, error) {
	blockBytes := int64(blockSize)
	omapBlock := make([]byte, blockBytes)
	if _, err := reader.ReadAt(omapBlock, containerOffset+int64(omapOID)*blockBytes); err != nil {
		return nil, fmt.Errorf("读 omap_phys 失败: %w", err)
	}
	omapPhys, err := ParseOmapPhys(omapBlock)
	if err != nil {
		return nil, err
	}
	if omapPhys.TreeOID == 0 {
		return nil, fmt.Errorf("omap tree OID 为 0")
	}
	out := make(map[uint64]OmapEntry)
	if err := walkOmapTreeAtXID(reader, containerOffset, blockSize, omapPhys.TreeOID, maxXID, out); err != nil {
		return nil, err
	}
	return out, nil
}

func walkOmapTreeAtXID(reader disk.DiskReader, containerOffset int64, blockSize uint32, nodeOID uint64, maxXID uint64, out map[uint64]OmapEntry) error {
	blockBytes := int64(blockSize)
	buf := make([]byte, blockBytes)
	if _, err := reader.ReadAt(buf, containerOffset+int64(nodeOID)*blockBytes); err != nil {
		return fmt.Errorf("读 omap node OID=%d: %w", nodeOID, err)
	}
	node, err := ParseBTreeNode(buf)
	if err != nil {
		return err
	}
	if node.IsLeaf {
		for _, ent := range node.Entries {
			if len(ent.Key) < 16 || len(ent.Value) < 16 {
				continue
			}
			oid := binary.LittleEndian.Uint64(ent.Key[0:8])
			xid := binary.LittleEndian.Uint64(ent.Key[8:16])
			if xid > maxXID {
				continue // 跳过快照之后的版本
			}
			size := binary.LittleEndian.Uint32(ent.Value[4:8])
			paddr := binary.LittleEndian.Uint64(ent.Value[8:16])
			if prev, ok := out[oid]; !ok || xid > prev.XID {
				out[oid] = OmapEntry{OID: oid, XID: xid, PAddr: paddr, Size: size}
			}
		}
		return nil
	}
	for _, ent := range node.Entries {
		if len(ent.Value) < 8 {
			continue
		}
		childOID := binary.LittleEndian.Uint64(ent.Value[0:8])
		if childOID == 0 || childOID == nodeOID {
			continue
		}
		if len(out) > 1_000_000 {
			return fmt.Errorf("omap 节点过多")
		}
		_ = walkOmapTreeAtXID(reader, containerOffset, blockSize, childOID, maxXID, out)
	}
	return nil
}

// EnumerateSnapshots 直接走 reader + omap，只收 snapshot record。
//
// 这是给"我只想要 snapshot 列表，不想做完整文件枚举"的场景。
func EnumerateSnapshots(reader disk.DiskReader, containerOffset int64, blockSize uint32, omap map[uint64]OmapEntry, rootTreeOID uint64) ([]Snapshot, error) {
	if omap == nil {
		return nil, fmt.Errorf("omap 为 nil")
	}
	rootPAddr, ok := ResolveVirtual(omap, rootTreeOID)
	if !ok {
		return nil, fmt.Errorf("rootTreeOID %d 在 omap 中找不到", rootTreeOID)
	}
	metas := make(map[uint64]*snapshotMetaRecord) // xid → meta
	if err := walkSnapshotNodes(reader, containerOffset, blockSize, omap, rootPAddr, 0, metas); err != nil {
		return nil, err
	}
	out := make([]Snapshot, 0, len(metas))
	for _, m := range metas {
		out = append(out, Snapshot{
			XID:        m.xid,
			CreateTime: m.createTime,
			ChangeTime: m.changeTime,
			InodeNum:   m.inodeNum,
			Flags:      m.flags,
			Name:       m.name,
		})
	}
	return out, nil
}

func walkSnapshotNodes(reader disk.DiskReader, containerOffset int64, blockSize uint32, omap map[uint64]OmapEntry, physBlock uint64, depth int, metas map[uint64]*snapshotMetaRecord) error {
	if depth > 32 {
		return fmt.Errorf("fs tree 深度异常")
	}
	blockBytes := int64(blockSize)
	buf := make([]byte, blockBytes)
	if _, err := reader.ReadAt(buf, containerOffset+int64(physBlock)*blockBytes); err != nil {
		return err
	}
	node, err := ParseBTreeNode(buf)
	if err != nil {
		return err
	}
	if node.IsLeaf {
		for _, ent := range node.Entries {
			jk, err := ParseJKey(ent.Key)
			if err != nil {
				continue
			}
			if jk.Type == JTypeSnapMetadata {
				m := parseSnapMetadataValue(jk.ObjID, ent.Value)
				if m != nil {
					if prev, ok := metas[m.xid]; !ok || prev.name == "" {
						metas[m.xid] = m
					}
				}
			}
		}
		return nil
	}
	for _, ent := range node.Entries {
		if len(ent.Value) < 8 {
			continue
		}
		childVOID := binary.LittleEndian.Uint64(ent.Value[0:8])
		if childVOID == 0 {
			continue
		}
		childPAddr, ok := ResolveVirtual(omap, childVOID)
		if !ok {
			continue
		}
		_ = walkSnapshotNodes(reader, containerOffset, blockSize, omap, childPAddr, depth+1, metas)
	}
	return nil
}

// parseSnapMetadataValue 解 j_snap_metadata_val_t
func parseSnapMetadataValue(xid uint64, val []byte) *snapshotMetaRecord {
	if len(val) < 0x32 {
		return nil
	}
	m := &snapshotMetaRecord{
		xid:        xid,
		createTime: binary.LittleEndian.Uint64(val[0x10:0x18]),
		changeTime: binary.LittleEndian.Uint64(val[0x18:0x20]),
		inodeNum:   binary.LittleEndian.Uint64(val[0x20:0x28]),
		flags:      binary.LittleEndian.Uint32(val[0x2C:0x30]),
	}
	nameLen := int(binary.LittleEndian.Uint16(val[0x30:0x32]))
	if 0x32+nameLen > len(val) {
		return m
	}
	// NUL-terminated UTF-8；剥掉尾部 \x00
	raw := val[0x32 : 0x32+nameLen]
	for i, c := range raw {
		if c == 0 {
			raw = raw[:i]
			break
		}
	}
	m.name = string(raw)
	return m
}
