package apfs

import (
	"encoding/binary"
	"fmt"

	"data-recovery/internal/disk"
)

// APFS object map (omap) 把 "virtual OID" 翻译成 "physical block number"。
// 容器超块的 nx_omap_oid 指向 omap 对象，omap 对象里 om_tree_oid 指向真正的 omap B-tree。
//
// omap B-tree key (omap_key_t):
//
//	uint64 ok_oid    要查的虚拟 OID
//	uint64 ok_xid    事务 ID（允许多版本；查时取 xid <= 当前事务的最大那条）
//
// omap B-tree value (omap_val_t):
//
//	uint32 ov_flags
//	uint32 ov_size      物理对象的字节大小（一般 = block_size）
//	uint64 ov_paddr     物理块号
//
// 查 omap 不需要全树遍历：单次 search 平均 O(log n)；但对"列出所有卷"我们做的是
// 全 leaf 扫描收集所有 (oid → paddr) 映射，方便后续 fs tree crawler 不用反复 search。

// OmapEntry 是从 omap leaf 解出的一条映射记录（取最高 xid 的）。
type OmapEntry struct {
	OID     uint64
	XID     uint64
	PAddr   uint64 // 物理块号
	Size    uint32 // 通常 = block_size
}

// OmapPhys 是 omap 对象本身（用容器超块 nx_omap_oid * block_size 读出来）。
// 偏移基于 obj_phys 之后：
//
//	+0x20  om_flags         uint32
//	+0x24  om_snap_count    uint32
//	+0x28  om_tree_type     uint32
//	+0x2C  om_snapshot_tree_type uint32
//	+0x30  om_tree_oid      uint64    ← 真正的 omap B-tree root（物理 OID = 物理块号）
//	+0x38  om_snapshot_tree_oid uint64
//	+0x40  om_most_recent_snap uint64
//	+0x48  om_pending_revert_min uint64
//	+0x50  om_pending_revert_max uint64
type OmapPhys struct {
	TreeOID uint64
}

// ParseOmapPhys 从 omap 对象的整块字节里解出 tree OID。
func ParseOmapPhys(buf []byte) (*OmapPhys, error) {
	if len(buf) < 0x40 {
		return nil, fmt.Errorf("omap_phys 块太短: %d", len(buf))
	}
	return &OmapPhys{
		TreeOID: binary.LittleEndian.Uint64(buf[0x30:0x38]),
	}, nil
}

// LoadOmap 从容器读出整个 object map：
//
//	1. 读 nx_omap_oid 对应的物理块（这是 omap_phys 对象）
//	2. 解出 om_tree_oid（omap B-tree 的物理块号）
//	3. 读那一块作为 B-tree root，walk 收集 (oid → paddr) 全表
//
// 当前实现假设 omap B-tree 整体规模在单个 root 节点里能放下；对中等规模 APFS 卷
// （几万到几十万对象）通常成立。深层 B-tree 需要补 walkBranch 递归。
func LoadOmap(reader disk.DiskReader, containerOffset int64, blockSize uint32, omapOID uint64) (map[uint64]OmapEntry, error) {
	blockBytes := int64(blockSize)

	// omap 对象本身的物理块号 = omapOID（因为 omap 自己是个 ephemeral 对象，OID 直接是物理块号）
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
	if err := walkOmapTree(reader, containerOffset, blockSize, omapPhys.TreeOID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// walkOmapTree 递归走完 omap B-tree（包括分支节点 + 叶节点），收集所有映射。
// 叶节点 entry 里 key 是 (oid, xid)，value 是 (flags, size, paddr)。
// 分支节点 entry 的 value 是 8 字节 child OID，需要继续读。
func walkOmapTree(reader disk.DiskReader, containerOffset int64, blockSize uint32, nodeOID uint64, out map[uint64]OmapEntry) error {
	blockBytes := int64(blockSize)
	buf := make([]byte, blockBytes)
	if _, err := reader.ReadAt(buf, containerOffset+int64(nodeOID)*blockBytes); err != nil {
		return fmt.Errorf("读 omap node OID=%d 失败: %w", nodeOID, err)
	}
	node, err := ParseBTreeNode(buf)
	if err != nil {
		return fmt.Errorf("解析 omap node OID=%d: %w", nodeOID, err)
	}

	if node.IsLeaf {
		for _, ent := range node.Entries {
			if len(ent.Key) < 16 || len(ent.Value) < 16 {
				continue
			}
			oid := binary.LittleEndian.Uint64(ent.Key[0:8])
			xid := binary.LittleEndian.Uint64(ent.Key[8:16])
			size := binary.LittleEndian.Uint32(ent.Value[4:8])
			paddr := binary.LittleEndian.Uint64(ent.Value[8:16])
			// 多版本：保留 xid 最大的那条
			if prev, ok := out[oid]; !ok || xid > prev.XID {
				out[oid] = OmapEntry{
					OID:   oid,
					XID:   xid,
					PAddr: paddr,
					Size:  size,
				}
			}
		}
		return nil
	}

	// 分支节点：每个 entry 的 value 是 8 字节 child OID
	for _, ent := range node.Entries {
		if len(ent.Value) < 8 {
			continue
		}
		childOID := binary.LittleEndian.Uint64(ent.Value[0:8])
		if childOID == 0 || childOID == nodeOID {
			continue // 防自环
		}
		// 防止过深 / 损坏 metadata 死循环：粗略限制到 1M 个节点
		if len(out) > 1_000_000 {
			return fmt.Errorf("omap 节点过多（>1M），疑似 metadata 损坏")
		}
		if err := walkOmapTree(reader, containerOffset, blockSize, childOID, out); err != nil {
			// 子节点失败不中断（部分可用即可）
			continue
		}
	}
	return nil
}

// ResolveVirtual 用 omap 表把 virtual OID 转成 physical block。
// 没找到返回 (0, false)。
func ResolveVirtual(omap map[uint64]OmapEntry, vOID uint64) (uint64, bool) {
	e, ok := omap[vOID]
	if !ok {
		return 0, false
	}
	return e.PAddr, true
}
