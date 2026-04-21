package apfs

import (
	"encoding/binary"
	"fmt"
	"path"

	"data-recovery/internal/disk"
)

// FSTreeCrawler 把整个 APFS 卷的 fs B-tree 拍平成"对象列表"：
//
//	inode → InodeRecord
//	dir entry → DirEntry
//	file extent → FileExtentRecord
//
// 给上层（recovery engine）提供一个简单的 API：
//   - EnumerateFiles 返回所有 (full path, inode, []extents) 三元组
//   - 上层再决定要恢复哪些
//
// 当前实现的边界：
//   ✅ 走完整 B-tree（含分支节点）
//   ✅ 处理多版本 (xid)：取最大 xid 的记录
//   ✅ 普通文件 + 目录 + 软链
//   ❌ snapshot 卷
//   ❌ extended attributes
//   ❌ 压缩文件（decmpfs）—— 需要解 LZFSE/LZVN
type FSTreeCrawler struct {
	reader          disk.DiskReader
	containerOffset int64
	blockSize       uint32
	omap            map[uint64]OmapEntry

	// 累积结果
	inodes  map[uint64]*InodeRecord       // obj_id → inode
	dirents map[uint64][]DirEntry         // parent_id → 目录下所有项
	extents map[uint64][]FileExtentRecord // file_obj_id → extents（按 LogicalOffset 排序）
}

// NewFSTreeCrawler 用容器信息 + 已加载的 omap 构造 crawler。
func NewFSTreeCrawler(reader disk.DiskReader, containerOffset int64, blockSize uint32, omap map[uint64]OmapEntry) *FSTreeCrawler {
	return &FSTreeCrawler{
		reader:          reader,
		containerOffset: containerOffset,
		blockSize:       blockSize,
		omap:            omap,
		inodes:          make(map[uint64]*InodeRecord),
		dirents:         make(map[uint64][]DirEntry),
		extents:         make(map[uint64][]FileExtentRecord),
	}
}

// Crawl 从 fs tree root 出发遍历整个 B-tree，把 leaf records 解出来塞进缓存。
//
// rootTreeOID 来自卷超块 apfs_root_tree_oid（virtual OID，需要先用 omap 翻译）。
func (c *FSTreeCrawler) Crawl(rootTreeOID uint64) error {
	if c.omap == nil {
		return fmt.Errorf("omap 未加载")
	}
	rootPAddr, ok := ResolveVirtual(c.omap, rootTreeOID)
	if !ok {
		return fmt.Errorf("fs root tree OID %d 在 omap 中查不到", rootTreeOID)
	}
	return c.walkNode(rootPAddr, 0)
}

func (c *FSTreeCrawler) walkNode(physBlock uint64, depth int) error {
	if depth > 32 {
		return fmt.Errorf("fs tree 深度超过 32 层，疑似损坏")
	}
	blockBytes := int64(c.blockSize)
	buf := make([]byte, blockBytes)
	if _, err := c.reader.ReadAt(buf, c.containerOffset+int64(physBlock)*blockBytes); err != nil {
		return fmt.Errorf("读 fs node 物理块 %d: %w", physBlock, err)
	}
	node, err := ParseBTreeNode(buf)
	if err != nil {
		return fmt.Errorf("解析 fs node 物理块 %d: %w", physBlock, err)
	}

	if node.IsLeaf {
		for _, ent := range node.Entries {
			c.consumeLeafEntry(ent)
		}
		return nil
	}

	// 分支节点：value 是 8 字节 child virtual OID（仍要走 omap）
	for _, ent := range node.Entries {
		if len(ent.Value) < 8 {
			continue
		}
		childVOID := binary.LittleEndian.Uint64(ent.Value[0:8])
		if childVOID == 0 {
			continue
		}
		childPAddr, ok := ResolveVirtual(c.omap, childVOID)
		if !ok {
			continue // 子节点不在当前 omap snapshot 里，跳过
		}
		if err := c.walkNode(childPAddr, depth+1); err != nil {
			continue // 部分子树失败不中断
		}
	}
	return nil
}

// consumeLeafEntry 按 j_key 的 type 字段分发到对应缓存。
func (c *FSTreeCrawler) consumeLeafEntry(ent BTreeEntry) {
	jk, err := ParseJKey(ent.Key)
	if err != nil {
		return
	}
	switch jk.Type {
	case JTypeInode:
		if in := ParseInodeRecord(ent.Key, ent.Value); in != nil {
			c.inodes[in.ObjID] = in
		}
	case JTypeDirRec:
		if d := ParseDirEntry(ent.Key, ent.Value); d != nil {
			c.dirents[d.ParentID] = append(c.dirents[d.ParentID], *d)
		}
	case JTypeFileExtent:
		if ex := ParseFileExtentRecord(ent.Key, ent.Value); ex != nil {
			c.extents[ex.OwnerObjID] = append(c.extents[ex.OwnerObjID], *ex)
		}
	}
}

// FileEntry 是 EnumerateFiles 返回的一行：
type FileEntry struct {
	Path    string             // 完整路径（含文件名）
	Inode   *InodeRecord
	IsDir   bool
	Extents []FileExtentRecord // 已按 LogicalOffset 排序
}

// EnumerateFiles 把 crawl 完成后的 inode/dirent/extent 关联起来，
// 返回扁平化的文件列表（含目录，便于上层做"层级显示"）。
//
// APFS 根目录 obj_id = 1（FSROOT_OID）。
func (c *FSTreeCrawler) EnumerateFiles() []FileEntry {
	const rootOID uint64 = 1
	var out []FileEntry
	c.recurse(rootOID, "/", &out, 0)
	return out
}

func (c *FSTreeCrawler) recurse(parentID uint64, parentPath string, out *[]FileEntry, depth int) {
	if depth > 64 {
		return // 防 dentry 形成的环
	}
	for _, d := range c.dirents[parentID] {
		fullPath := path.Join(parentPath, d.Name)
		in := c.inodes[d.FileID]
		if in == nil {
			continue
		}
		// d.Type bit： 4 = DT_DIR；其他基本是文件 / 软链 / 设备
		isDir := d.Type == 4
		entry := FileEntry{
			Path:  fullPath,
			Inode: in,
			IsDir: isDir,
		}
		if !isDir {
			// PrivateID 才是 file extent 的 owner_obj_id
			ownerID := in.PrivateID
			if ownerID == 0 {
				ownerID = in.ObjID
			}
			ex := c.extents[ownerID]
			// 简单按 LogicalOffset 升序排
			sortExtents(ex)
			entry.Extents = ex
		}
		*out = append(*out, entry)
		if isDir {
			c.recurse(d.FileID, fullPath, out, depth+1)
		}
	}
}

func sortExtents(ex []FileExtentRecord) {
	// 简单 O(n^2) 插入排序：单文件 extents 数通常很少（<32），不引入 sort 包依赖
	for i := 1; i < len(ex); i++ {
		for j := i; j > 0 && ex[j-1].LogicalOffset > ex[j].LogicalOffset; j-- {
			ex[j-1], ex[j] = ex[j], ex[j-1]
		}
	}
}
