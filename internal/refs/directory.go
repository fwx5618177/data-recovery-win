package refs

// ReFS 目录层级还原 —— 基于社区逆向的 best-effort 树重建。
//
// 问题：Minstore B+ tree 里文件条目的 parent-child 关系通过以下方式存：
//   1. File entry 里有 parent_object_id 字段（8 字节 uint64）
//   2. Directory entry 里有 child list（在 IndexRoot / IndexAllocation 字段）
//   3. 根目录有固定 object id = 0x600 或 0x721 (ReFS v3.x 根 object)
//
// 由于 Microsoft 无公开规范，本实现使用三层启发 + 结构组合：
//   Pass 1: 扫 MSB+ page，提取所有 file entry + ParentID 候选
//   Pass 2: 构建 ObjectID → FileName 映射 + ObjectID → ParentID 映射
//   Pass 3: 对每个 file 递归回溯 parent 链，拼完整 path
//
// 根目录识别：
//   - ObjectID ∈ {0x600, 0x601, 0x721} 是 ReFS 内置对象（MFT 元文件等）
//   - ParentID == ObjectID → 自引用，视为根
//   - ParentID == 0 → 未分配/根
//
// 覆盖范围：
//   ✅ 两三层目录的常见场景（家庭文档 / 照片 / 程序文件）
//   ✅ 循环检测（parent 链 > 32 层视为异常 → 截断）
//   ✅ 部分 parent 缺失时"? / <unknown> / filename" fallback path
//   ❌ 硬链接（ReFS 支持但 parent 链会多 parent）
//   ❌ CoW 版本树（本版本只取当前 transaction 的状态）
//   ❌ 别名 stream (alternate data streams)

import (
	"encoding/binary"
	"fmt"
	"strings"

	"data-recovery/internal/disk"
)

// ReFS 根目录常见 ObjectID（社区观察；不同 ReFS 版本值略有变化）
var refsWellKnownRootIDs = map[uint64]string{
	0x0000000000000500: "$TrueRoot",
	0x0000000000000600: "$Root",
	0x0000000000000601: "$System",
	0x0000000000000721: "$Root",
}

// DirEntry 目录关联表：child id → parent id + name
type DirEntry struct {
	ChildID  uint64
	ParentID uint64
	Name     string
}

// extractParentChildRelations 从 page 里启发找 parent-child 关系模式
//
// ReFS 内部 "directory index" 典型格式（社区逆向观察）:
//
//	entry header (通常 16 字节) + child_id (u64) + ... + name_len (u16) + name (UTF-16)
//	parent_id 则在 entry 所属 key 或附近的 16 字节 header 里
//
// 本函数扫 page body 找以下模式：
//
//	8 字节候选 parent_id（合理范围 0..2^40，排除极端值）
//	后接 8 字节候选 child_id
//	附近 2 字节 name_len (2..510)
//	紧跟 name_len 字节的 UTF-16 字符串
//
// 命中则记录一条 DirEntry
func extractParentChildRelations(buf []byte) []DirEntry {
	var out []DirEntry
	// 启发位置：从 page header 后开始每 16 字节步长
	for i := 64; i+64 < len(buf); i += 16 {
		// 尝试 (parent_id, child_id) 对
		parentID := binary.LittleEndian.Uint64(buf[i : i+8])
		childID := binary.LittleEndian.Uint64(buf[i+8 : i+16])

		if !looksLikeObjectID(parentID) || !looksLikeObjectID(childID) {
			continue
		}
		if parentID == childID {
			continue // 不接受自引用（虽然根可能是，但这里作为 entry 匹配的排除）
		}

		// 在 buf[i+16 .. i+16+256] 找 UTF-16 name
		scanStart := i + 16
		scanEnd := scanStart + 256
		if scanEnd > len(buf) {
			scanEnd = len(buf)
		}
		name := tryExtractUTF16Near(buf[:scanEnd], scanStart, scanEnd-scanStart)
		if name == "" {
			continue
		}
		out = append(out, DirEntry{
			ChildID:  childID,
			ParentID: parentID,
			Name:     name,
		})
		// 跳过该 entry（粗略估算：16 header + name 两倍字节 + 对齐）
		i += 16 + len(name)*2
	}
	return out
}

// looksLikeObjectID 合理的 ReFS Minstore ObjectID 启发
//
//	非零 + 小于 2^48（实际 ReFS 卷里 ObjectID 远不会这么大）
func looksLikeObjectID(id uint64) bool {
	if id == 0 {
		return false
	}
	const maxReasonable uint64 = 1 << 48
	return id < maxReasonable
}

// BuildReFSDirectoryTree 完整枚举 + 目录树拼装
//
// 流程：
//  1. 全卷 Pass 1：按现有 EnumerateReFSFullEntries 拿所有 file entry
//  2. 全卷 Pass 2：按 extractParentChildRelations 拿 parent-child 关系
//  3. 合并：对每个 file，用 relations 里 ChildID==ObjectID 的记录补 ParentID
//  4. 递归拼 full path（带循环检测）
func BuildReFSDirectoryTree(reader disk.DiskReader, volStart, volSize int64) ([]ReFSFileWithPath, error) {
	// Pass 1: 收集 file entry
	files, err := EnumerateReFSFullEntries(reader, volStart, volSize)
	if err != nil {
		return nil, fmt.Errorf("枚举 file entry: %w", err)
	}

	// Pass 2: 收集 parent-child 关系
	pages, err := IndexMinstorePages(reader, volStart, volSize)
	if err != nil {
		return nil, fmt.Errorf("索引 page: %w", err)
	}
	var allRelations []DirEntry
	for _, p := range pages {
		if p.Magic != pageMagicMSBPlus {
			continue
		}
		buf := make([]byte, MinstorePageSize)
		n, err := reader.ReadAt(buf, p.Offset)
		if err != nil || int64(n) < MinstorePageSize {
			continue
		}
		rels := extractParentChildRelations(buf)
		allRelations = append(allRelations, rels...)
	}

	// 构 index：ObjectID → DirEntry（最近一次看到的 parent-child 记录）
	parentOf := make(map[uint64]uint64)
	nameByID := make(map[uint64]string)
	for _, r := range allRelations {
		parentOf[r.ChildID] = r.ParentID
		// 以第一个出现的 name 为准（ReFS 里 object 多次出现时应一致）
		if _, ok := nameByID[r.ChildID]; !ok {
			nameByID[r.ChildID] = r.Name
		}
	}

	// Pass 3: 对每个 file 拼 full path
	result := make([]ReFSFileWithPath, 0, len(files))
	for _, f := range files {
		f2 := ReFSFileWithPath{ReFSFileEntry: f}
		// 若 file entry 已有 ParentID（从 Phase H 的启发），直接用；否则查 relations
		if f.ParentID == 0 {
			if p, ok := parentOf[f.ObjectID]; ok {
				f2.ParentID = p
			}
		}
		f2.FullPath = buildFullPath(f.ObjectID, f.FileName, parentOf, nameByID, 32)
		result = append(result, f2)
	}
	return result, nil
}

// ReFSFileWithPath 扩展 entry 加 full path
type ReFSFileWithPath struct {
	ReFSFileEntry
	FullPath string // "Users/Alice/Documents/report.docx"
}

// buildFullPath 递归回溯 parent 链拼路径；循环检测（maxDepth）+ 根检测
func buildFullPath(objID uint64, selfName string, parentOf map[uint64]uint64,
	nameByID map[uint64]string, maxDepth int) string {

	if selfName == "" {
		selfName = "<unknown>"
	}
	parts := []string{selfName}
	seen := map[uint64]bool{objID: true}
	cur := objID

	for depth := 0; depth < maxDepth; depth++ {
		parent, ok := parentOf[cur]
		if !ok {
			break // parent 信息缺失
		}
		if seen[parent] {
			// 循环 / 自引用 / 根
			break
		}
		if _, isRoot := refsWellKnownRootIDs[parent]; isRoot {
			// 碰到已知根对象，不再追溯
			break
		}
		seen[parent] = true
		pname, has := nameByID[parent]
		if !has {
			pname = fmt.Sprintf("<obj_%x>", parent)
		}
		parts = append([]string{pname}, parts...)
		cur = parent
	}
	return strings.Join(parts, "/")
}
