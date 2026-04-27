package refs

// ReFS Minstore B+ tree walker —— 在 ParseMinstorePage 提供的 (key, value) 之上
// 做"value TLV 解析 + 跨 page 跟踪 child 指针 + 建对象 graph"。
//
// **背景**：Microsoft 不发 ReFS 内部规范，本实现基于以下公开 RE 来源：
//
//   - Microsoft Patent US20140351545 "Block storage by decoupling ordering from
//     durability" —— 提供 Minstore B+ 树架构概念图
//   - Andrea Allievi BlackHat 2019 "ReFS forensics" presentation slides
//   - libfsrefs (Joachim Metz) —— 部分 v1.x 反向工程
//   - 真实 ReFS v3.x 卷的 hexdump 观察
//
// **能做的（可信度 80%+）**：
//   ✅ 区分 leaf vs internal node（用 entry value 里的 child page hint）
//   ✅ 从 leaf entry 抽 key=ObjectID, value 里的 $FILE_NAME / $STANDARD_INFORMATION
//   ✅ 内部节点遍历：从 root MSB+ 顺着 child 引用递归
//
// **能做的（可信度 50%）**：
//   ⚠️ 同一 page 多版本（CoW）— 选最高 LSN 但不能保证逻辑一致
//   ⚠️ Object table 反向引用（parent_id → child[]）
//   ⚠️ 大目录跨多 page split 处理
//
// **不能做（社区无足够 RE 数据）**：
//   ❌ 64-bit block reference (ReFS v3.4+)
//   ❌ Integrity stream / Cluster band 重组
//   ❌ Snapshot tree（block-cloned 块的引用计数）

import (
	"encoding/binary"
	"fmt"
	"sort"
	"unicode/utf16"

	"data-recovery/internal/disk"
)

// MinstoreNodeKind leaf 还是 internal
type MinstoreNodeKind int

const (
	NodeKindUnknown MinstoreNodeKind = iota
	NodeKindLeaf
	NodeKindInternal
)

// ParsedNode 是结构化解析的 MSB+ page
type ParsedNode struct {
	Offset    int64
	LSN       uint64
	Kind      MinstoreNodeKind
	Entries   []MinstoreEntry
	// 如果是 internal node，每个 entry 的 value 解出一个 child page offset
	ChildPages []int64
}

// ParseNodeStructured 把 MSB+ page 解析成有 leaf/internal 语义的 ParsedNode
//
// 启发：value 里若 ≥ 8 字节且解为 uint64 落在 [volStart, volStart+volSize) 范围，
// 视为 child page 引用 → internal node；否则为 leaf。
func ParseNodeStructured(reader disk.DiskReader, pageOffset, volStart, volSize int64) (*ParsedNode, error) {
	buf := make([]byte, MinstorePageSize)
	n, err := reader.ReadAt(buf, pageOffset)
	if err != nil || int64(n) < MinstorePageSize {
		return nil, fmt.Errorf("读 page @%d: %w", pageOffset, err)
	}
	if string(buf[0:4]) != pageMagicMSBPlus {
		return nil, fmt.Errorf("非 MSB+ page")
	}
	entries, err := ParseMinstorePage(buf)
	if err != nil {
		return nil, err
	}
	node := &ParsedNode{
		Offset:  pageOffset,
		Entries: entries,
	}
	if len(buf) >= 16 {
		node.LSN = binary.LittleEndian.Uint64(buf[8:16])
	}

	// 启发：判断 leaf vs internal
	internalHits := 0
	for _, e := range entries {
		if len(e.Value) < 8 {
			continue
		}
		// 检查 value 前 8 字节是否像 child page 引用
		// child page = page offset 在卷范围内且 16KB 对齐
		ref := int64(binary.LittleEndian.Uint64(e.Value[:8]))
		if ref >= volStart && ref < volStart+volSize && ref%MinstorePageSize == 0 {
			internalHits++
		}
	}
	// 70%+ entries 看起来是 page ref → internal node
	if len(entries) > 0 && internalHits*10 >= len(entries)*7 {
		node.Kind = NodeKindInternal
		for _, e := range entries {
			if len(e.Value) >= 8 {
				ref := int64(binary.LittleEndian.Uint64(e.Value[:8]))
				if ref >= volStart && ref < volStart+volSize && ref%MinstorePageSize == 0 {
					node.ChildPages = append(node.ChildPages, ref)
				}
			}
		}
	} else if len(entries) > 0 {
		node.Kind = NodeKindLeaf
	} else {
		node.Kind = NodeKindUnknown
	}
	return node, nil
}

// FieldTLV 是 leaf entry value 里一段 (tag, length, payload)
//
// ReFS field 编码（社区 RE）：
//   2 字节 tag (refsField* 常量)
//   4 字节 length（含 self 的总字节数？或 payload 字节数？社区数据不一致）
//   payload bytes
type FieldTLV struct {
	Tag     uint16
	Length  uint32
	Payload []byte
}

// ParseValueAsTLV 把 entry value 当 TLV 流解析
//
// 失败启发：解到一半 length 越界 → 返回已解出的部分 + nil（不报错，因为 value
// 可能就不是 TLV 编码，是别的格式）
func ParseValueAsTLV(value []byte) []FieldTLV {
	var fields []FieldTLV
	pos := 0
	for pos+6 <= len(value) {
		tag := binary.LittleEndian.Uint16(value[pos : pos+2])
		length := binary.LittleEndian.Uint32(value[pos+2 : pos+6])
		// 防御
		if length < 6 || int(length) > len(value)-pos {
			break
		}
		payloadSize := int(length) - 6
		field := FieldTLV{
			Tag:     tag,
			Length:  length,
			Payload: append([]byte(nil), value[pos+6:pos+6+payloadSize]...),
		}
		fields = append(fields, field)
		pos += int(length)
	}
	return fields
}

// ExtractFileNameFromTLV 在 TLV fields 里找 $FILE_NAME，返回 utf-8 名 + parent ID
//
// $FILE_NAME payload 估计布局（社区 RE）：
//   +0x00  uint64 parent object id
//   +0x08  uint64 created time (FILETIME)
//   +0x10  uint64 modified time
//   +0x18  uint64 mft_changed time
//   +0x20  uint64 access time
//   +0x28  uint64 allocated_size
//   +0x30  uint64 file_size
//   +0x38  uint32 file_attributes
//   +0x3C  uint8  name_length (UTF-16 units)
//   +0x3D  uint8  name_type (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS)
//   +0x3E  utf16  name_units
func ExtractFileNameFromTLV(fields []FieldTLV) (name string, parentID uint64, ok bool) {
	for _, f := range fields {
		if f.Tag != refsFieldFileName {
			continue
		}
		if len(f.Payload) < 0x40 {
			continue
		}
		parent := binary.LittleEndian.Uint64(f.Payload[0:8])
		nameLen := int(f.Payload[0x3C])
		if nameLen == 0 || 0x3E+nameLen*2 > len(f.Payload) {
			continue
		}
		units := make([]uint16, nameLen)
		for i := 0; i < nameLen; i++ {
			units[i] = binary.LittleEndian.Uint16(f.Payload[0x3E+i*2 : 0x40+i*2])
		}
		// 校验合法
		valid := true
		for _, u := range units {
			if !isValidNameChar(u) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		return string(utf16.Decode(units)), parent, true
	}
	return "", 0, false
}

// WalkBTree 从 root page 开始 DFS 整棵树，对每个 leaf 的 entries 调 onEntry。
//
// onEntry(key, value, sourcePage)：调用方收到 (key, value) 和它出自哪个 page
// （便于 debug / 取证）。
//
// rootOffset 应该是从 superblock 找出的 object table root（社区 RE 没有完美方案，
// 用户可以传入 SummarizeMinstore 里 LSN 最高的 MSB+ page 作为启发起点）。
//
// 防 cycle：visited set 限制每 page 只走一次。
func WalkBTree(reader disk.DiskReader, rootOffset, volStart, volSize int64,
	maxDepth int, onEntry func(key, value []byte, page int64)) error {

	if maxDepth <= 0 {
		maxDepth = 32
	}
	visited := map[int64]bool{}
	type frame struct {
		page  int64
		depth int
	}
	stack := []frame{{rootOffset, 0}}

	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if visited[top.page] || top.depth > maxDepth {
			continue
		}
		visited[top.page] = true

		node, err := ParseNodeStructured(reader, top.page, volStart, volSize)
		if err != nil {
			continue // 损坏 page 跳过，继续走兄弟
		}

		switch node.Kind {
		case NodeKindLeaf:
			for _, e := range node.Entries {
				if onEntry != nil {
					onEntry(e.Key, e.Value, top.page)
				}
			}
		case NodeKindInternal:
			for _, child := range node.ChildPages {
				stack = append(stack, frame{child, top.depth + 1})
			}
		}
	}
	return nil
}

// EnumerateFilesViaBTree 完整 B+ tree 遍历版的 file 枚举（vs entries.go 的启发）。
//
// 1. SummarizeMinstore 找 LSN 最高的 MSB+ page（启发为 root）
// 2. WalkBTree 从 root 走整棵树
// 3. 对每个 leaf entry 解 TLV，抽 $FILE_NAME → 输出 ReFSFileEntry
//
// 比 entries.go 的纯字符串扫精度高，但在没找到 root 或 root 走不通时
// 应当 fallback 到启发式（调用方保留两种路径）。
func EnumerateFilesViaBTree(reader disk.DiskReader, volStart, volSize int64) ([]ReFSFileEntry, error) {
	pages, err := IndexMinstorePages(reader, volStart, volSize)
	if err != nil {
		return nil, err
	}
	// 找 LSN 最高的 MSB+ page 作为根（启发：版本最新的 page 大概率是 active root）
	var rootCandidates []MinstorePage
	for _, p := range pages {
		if p.Magic == pageMagicMSBPlus {
			rootCandidates = append(rootCandidates, p)
		}
	}
	if len(rootCandidates) == 0 {
		return nil, fmt.Errorf("没找到 MSB+ page")
	}
	sort.Slice(rootCandidates, func(i, j int) bool {
		return rootCandidates[i].LSN > rootCandidates[j].LSN
	})

	var out []ReFSFileEntry
	seen := map[uint64]bool{}

	// 取 LSN 最高的前 5 个 page 作为 root candidates 都试一次
	maxRoots := 5
	if len(rootCandidates) < maxRoots {
		maxRoots = len(rootCandidates)
	}
	for i := 0; i < maxRoots; i++ {
		root := rootCandidates[i]
		_ = WalkBTree(reader, volStart+root.Offset, volStart, volSize, 16,
			func(key, value []byte, page int64) {
				if len(key) < 8 {
					return
				}
				objID := binary.LittleEndian.Uint64(key[:8])
				if seen[objID] {
					return
				}
				fields := ParseValueAsTLV(value)
				name, parentID, ok := ExtractFileNameFromTLV(fields)
				if !ok {
					return
				}
				seen[objID] = true
				out = append(out, ReFSFileEntry{
					ObjectID:   objID,
					ParentID:   parentID,
					FileName:   name,
					PageOffset: page,
				})
			})
	}
	return out, nil
}
