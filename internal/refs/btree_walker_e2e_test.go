package refs

// 端到端 B+ tree walker 测试 —— 构造合成多层 ReFS 风格 B+ tree，
// 验证 EnumerateFilesViaBTree 能从 root 走到所有 leaf 并解出 $FILE_NAME。
//
// 为什么用合成 fixture 而非真 ReFS 镜像：
//
//   - macOS 上没有原生 ReFS 工具（Microsoft 只在 Windows Server 提供）
//   - 真 ReFS 镜像 ≥ 几 MB（最小 v3.x 卷 = 32MB），git 里塞测试 fixture 不可行
//   - **合成 fixture 验证**结构 walker + TLV parser 端到端正确性，
//     真镜像验证留给取证社区的 sample 集（用户/CI 上跑 integration test）
//
// 本测试的 fixture 结构（3 层 B+ tree）：
//
//	                root (MSB+ page @ offset 0x10000, internal)
//	               /                                         \
//	     internal_a (page @ 0x14000)              internal_b (page @ 0x18000)
//	      /                       \                 /                       \
//	leaf_0 (@0x20000)   leaf_1 (@0x24000)  leaf_2 (@0x28000)   leaf_3 (@0x2C000)
//	  ↓                   ↓                  ↓                    ↓
//	2 file entries     2 file entries     2 file entries      2 file entries
//
// 总计 8 个 file entry，文件名分别 file_0..file_7。
// EnumerateFilesViaBTree 应从 root 启发式找到 root，走整棵树，返回 8 个 file。

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

// fakeBigReader 是带任意 size 的 in-memory disk
type fakeBigReader struct {
	data []byte
}

func (f *fakeBigReader) Open() error { return nil }
func (f *fakeBigReader) ReadAt(p []byte, off int64) (int, error) {
	if int(off) >= len(f.data) {
		return 0, nil
	}
	n := copy(p, f.data[off:])
	return n, nil
}
func (f *fakeBigReader) Size() (int64, error) { return int64(len(f.data)), nil }
func (f *fakeBigReader) Close() error         { return nil }
func (f *fakeBigReader) SectorSize() int      { return 512 }
func (f *fakeBigReader) DevicePath() string   { return "fake" }

// buildLeafPage 构造一个 leaf MSB+ page，含 numEntries 个 file entry。
//
// 每个 entry：
//   - key = uint64 objectID (LE)
//   - value = TLV 流：单 $FILE_NAME field
//
// 返回 16KB 的 page bytes。
func buildLeafPage(t *testing.T, lsn uint64, baseObjID uint64, baseFileName string, numEntries int) []byte {
	t.Helper()
	page := make([]byte, MinstorePageSize)
	copy(page[0:4], pageMagicMSBPlus)
	binary.LittleEndian.PutUint64(page[8:16], lsn)

	// 准备 entries
	entries := make([]struct {
		key, value []byte
	}, numEntries)

	for i := 0; i < numEntries; i++ {
		// key = objectID (8 bytes)
		key := make([]byte, 8)
		binary.LittleEndian.PutUint64(key, baseObjID+uint64(i))

		// value = $FILE_NAME TLV field
		fileName := fmt.Sprintf("%s_%d", baseFileName, i)
		value := buildFileNameTLV(uint64(99), fileName) // parent_id = 99
		entries[i] = struct{ key, value []byte }{key, value}
	}

	// 写 index header at 0x20
	const indexHdrAt = 0x20
	const firstEntryOff = 0x40
	binary.LittleEndian.PutUint32(page[indexHdrAt:], firstEntryOff)
	binary.LittleEndian.PutUint32(page[indexHdrAt+8:], uint32(numEntries))

	// 写每个 entry
	pos := firstEntryOff
	for _, e := range entries {
		// entry header: 16 字节
		// +0 entry_size (u16)
		// +2 key_off (u16) = 16
		// +4 key_len (u16)
		// +6 val_off (u16) = 16 + key_len (round to 4)
		// +8 val_len (u16)
		keyOff := 16
		keyLen := len(e.key)
		valOff := keyOff + ((keyLen + 3) &^ 3) // 4-byte align
		valLen := len(e.value)
		entrySize := valOff + ((valLen + 3) &^ 3)

		if int64(pos+entrySize) > MinstorePageSize {
			t.Fatalf("page overflow at entry, pos=%d size=%d", pos, entrySize)
		}

		binary.LittleEndian.PutUint16(page[pos:], uint16(entrySize))
		binary.LittleEndian.PutUint16(page[pos+2:], uint16(keyOff))
		binary.LittleEndian.PutUint16(page[pos+4:], uint16(keyLen))
		binary.LittleEndian.PutUint16(page[pos+6:], uint16(valOff))
		binary.LittleEndian.PutUint16(page[pos+8:], uint16(valLen))
		copy(page[pos+keyOff:], e.key)
		copy(page[pos+valOff:], e.value)
		pos += entrySize
	}

	return page
}

// buildInternalPage 构造一个 internal MSB+ page，每个 entry 的 value = 子 page offset (u64 LE)。
func buildInternalPage(t *testing.T, lsn uint64, childOffsets []int64) []byte {
	t.Helper()
	page := make([]byte, MinstorePageSize)
	copy(page[0:4], pageMagicMSBPlus)
	binary.LittleEndian.PutUint64(page[8:16], lsn)

	const indexHdrAt = 0x20
	const firstEntryOff = 0x40
	binary.LittleEndian.PutUint32(page[indexHdrAt:], firstEntryOff)
	binary.LittleEndian.PutUint32(page[indexHdrAt+8:], uint32(len(childOffsets)))

	pos := firstEntryOff
	for i, child := range childOffsets {
		// key = uint64 separator key (用 i 占位)
		key := make([]byte, 8)
		binary.LittleEndian.PutUint64(key, uint64(1000+i))
		// value = uint64 child page offset (LE)
		value := make([]byte, 8)
		binary.LittleEndian.PutUint64(value, uint64(child))

		keyOff := 16
		keyLen := 8
		valOff := keyOff + 8
		valLen := 8
		entrySize := valOff + 8

		binary.LittleEndian.PutUint16(page[pos:], uint16(entrySize))
		binary.LittleEndian.PutUint16(page[pos+2:], uint16(keyOff))
		binary.LittleEndian.PutUint16(page[pos+4:], uint16(keyLen))
		binary.LittleEndian.PutUint16(page[pos+6:], uint16(valOff))
		binary.LittleEndian.PutUint16(page[pos+8:], uint16(valLen))
		copy(page[pos+keyOff:], key)
		copy(page[pos+valOff:], value)
		pos += entrySize
	}
	return page
}

// buildFileNameTLV 按 ExtractFileNameFromTLV 期望的布局构造一个 $FILE_NAME TLV field。
//
// 布局（与 btree_walker.go 注释一致）：
//
//	+0 (2)  tag = 0x0030 (refsFieldFileName)
//	+2 (4)  length = 6 + payload_size
//	+6      payload:
//	   +0x00 (8)   parent object id
//	   +0x08 (8)   created time
//	   +0x10 (8)   modified time
//	   +0x18 (8)   mft_changed time
//	   +0x20 (8)   access time
//	   +0x28 (8)   allocated_size
//	   +0x30 (8)   file_size
//	   +0x38 (4)   file_attributes
//	   +0x3C (1)   name_length (UTF-16 units)
//	   +0x3D (1)   name_type
//	   +0x3E       UTF-16 LE name
func buildFileNameTLV(parentID uint64, name string) []byte {
	units := utf16.Encode([]rune(name))
	if len(units) > 255 {
		panic("name too long for u8 length field")
	}

	payloadSize := 0x3E + len(units)*2
	payload := make([]byte, payloadSize)

	binary.LittleEndian.PutUint64(payload[0:8], parentID)
	// created/modified/mft/access times：留 0（FILETIME 0 = 1601-01-01；ExtractFileName 不校验合理性）
	// allocated/file_size：留 0
	// file_attributes：留 0
	payload[0x3C] = byte(len(units))
	payload[0x3D] = 1 // Win32 type

	for i, u := range units {
		binary.LittleEndian.PutUint16(payload[0x3E+i*2:], u)
	}

	// 包成 TLV：tag (2) + length (4) + payload
	totalLen := 6 + payloadSize
	out := make([]byte, totalLen)
	binary.LittleEndian.PutUint16(out[0:2], refsFieldFileName)
	binary.LittleEndian.PutUint32(out[2:6], uint32(totalLen))
	copy(out[6:], payload)
	return out
}

// 端到端：构造 3 层 B+ tree 后跑 EnumerateFilesViaBTree
func TestEnumerateFilesViaBTree_EndToEnd(t *testing.T) {
	// 卷大小 256KB，足够放 ~16 个 page
	const volSize = 256 * 1024
	data := make([]byte, volSize)

	// page 偏移
	const (
		rootOff      = 0x10000 // 64KB
		internalAOff = 0x14000 // 80KB
		internalBOff = 0x18000 // 96KB
		leaf0Off     = 0x20000 // 128KB
		leaf1Off     = 0x24000 // 144KB
		leaf2Off     = 0x28000 // 160KB
		leaf3Off     = 0x2C000 // 176KB
	)

	// 4 个 leaf：每个 2 entry
	leaves := []struct {
		offset    int64
		baseObjID uint64
		baseName  string
	}{
		{leaf0Off, 100, "alpha"},
		{leaf1Off, 200, "bravo"},
		{leaf2Off, 300, "charlie"},
		{leaf3Off, 400, "delta"},
	}
	for _, l := range leaves {
		page := buildLeafPage(t, 1000, l.baseObjID, l.baseName, 2)
		copy(data[l.offset:], page)
	}

	// 2 个 internal node：每个指向 2 个 leaf
	internalA := buildInternalPage(t, 2000, []int64{leaf0Off, leaf1Off})
	internalB := buildInternalPage(t, 2000, []int64{leaf2Off, leaf3Off})
	copy(data[internalAOff:], internalA)
	copy(data[internalBOff:], internalB)

	// root：最高 LSN，指向 2 个 internal
	root := buildInternalPage(t, 9999, []int64{internalAOff, internalBOff})
	copy(data[rootOff:], root)

	r := &fakeBigReader{data: data}

	// 跑 walker
	entries, err := EnumerateFilesViaBTree(r, 0, volSize)
	if err != nil {
		t.Fatalf("EnumerateFilesViaBTree: %v", err)
	}

	// 验证得到 8 个 entry，文件名涵盖 alpha_0..alpha_1, bravo_0..1, ...
	gotNames := make([]string, 0, len(entries))
	gotIDs := make(map[uint64]bool)
	for _, e := range entries {
		gotNames = append(gotNames, e.FileName)
		gotIDs[e.ObjectID] = true
		if e.ParentID != 99 {
			t.Errorf("entry %s parentID = %d want 99", e.FileName, e.ParentID)
		}
	}
	sort.Strings(gotNames)

	wantNames := []string{
		"alpha_0", "alpha_1", "bravo_0", "bravo_1",
		"charlie_0", "charlie_1", "delta_0", "delta_1",
	}
	wantNamesStr := strings.Join(wantNames, ",")
	gotNamesStr := strings.Join(gotNames, ",")
	if gotNamesStr != wantNamesStr {
		t.Errorf("文件名清单不符:\n  got:  %s\n  want: %s", gotNamesStr, wantNamesStr)
	}

	wantIDs := []uint64{100, 101, 200, 201, 300, 301, 400, 401}
	for _, id := range wantIDs {
		if !gotIDs[id] {
			t.Errorf("缺 ObjectID %d", id)
		}
	}
}

// 单层（root 直接是 leaf）：root_offset=leaf 时也能工作
func TestEnumerateFilesViaBTree_RootIsLeaf(t *testing.T) {
	const volSize = 64 * 1024
	data := make([]byte, volSize)

	// 单 page：leaf at offset 0x4000，含 3 entries
	page := buildLeafPage(t, 5000, 50, "single", 3)
	copy(data[0x4000:], page)

	r := &fakeBigReader{data: data}
	entries, err := EnumerateFilesViaBTree(r, 0, volSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries want 3", len(entries))
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.FileName, "single_") {
			t.Errorf("意外文件名 %s", e.FileName)
		}
	}
}

// 多 root candidate：highest LSN 的应被优先选中
func TestEnumerateFilesViaBTree_PrefersHighestLSN(t *testing.T) {
	const volSize = 128 * 1024
	data := make([]byte, volSize)

	// 老 page (LSN=1)：含 1 entry "old_data"
	old := buildLeafPage(t, 1, 1, "old_data", 1)
	copy(data[0x4000:], old)

	// 新 page (LSN=999)：含 1 entry "new_data"
	new1 := buildLeafPage(t, 999, 2, "new_data", 1)
	copy(data[0x8000:], new1)

	r := &fakeBigReader{data: data}
	entries, err := EnumerateFilesViaBTree(r, 0, volSize)
	if err != nil {
		t.Fatal(err)
	}

	// LSN=999 page 应被作为 root candidate 优先；但因为它是 leaf，应直接出 entries
	// 老 page 也会被作为 candidate（top 5）走一次
	// 所以最终 entries 含 new_data 也含 old_data。新 data 应有
	hasNew := false
	for _, e := range entries {
		if strings.HasPrefix(e.FileName, "new_data") {
			hasNew = true
		}
	}
	if !hasNew {
		t.Error("最高 LSN page 的内容没解出")
	}
}

// 防 cycle：构造 root → internal → root 的环，walker 不应死循环
func TestWalkBTree_CycleDetection(t *testing.T) {
	const volSize = 64 * 1024
	data := make([]byte, volSize)

	// root @ 0x4000 指向 internal @ 0x8000
	root := buildInternalPage(t, 100, []int64{0x8000})
	copy(data[0x4000:], root)
	// internal @ 0x8000 指向 root @ 0x4000（环！）
	internal1 := buildInternalPage(t, 100, []int64{0x4000})
	copy(data[0x8000:], internal1)

	r := &fakeBigReader{data: data}

	visited := 0
	err := WalkBTree(r, 0x4000, 0, volSize, 32, func(key, value []byte, page int64) {
		visited++
	})
	if err != nil {
		t.Errorf("环检测应静默处理, got %v", err)
	}
	// 走的 page 数应有限（visited set 限制每 page 走一次）
	if visited > 10 {
		t.Errorf("可能死循环, visited=%d", visited)
	}
}
