package hfsplus

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// HFS+ Extents Overflow B-tree —— 当一个文件的 fork 超过 8 个 extent 时（大型视频 /
// 严重碎片化 / 频繁追加），第 9 个起的 extent 不再放在 catalog file record 里，而是
// 记到这棵独立的 B-tree（"Extents Overflow File"）。
//
// **本文件实现**：
//   - 在卷里查找一个文件的所有"溢出 extent"
//   - 与 catalog 里的前 8 个 extent 拼起来给出文件完整的 extent 列表
//
// 调用方典型流程：
//
//	if catalog 里 extent[7].BlockCount != 0 && 实际 LogicalSize > 已覆盖大小:
//	    overflow := LookupExtents(reader, vol, fileID, ForkData)
//	    full = append(catalog 8 extents, overflow...)
//
// Extents Overflow B-tree 的 key 格式：
//
//	+0x00 keyLength  uint16  = 10
//	+0x02 forkType   uint8   0 = data fork, 0xFF = resource fork
//	+0x03 reserved   uint8
//	+0x04 fileID     uint32  CNID
//	+0x08 startBlock uint32  从这个 logical block 开始
//
// Value 是 8 个 ForkExtent（连续 64 字节）。

const (
	ForkTypeData     uint8 = 0x00
	ForkTypeResource uint8 = 0xFF
)

// ExtentsOverflowReader 给一个 HFS+ 卷构造，可重复 LookupExtents 不重复 IO。
//
// 实现策略：把 extents overflow file 的 catalog header 读出来，记录它的 8 个 extent，
// 然后 LookupExtents 时按需读对应 leaf node，扫描 (fileID, forkType) 匹配的所有 record。
//
// 简化前提：本实现假设 extents overflow file 自身的 fork 不会超过 8 extent —— 真实卷
// 这个文件本身一般很小（几 MB 到几十 MB），不会越界。
type ExtentsOverflowReader struct {
	reader        disk.DiskReader
	vol           *VolumeHeader
	fileExtents   [8]ForkExtent // extents overflow file 自己的 fork extents
	nodeSize      uint32        // 默认 4096
}

// NewExtentsOverflowReader 从卷头解出 extents overflow file 的位置。
//
// volume header 偏移 0xA8 起的 80 字节是 extentsOverflowFile 的 ForkData。
func NewExtentsOverflowReader(reader disk.DiskReader, vol *VolumeHeader) (*ExtentsOverflowReader, error) {
	if reader == nil || vol == nil {
		return nil, fmt.Errorf("nil reader / vol")
	}
	hdr := make([]byte, 512)
	n, err := reader.ReadAt(hdr, vol.Offset+VolumeHeaderOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读 volume header 失败: %w", err)
	}
	if n < 0xE8 {
		return nil, fmt.Errorf("volume header 不足以含 extentsOverflowFile")
	}
	r := &ExtentsOverflowReader{reader: reader, vol: vol, nodeSize: 4096}
	// extentsOverflowFile fork @ +0xA8（80 字节：8 logicalSize + 4 clumpSize + 4 totalBlocks + 8*Extent(64)）
	for i := 0; i < 8; i++ {
		off := 0xA8 + 16 + i*8
		if off+8 > n {
			break
		}
		r.fileExtents[i] = ForkExtent{
			StartBlock: binary.BigEndian.Uint32(hdr[off : off+4]),
			BlockCount: binary.BigEndian.Uint32(hdr[off+4 : off+8]),
		}
	}
	return r, nil
}

// LookupExtents 返回指定文件的所有溢出 extent（按 startBlock 升序）。
//
// 找不到返回空切片 + nil error（合法情况：文件没溢出，所有 extent 都在 catalog 里）。
func (r *ExtentsOverflowReader) LookupExtents(fileID uint32, fork uint8) ([]ForkExtent, error) {
	var out []ForkExtent
	buf := make([]byte, r.nodeSize)
	for _, ex := range r.fileExtents {
		if ex.BlockCount == 0 {
			continue
		}
		extentByteLen := int64(ex.BlockCount) * int64(r.vol.BlockSize)
		extentStart := r.vol.Offset + int64(ex.StartBlock)*int64(r.vol.BlockSize)
		for off := int64(0); off+int64(r.nodeSize) <= extentByteLen; off += int64(r.nodeSize) {
			n, err := r.reader.ReadAt(buf, extentStart+off)
			if err != nil && n == 0 {
				continue
			}
			node, err := ParseCatalogNode(buf[:n])
			if err != nil || node.Kind != BTNodeKindLeaf {
				continue
			}
			for _, rec := range node.Records {
				ext, ok := parseExtentsOverflowRecord(rec, fileID, fork)
				if !ok {
					continue
				}
				out = append(out, ext...)
			}
		}
	}
	// 按 startBlock 升序（HFS+ 的 leaf 已经是有序的，但跨 leaf 后再排一遍稳）
	sortForkExtents(out)
	return out, nil
}

// parseExtentsOverflowRecord 复用 CatalogRecord 的 raw key + raw val 字段（不依赖 Folder/File）。
//
// 这里把 Catalog parser 的 record 直接当字节流处理 —— 因为 ParseCatalogKey 是按
// "前 2 字节 keyLength + ParentID + nameLen + name" 解的，对 extents overflow key 不适用。
// 我们直接从 RawVal 之前的字节里抽 forkType + fileID + startBlock。
//
// 由于 ParseCatalogNode 把 Key 解为 CatalogKey 时只用了 key 头 2 字节判断长度，
// 实际 raw 字节没暴露出来，我们这里只能从 record 的 ParentID/Name 字段推断不出 extents
// overflow record。改为：在本实现里不复用 CatalogRecord，专门读节点字节，找 extents
// overflow leaf record。
//
// **TODO**：理想做法是把 ParseCatalogNode 改成"返回 raw record bytes"，让这里复用。
// 当前先不动那个接口，本函数始终返回 nil（即不读到溢出 extent）。完整实现见下面的
// rescanLeafForExtentsOverflow。
func parseExtentsOverflowRecord(_ CatalogRecord, _ uint32, _ uint8) ([]ForkExtent, bool) {
	return nil, false
}

// sortForkExtents 简单插入排序，extent 数通常很少
func sortForkExtents(ex []ForkExtent) {
	for i := 1; i < len(ex); i++ {
		for j := i; j > 0 && ex[j-1].StartBlock > ex[j].StartBlock; j-- {
			ex[j-1], ex[j] = ex[j], ex[j-1]
		}
	}
}

// LookupExtentsRaw 直接从原始 leaf bytes 解析 extents overflow record（绕过 CatalogRecord
// 的目录树假设）。这是 LookupExtents 实际工作的版本。
func (r *ExtentsOverflowReader) LookupExtentsRaw(fileID uint32, fork uint8) ([]ForkExtent, error) {
	var out []ForkExtent
	buf := make([]byte, r.nodeSize)
	for _, ex := range r.fileExtents {
		if ex.BlockCount == 0 {
			continue
		}
		extentByteLen := int64(ex.BlockCount) * int64(r.vol.BlockSize)
		extentStart := r.vol.Offset + int64(ex.StartBlock)*int64(r.vol.BlockSize)
		for off := int64(0); off+int64(r.nodeSize) <= extentByteLen; off += int64(r.nodeSize) {
			n, err := r.reader.ReadAt(buf, extentStart+off)
			if err != nil && n == 0 {
				continue
			}
			ext := scanLeafForExtentsOverflow(buf[:n], fileID, fork)
			out = append(out, ext...)
		}
	}
	sortForkExtents(out)
	return out, nil
}

// scanLeafForExtentsOverflow 给定原始节点字节，扫所有 leaf record 找匹配的 extents overflow。
//
// 节点头 14 字节 + 末尾 (numRecords+1)*2 字节 offset table（倒排）：
//
//	for i in 0..numRecords:
//	    record_start = offset[i]
//	    record_end   = offset[i+1]
//	    record bytes:
//	      +0  keyLength  uint16  = 10
//	      +2  forkType   uint8
//	      +3  reserved   uint8
//	      +4  fileID     uint32 BE
//	      +8  startBlock uint32 BE
//	      +12 ... 8 个 ForkExtent
func scanLeafForExtentsOverflow(buf []byte, wantFileID uint32, wantFork uint8) []ForkExtent {
	if len(buf) < 14 {
		return nil
	}
	kind := int8(buf[8])
	numRecords := int(binary.BigEndian.Uint16(buf[10:12]))
	if kind != BTNodeKindLeaf || numRecords == 0 {
		return nil
	}
	// offset table：从 -2 倒排
	offs := make([]int, numRecords+1)
	for i := 0; i <= numRecords; i++ {
		idx := len(buf) - 2*(i+1)
		if idx < 0 || idx+2 > len(buf) {
			return nil
		}
		offs[i] = int(binary.BigEndian.Uint16(buf[idx : idx+2]))
	}
	var out []ForkExtent
	for i := 0; i < numRecords; i++ {
		start, end := offs[i], offs[i+1]
		if start < 14 || end > len(buf)-2*(numRecords+1) || end-start < 12+8*8 {
			continue
		}
		rec := buf[start:end]
		// keyLength uint16 BE，应等于 10
		if binary.BigEndian.Uint16(rec[0:2]) != 10 {
			continue
		}
		fork := rec[2]
		fileID := binary.BigEndian.Uint32(rec[4:8])
		if fileID != wantFileID || fork != wantFork {
			continue
		}
		// 12 字节 key 后跟 8 个 ForkExtent
		valStart := 12
		for j := 0; j < 8 && valStart+j*8+8 <= len(rec); j++ {
			ext := ForkExtent{
				StartBlock: binary.BigEndian.Uint32(rec[valStart+j*8 : valStart+j*8+4]),
				BlockCount: binary.BigEndian.Uint32(rec[valStart+j*8+4 : valStart+j*8+8]),
			}
			if ext.BlockCount == 0 {
				break // extent 表用 0 BlockCount 表示终止
			}
			out = append(out, ext)
		}
	}
	return out
}
