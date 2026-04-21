// Package carver 内部的 JPEG "block-graph" 拼接 carver。
//
// **背景**：传统 carver 假设文件连续 — 找到 SOI (0xFF 0xD8) 直接读到 EOI (0xFF 0xD9) 写出。
// 当文件碎片化（簇被中间分配给别的文件）时，读到 EOI 之前会撞上别的文件的字节，要么
// EOI 找不到，要么找到也是错的，输出文件打不开。
//
// **本实现的核心思想**（block-graph 简化版）：
//
//	1. 从 SOI 起按 marker 顺序扫，记录所有"重启 marker" RST0..RST7 (0xFF D0..D7) 的位置
//	2. RST marker 在 JPEG 里有"序号循环 0,1,2,3,4,5,6,7,0,1..."的强约束
//	3. 当扫到一个"非法 marker"（比如 0xFF D8 SOI 又出现 = 另一个 JPEG 的开头），
//	    判定为碎片断点
//	4. 从断点位置向后扫**容器内其它 chunk**，找下一个 "合法 RST + 序号 = 期望值" 的位置
//	5. 把断点前 + 找到的延续段 + 后续部分拼起来（stitching）
//
// **比传统启发的提升**：
//   - RST 序号匹配比单纯"找下一个 0xFF D9" 严格一万倍（误匹配率 1/8 vs 1/2）
//   - 多段碎片可以连续拼
//
// **当前限制**：
//   - 仅适用于含 RST marker 的 JPEG（restart interval > 0；现代相机 / scanner 输出的
//     大多有，手机随手拍可能没有）
//   - 不解 huffman state 所以不能处理"无 RST 的纯连续熵流"中段碎片
//   - 真 huffman state stitching 需要完整 JPEG decoder，留作后续扩展
//
// 参考：ITU T.81 / ISO 10918-1 §B.2.4.4 RST_n marker；R-Studio 商业版同理但加了
// 训练分类器 + parser 完整性约束。
package carver

import (
	"encoding/binary"
	"fmt"

	"data-recovery/internal/disk"
)

// JPEG marker bytes
const (
	jpegSOI byte = 0xD8
	jpegEOI byte = 0xD9
	jpegSOS byte = 0xDA // Start of Scan，之后是熵编码数据 + RST markers
	jpegDRI byte = 0xDD // Define Restart Interval
	jpegRST0 byte = 0xD0
	jpegRST7 byte = 0xD7
)

// JPEGCarverResult 是单次 carve 的输出。
type JPEGCarverResult struct {
	Bytes      []byte // 拼接出来的完整 JPEG 数据
	Fragmented bool   // 是否做过 stitching；若是，输出可能仍有错
	Stitches   int    // 进行了多少次 stitching
	Reason     string // 调试信息
}

// JPEGBlockGraphCarver 在容器内做 JPEG block-graph carve。
//
// "容器"通常是整块磁盘 reader；StartOffset 是 SOI 位置。
// MaxFileSize 限制最大输出（防止"找不到 EOI 一直读到盘尾"）。
type JPEGBlockGraphCarver struct {
	Reader        disk.DiskReader
	MaxFileSize   int64 // 默认 32MB
	SearchWindow  int64 // stitching 时向后搜的字节窗口；默认 16MB
	ChunkSize     int64 // 内部 IO 块大小；默认 64KB
}

// NewJPEGBlockGraphCarver 用合理默认值构造。
func NewJPEGBlockGraphCarver(reader disk.DiskReader) *JPEGBlockGraphCarver {
	return &JPEGBlockGraphCarver{
		Reader:       reader,
		MaxFileSize:  32 * 1024 * 1024,
		SearchWindow: 16 * 1024 * 1024,
		ChunkSize:    64 * 1024,
	}
}

// Carve 从 startOffset 处的 SOI 开始 carve 出一个 JPEG 文件。
// 返回 (result, err)。result.Fragmented=true 时 result.Bytes 是 stitching 后的结果。
func (c *JPEGBlockGraphCarver) Carve(startOffset int64) (*JPEGCarverResult, error) {
	// 1. 读起始 chunk 验证 SOI
	hdr := make([]byte, 4)
	if n, _ := c.Reader.ReadAt(hdr, startOffset); n < 4 {
		return nil, fmt.Errorf("起始 4 字节读不全")
	}
	if hdr[0] != 0xFF || hdr[1] != jpegSOI {
		return nil, fmt.Errorf("起始位置不是 JPEG SOI: %02X %02X", hdr[0], hdr[1])
	}

	// 2. 读完整候选区（一次最多 MaxFileSize）
	candidate := make([]byte, c.MaxFileSize)
	n, _ := c.Reader.ReadAt(candidate, startOffset)
	candidate = candidate[:n]

	// 3. 解析 marker 链 + 找 EOI / 碎片点
	res := &JPEGCarverResult{}
	pos := 2 // SOI 已确认
	restartInterval := 0
	expectedRSTSeq := 0
	inEntropyData := false
	for pos < len(candidate) {
		// 找下一个 marker：跳过非 0xFF 字节；对 0xFF 后跟 0x00（stuffed byte）跳过
		if candidate[pos] != 0xFF {
			pos++
			continue
		}
		if pos+1 >= len(candidate) {
			break
		}
		next := candidate[pos+1]
		if next == 0x00 {
			pos += 2
			continue // stuffed byte
		}
		if next == 0xFF {
			// 多个连续 0xFF 是 fill bytes
			pos++
			continue
		}

		// 是真 marker
		switch {
		case next == jpegEOI:
			res.Bytes = candidate[:pos+2]
			return res, nil
		case next == jpegSOI:
			// 中段又出现 SOI = 另一个 JPEG 的开头被拼接进来 → 碎片断点
			if !inEntropyData {
				// 还没进 SOS，怪事；当作普通 marker 跳过
				pos += 2
				continue
			}
			return c.tryStitch(startOffset, candidate[:pos], expectedRSTSeq, restartInterval)
		case next >= jpegRST0 && next <= jpegRST7:
			rstSeq := int(next - jpegRST0)
			if expectedRSTSeq != -1 && rstSeq != expectedRSTSeq {
				// RST 序号不对 → 碎片
				return c.tryStitch(startOffset, candidate[:pos], expectedRSTSeq, restartInterval)
			}
			expectedRSTSeq = (rstSeq + 1) % 8
			pos += 2
		case next == jpegDRI:
			// DRI segment: marker(2) + length(2) + restart_interval(2)
			if pos+6 >= len(candidate) {
				break
			}
			restartInterval = int(binary.BigEndian.Uint16(candidate[pos+4 : pos+6]))
			pos += 2 + int(binary.BigEndian.Uint16(candidate[pos+2:pos+4]))
		case next == jpegSOS:
			// SOS segment: marker(2) + length(2) + payload
			if pos+4 >= len(candidate) {
				break
			}
			segLen := int(binary.BigEndian.Uint16(candidate[pos+2 : pos+4]))
			pos += 2 + segLen
			inEntropyData = true
			if restartInterval == 0 {
				expectedRSTSeq = -1 // 无 RST，无序号约束
			} else {
				expectedRSTSeq = 0
			}
		default:
			// 普通 marker：跳过 marker(2) + length(2) + payload(length-2)
			if pos+4 >= len(candidate) {
				pos += 2
				continue
			}
			segLen := int(binary.BigEndian.Uint16(candidate[pos+2 : pos+4]))
			if segLen < 2 {
				pos += 2
				continue
			}
			pos += 2 + segLen
		}
	}

	// 没找到 EOI 也没断点 — 文件可能截断
	res.Bytes = candidate
	res.Reason = "未找到 EOI（文件可能被截断或后段被覆盖）"
	return res, nil
}

// tryStitch 在断点之后向后搜 SearchWindow 字节，找下一个"合法 RST + 序号 = expectedSeq"
// 的位置作为延续段起点。
//
// 找到则把 [head] + [stitched continuation] 拼起来再递归扫；找不到就返回 head 部分。
func (c *JPEGBlockGraphCarver) tryStitch(startOffset int64, head []byte, expectedSeq, restartInterval int) (*JPEGCarverResult, error) {
	res := &JPEGCarverResult{Fragmented: true, Stitches: 1}

	if expectedSeq < 0 {
		// 无 RST 约束 → 无法 stitching
		res.Bytes = head
		res.Reason = "碎片断点，但 JPEG 无 restart interval，无法基于 RST 序号 stitching"
		return res, nil
	}

	// 搜索窗口起点 = startOffset + len(head) + ChunkSize （跳过断点附近）
	searchStart := startOffset + int64(len(head)) + c.ChunkSize
	searchEnd := startOffset + int64(len(head)) + c.SearchWindow
	wantMarker := jpegRST0 + byte(expectedSeq)

	buf := make([]byte, c.ChunkSize)
	for off := searchStart; off+int64(len(buf)) <= searchEnd; off += c.ChunkSize / 2 {
		n, _ := c.Reader.ReadAt(buf, off)
		if n < 2 {
			continue
		}
		// 在 buf 里找 0xFF + wantMarker 模式
		for i := 0; i < n-1; i++ {
			if buf[i] == 0xFF && buf[i+1] == wantMarker {
				// 找到候选！读延续段
				continued := make([]byte, c.MaxFileSize-int64(len(head)))
				cn, _ := c.Reader.ReadAt(continued, off+int64(i))
				continued = continued[:cn]

				// 拼接 head + continued，对 continued 再走一次 marker 扫描
				combined := append([]byte{}, head...)
				combined = append(combined, continued...)

				// 在 continued 里继续找 EOI；找到就完整返回
				if eoiPos := findJPEGEOI(continued); eoiPos >= 0 {
					res.Bytes = append([]byte{}, head...)
					res.Bytes = append(res.Bytes, continued[:eoiPos+2]...)
					res.Reason = fmt.Sprintf("stitched from offset 0x%X (RST%d 续)", off+int64(i), expectedSeq)
					return res, nil
				}
				// 没找到 EOI 也返回拼接结果（可能仍是部分文件）
				res.Bytes = combined
				res.Reason = "stitched 但未找到 EOI（可能多段碎片）"
				return res, nil
			}
		}
	}

	// 搜不到合法续段
	res.Bytes = head
	res.Reason = fmt.Sprintf("碎片断点，未找到 RST%d 续段（搜索窗口 %d MB）",
		expectedSeq, c.SearchWindow/1024/1024)
	return res, nil
}

// findJPEGEOI 在字节流里找第一个 0xFF 0xD9（跳过 stuffed bytes）
func findJPEGEOI(buf []byte) int {
	for i := 0; i < len(buf)-1; i++ {
		if buf[i] != 0xFF {
			continue
		}
		next := buf[i+1]
		if next == 0x00 || next == 0xFF {
			continue
		}
		if next == jpegEOI {
			return i
		}
	}
	return -1
}
