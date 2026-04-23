package carver

// MP4 / MOV atom stitcher —— 基于 box (atom) 链自述结构的碎片重组。
//
// ISO BMFF (MP4 / MOV / HEIF / fMP4) 是自述 box 链：
//   box = { size:4 BE, type:4 ASCII, [extended_size:8 if size==1], data:... }
//
// 合法 top-level box type（按 ISO/IEC 14496-12 + Apple QuickTime）：
//   ftyp  File Type            —— 必为第一个
//   moov  Movie metadata        —— 含 trak / mdia / stbl 等；解码全靠它
//   mdat  Media Data           —— 最大的一块（实际 audio/video bits）
//   free  Free space
//   skip  Skippable
//   wide  64-bit size marker
//   uuid  User type (custom)
//   moof  Movie Fragment       —— 分片 MP4 (streaming)
//   mfra  Movie Fragment Random Access
//   meta  Metadata container
//   pdin  Progressive Download info
//
// 重组策略：
//   1. 验第一个 box 是 ftyp（MP4 必须；MOV 常也 ftyp 开头，早期 MOV 偶尔 wide+mdat 起手）
//   2. 按 size 字段跳到下一个 box，验 type 是合法 4cc
//   3. 合法 → 继续；非法 → 断点：在窗口内扫所有 "合法 box type magic"
//   4. 对候选位置读 size 字段验证 "下一个 size 也合法"（降假阳性）
//   5. 命中 moov 末端 或文件结构 obvious 完成时停
//
// 强完整性：moov 必须存在；如果 stitch 完没 moov，视为低置信。
//
// 覆盖范围：
//   ✅ 单次 / 有限次 box-level 断点
//   ✅ 自述 size 做硬边界
//   ❌ box 内部 sample table 的碎片化（mdat 内 sample offsets 散乱时无法重建）
//   ❌ 加密 box (senc/saiz)

import (
	"encoding/binary"
	"fmt"

	"data-recovery/internal/disk"
)

// MP4StitchResult 重组输出
type MP4StitchResult struct {
	Data          []byte  // 重组字节流（box 顺序 = 原盘顺序 + 断点跳过的 garbage 被跳掉）
	Boxes         []BoxInfo
	FragmentsHit  int
	HasMoov       bool    // 关键：没 moov 等于无法解码
	HasFtyp       bool
	HasMdat       bool
	ConfidenceHex float32
	Notes         string
}

type BoxInfo struct {
	Offset int64
	Size   int64
	Type   string
}

// MP4Stitcher 配置
type MP4Stitcher struct {
	Reader          disk.DiskReader
	MaxSearchWindow int64
	MaxOutputBytes  int64
}

func NewMP4Stitcher(r disk.DiskReader) *MP4Stitcher {
	return &MP4Stitcher{
		Reader:          r,
		MaxSearchWindow: 64 * 1024 * 1024,
		MaxOutputBytes:  1024 * 1024 * 1024, // 1GB — 视频文件常大，但要有上限
	}
}

// 合法 top-level box type 白名单
var mp4ValidTopBoxes = map[string]bool{
	"ftyp": true, "moov": true, "mdat": true, "free": true, "skip": true,
	"wide": true, "uuid": true, "moof": true, "mfra": true, "meta": true,
	"pdin": true, "bloc": true, "ssix": true, "sidx": true, "styp": true,
	// Apple-specific
	"pnot": true, "PICT": true, "pict": true,
	// HEIF
	"mdia": true,
}

// Stitch 从 mp4Start 开始尝试重组。mp4Start 必须是第一个 box（通常 ftyp）的字节位置。
func (s *MP4Stitcher) Stitch(mp4Start int64) (*MP4StitchResult, error) {
	out := make([]byte, 0, 1024*1024)
	result := &MP4StitchResult{}
	pos := mp4Start

	for {
		if int64(len(out)) > s.MaxOutputBytes {
			return nil, fmt.Errorf("MP4 重组超过 %d 字节上限", s.MaxOutputBytes)
		}

		hdr := make([]byte, 16) // 足够容纳 64-bit extended size
		n, err := s.Reader.ReadAt(hdr, pos)
		if err != nil || n < 8 {
			break
		}
		size := int64(binary.BigEndian.Uint32(hdr[0:4]))
		boxType := string(hdr[4:8])
		hdrSize := int64(8)

		// size==1 → 读 8 字节 extended size
		if size == 1 {
			if n < 16 {
				break
			}
			size = int64(binary.BigEndian.Uint64(hdr[8:16]))
			hdrSize = 16
		}
		// size==0 → box 延伸到 EOF（合法但 stitch 里处理麻烦）
		if size == 0 {
			if !mp4ValidTopBoxes[boxType] {
				break
			}
			// 把从 pos 到 EOF 的当成这个 box
			diskSize, _ := s.Reader.Size()
			size = diskSize - pos
		}

		// 验 box type
		if !mp4ValidTopBoxes[boxType] {
			if s.MaxSearchWindow <= 0 {
				break
			}
			nextPos, found := s.searchNextBox(pos+1, s.MaxSearchWindow)
			if !found {
				break
			}
			result.FragmentsHit++
			pos = nextPos
			continue
		}

		// size 合理性检查
		if size < hdrSize || size > s.MaxOutputBytes {
			break
		}

		// 把整个 box（header + data）追加到 output
		box := make([]byte, size)
		m, _ := s.Reader.ReadAt(box, pos)
		if int64(m) < size {
			// 读不全 —— 仍先追加已读的部分，然后中止
			box = box[:m]
			out = append(out, box...)
			result.Boxes = append(result.Boxes, BoxInfo{Offset: pos, Size: int64(m), Type: boxType})
			break
		}
		out = append(out, box...)
		result.Boxes = append(result.Boxes, BoxInfo{Offset: pos, Size: size, Type: boxType})

		switch boxType {
		case "ftyp":
			result.HasFtyp = true
		case "moov":
			result.HasMoov = true
		case "mdat":
			result.HasMdat = true
		}
		pos += size
	}

	result.Data = out
	switch {
	case result.HasMoov && result.HasMdat && result.FragmentsHit == 0:
		result.ConfidenceHex = 1.0
		result.Notes = "连续 + 含 moov/mdat，最高置信"
	case result.HasMoov && result.HasMdat:
		result.ConfidenceHex = 0.85
		result.Notes = fmt.Sprintf("有 %d 次 box 断点但 moov/mdat 都重建成功", result.FragmentsHit)
	case result.HasMoov:
		result.ConfidenceHex = 0.7
		result.Notes = "有 moov 但没 mdat（视频数据缺失，仅元数据）"
	case result.HasMdat:
		result.ConfidenceHex = 0.4
		result.Notes = "有 mdat 但没 moov（无法解码）"
	default:
		result.ConfidenceHex = 0.1
		result.Notes = "关键 box 缺失"
	}
	return result, nil
}

// searchNextBox 在 [start, start+window) 找下一个合法 box
func (s *MP4Stitcher) searchNextBox(start, window int64) (int64, bool) {
	if window > s.MaxSearchWindow {
		window = s.MaxSearchWindow
	}
	const step int64 = 512
	buf := make([]byte, step+16)
	for probe := start; probe < start+window; probe += step {
		n, _ := s.Reader.ReadAt(buf, probe)
		if n < 8 {
			continue
		}
		for i := 0; i+8 <= n; i++ {
			boxType := string(buf[i+4 : i+8])
			if !mp4ValidTopBoxes[boxType] {
				continue
			}
			size := int64(binary.BigEndian.Uint32(buf[i : i+4]))
			if size == 1 && i+16 <= n {
				size = int64(binary.BigEndian.Uint64(buf[i+8 : i+16]))
			}
			// size 合理性：8..1GB
			if size < 8 || size > 1024*1024*1024 {
				continue
			}
			// 确认是 box 而非巧合的 4 字节匹配：探测下一个 box 位置
			// （合法文件 box 连续出现）
			nextPos := probe + int64(i) + size
			if nextPos < start+window {
				nextHdr := make([]byte, 8)
				nm, _ := s.Reader.ReadAt(nextHdr, nextPos)
				if nm == 8 {
					nextType := string(nextHdr[4:8])
					if mp4ValidTopBoxes[nextType] {
						return probe + int64(i), true
					}
				}
			} else {
				// 单 box 命中也接受（可能是最后一个 box）
				return probe + int64(i), true
			}
		}
	}
	return 0, false
}
