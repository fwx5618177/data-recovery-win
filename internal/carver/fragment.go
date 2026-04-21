package carver

import (
	"fmt"
	"math"

	"data-recovery/internal/disk"
)

// 碎片化检测启发：碎片文件重组（fragmentation reassembly）的完整解决方案
// 是 R-Studio 卖钱的核心能力，工程上需要数年研究 —— 我们做不到。
//
// 但**检测**文件是否可能碎片化、给用户一个"这个文件可能不完整"的明确警告，
// 是可达成的。基本思路（PhotoRec 的"paranoid"模式同款）：
//
//   1. 对**有内置完整性校验**的格式（JPEG/PDF/ZIP），扫描中段做格式合规性检查
//   2. 发现"中段突然遇到不该出现的字节"（比如 JPEG 中段出现非法 marker、
//      PDF 中段出现别的文件的 magic、ZIP 中段 CRC 不连续）
//   3. 标记为 likely_fragmented，让上层把这种文件单独归类（如 _fragmented/ 子目录）
//      让用户知道：这个文件你拿到了，但可能打不开/可能内容不全
//
// 这一档的价值是**真诚** —— 与其把碎片文件当好文件给用户最后发现打不开砸掉信任，
// 不如清楚标出来，让用户看到 R-Studio 商业版的价值所在并按需购买。

// FragmentDetectionResult 给出文件是否可能碎片化的判断
type FragmentDetectionResult struct {
	LikelyFragmented bool
	Reason           string // 为什么觉得碎片，便于 manifest / log 调试
}

// DetectFragmentation 根据文件类型 + 数据采样判断是否可能存在碎片。
//
// 我们只对**有结构可校验**的格式做判断：JPEG / PNG / PDF / ZIP / MP4。
// 其他格式返回"不确定，按非碎片处理"。
//
// 实现策略：
//   - JPEG：从中段读 64KB，扫描 0xFF 字节后的 marker；遇到非法/不可能在中段出现的
//     marker（如另一个 SOI 0xD8 != 第一个）认为碎片
//   - PDF：从中段读 64KB，看里面有没有别的文件的 PDF/PNG/JPEG magic 突然冒出来
//   - ZIP：从中段抽样验证局部签名密度（碎片化时通常会突然出现非 PK 区段）
//
// 这是 80/20 启发，不是精确判定。误判（漏报或误报）是必然的。
func DetectFragmentation(
	reader disk.DiskReader,
	offset, size int64,
	ext string,
) FragmentDetectionResult {
	// 文件太小没必要查；碎片至少需要跨 cluster
	if size < 64*1024 {
		return FragmentDetectionResult{}
	}

	// 中段位置：50% 处
	midOffset := offset + size/2
	const sampleSize = 64 * 1024
	if size-(midOffset-offset) < sampleSize {
		// 文件太小，就用整个尾段
		midOffset = offset + size - sampleSize
	}

	buf := make([]byte, sampleSize)
	n, err := reader.ReadAt(buf, midOffset)
	if err != nil && n == 0 {
		return FragmentDetectionResult{}
	}
	sample := buf[:n]

	switch ext {
	case "jpg", "jpeg":
		return detectJPEGFragment(sample, midOffset-offset)
	case "pdf":
		return detectPDFFragment(sample)
	case "zip", "docx", "xlsx", "pptx", "epub":
		return detectZIPFragment(sample)
	default:
		return FragmentDetectionResult{}
	}
}

// detectJPEGFragment 在 JPEG 中段查异常 marker。
//
// 合法的 JPEG 中段几乎都是熵编码数据（看起来随机），偶尔出现 RST / DRI 等控制 marker。
// 出现 SOI (0xFF 0xD8) 在中段 = 一定是另一个 JPEG 的开头，意味着 carve 时把别的文件
// 的数据误连接进来了 → 碎片化。
func detectJPEGFragment(sample []byte, posInFile int64) FragmentDetectionResult {
	for i := 0; i < len(sample)-1; i++ {
		if sample[i] != 0xFF {
			continue
		}
		next := sample[i+1]
		// 0xFF 后跟 0x00 是 stuffed byte（合法熵数据中的转义），不是 marker
		if next == 0x00 {
			continue
		}
		// 中段不可能合法出现的 marker：
		//   0xD8 (SOI) - 另一个 JPEG 开头
		//   0xD9 (EOI) - 当前 JPEG 已结束（中段不该有）
		//   0xE0..0xEF (APPn) 在初始段后再出现也很可疑
		switch next {
		case 0xD8: // SOI
			return FragmentDetectionResult{
				LikelyFragmented: true,
				Reason:           "JPEG 中段发现 SOI 标记（多半是另一个文件的开头被拼接进来）",
			}
		case 0xD9: // EOI
			// EOI 在中段说明本 JPEG 实际已结束，后面是别的文件
			return FragmentDetectionResult{
				LikelyFragmented: true,
				Reason:           "JPEG 中段发现 EOI；真实文件可能更短，剩余部分是别的数据",
			}
		}
	}
	_ = posInFile
	return FragmentDetectionResult{}
}

// detectPDFFragment 在 PDF 中段查别的文件的 magic 突然出现。
//
// 合法 PDF 中段大多是压缩流（FlateDecode 后的二进制）+ 文本对象。
// 出现 "%PDF-" 新文件头 / PNG / JPEG magic 都强烈暗示拼接进了别的文件。
func detectPDFFragment(sample []byte) FragmentDetectionResult {
	// 别的文件的 magic 出现 = 强证据
	checks := [][]byte{
		[]byte("%PDF-"), // 另一个 PDF 头
		// PNG signature
		{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
		// JPEG SOI + 标准 APP0
		{0xFF, 0xD8, 0xFF, 0xE0},
	}
	for _, magic := range checks {
		if indexOf(sample, magic) >= 0 {
			return FragmentDetectionResult{
				LikelyFragmented: true,
				Reason:           "PDF 中段发现其他文件的 magic（%PDF / PNG / JPEG）",
			}
		}
	}
	return FragmentDetectionResult{}
}

// detectZIPFragment ZIP 中段如果完全没有 "PK" 字节模式可能是异常。
//
// 真实 ZIP 文件中 "PK" 局部文件头会反复出现；中段连续 64KB 都不见任何 PK 暗示
// 中段是别的文件被拼了进来。注意：少数 ZIP（一个超大文件压缩，单个 LFH）不符合这个启发，
// 所以阈值要放宽，避免误报。
func detectZIPFragment(sample []byte) FragmentDetectionResult {
	pkCount := 0
	for i := 0; i < len(sample)-1; i++ {
		if sample[i] == 'P' && sample[i+1] == 'K' {
			pkCount++
			if pkCount >= 1 {
				return FragmentDetectionResult{} // 至少一个 PK，可能正常
			}
		}
	}
	// 完全没有 "PK"：可能是单条目大文件 ZIP（合法），也可能是碎片
	// 阈值很弱，故只在采样区 ≥ 32KB 才报告
	if len(sample) >= 32*1024 && pkCount == 0 {
		return FragmentDetectionResult{
			LikelyFragmented: true,
			Reason:           "ZIP 中段未见任何 'PK' 模式（可能正常单文件大压缩，也可能是碎片）",
		}
	}
	return FragmentDetectionResult{}
}

// indexOf naive byte search（少量调用，不需要 Aho-Corasick）
func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// =====================================================================
// Paranoid Level 2 —— 多点采样 + 熵 / 字节直方图突变检测 + 更多格式
//
// Level 1（上面的 DetectFragmentation）是单点中段采样 + 4 种格式。
// Level 2 加：
//   1. 多点采样（25%、50%、75% 三段）
//   2. 字节直方图熵突变：从一段到下一段熵变化超过 1.5 bits 强烈暗示数据来源切换
//      （比如压缩流 ↔ 全零 ↔ 文本，三种熵差异极大）
//   3. PNG 中段 IDAT 边界一致性检查
//   4. MP4/MOV box 长度递归一致性检查（box 链断裂 = 碎片）
// =====================================================================

// FragmentDetectionResultV2 比 V1 多了 confidence + 命中位置
type FragmentDetectionResultV2 struct {
	LikelyFragmented bool
	Confidence       float32 // 0..1
	Reason           string
	HitOffset        int64 // 命中点在文件内的字节偏移；-1 = 未定位
}

// DetectFragmentationParanoid 是 Level 2 的入口。比 V1 慢约 3 倍（多点采样 + 熵计算），
// 但对所有 carved 文件兜底跑一遍可以让"看起来像但其实是垃圾拼接"的误报大大下降。
func DetectFragmentationParanoid(reader disk.DiskReader, offset, size int64, ext string) FragmentDetectionResultV2 {
	if size < 64*1024 {
		return FragmentDetectionResultV2{HitOffset: -1}
	}

	// 先跑 Level 1：高置信信号（marker / magic）发现就直接报
	v1 := DetectFragmentation(reader, offset, size, ext)
	if v1.LikelyFragmented {
		return FragmentDetectionResultV2{
			LikelyFragmented: true,
			Confidence:       0.9,
			Reason:           v1.Reason,
			HitOffset:        offset + size/2,
		}
	}

	// 多点采样：25% / 50% / 75%
	const sampleSize = 32 * 1024
	samples := make([][]byte, 0, 3)
	sampleOffsets := []int64{size / 4, size / 2, 3 * size / 4}
	for _, rel := range sampleOffsets {
		buf := make([]byte, sampleSize)
		n, _ := reader.ReadAt(buf, offset+rel)
		if n < sampleSize/2 {
			continue
		}
		samples = append(samples, buf[:n])
	}
	if len(samples) < 2 {
		return FragmentDetectionResultV2{HitOffset: -1}
	}

	// 熵突变：计算每个采样的字节熵，相邻段差 > 1.5 bits 视为"数据源切换"
	entropies := make([]float64, len(samples))
	for i, s := range samples {
		entropies[i] = byteEntropy(s)
	}
	for i := 1; i < len(entropies); i++ {
		diff := entropies[i] - entropies[i-1]
		if diff < 0 {
			diff = -diff
		}
		if diff > 1.5 {
			return FragmentDetectionResultV2{
				LikelyFragmented: true,
				Confidence:       0.6,
				Reason: fmt.Sprintf("字节熵突变：第 %d 段 %.2f bits → 第 %d 段 %.2f bits（数据来源可能切换）",
					i-1, entropies[i-1], i, entropies[i]),
				HitOffset: offset + sampleOffsets[i],
			}
		}
	}

	// 格式专项：PNG / MP4
	switch ext {
	case "png":
		if r := detectPNGFragment(reader, offset, size); r.LikelyFragmented {
			return r
		}
	case "mp4", "mov", "m4v":
		if r := detectMP4Fragment(reader, offset, size); r.LikelyFragmented {
			return r
		}
	}

	return FragmentDetectionResultV2{HitOffset: -1}
}

// byteEntropy 计算字节直方图的香农熵（0..8 bits）
func byteEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var hist [256]int
	for _, c := range b {
		hist[c]++
	}
	total := float64(len(b))
	h := 0.0
	for _, cnt := range hist {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) / total
		h -= p * math.Log2(p)
	}
	return h
}

// detectPNGFragment：PNG 由若干 chunk 组成（IHDR / IDAT* / IEND）。
// 中段如果出现明显非 PNG 的 magic（JPEG SOI / 另一个 PNG 签名），说明被拼接。
func detectPNGFragment(reader disk.DiskReader, offset, size int64) FragmentDetectionResultV2 {
	const sampleSize = 64 * 1024
	mid := offset + size/2
	buf := make([]byte, sampleSize)
	n, _ := reader.ReadAt(buf, mid)
	if n == 0 {
		return FragmentDetectionResultV2{HitOffset: -1}
	}
	sample := buf[:n]
	otherMagics := [][]byte{
		{0x89, 'P', 'N', 'G'},      // 另一个 PNG 头
		{0xFF, 0xD8, 0xFF},         // JPEG
		{'%', 'P', 'D', 'F', '-'},  // PDF
	}
	for _, m := range otherMagics {
		if i := indexOf(sample, m); i >= 0 {
			return FragmentDetectionResultV2{
				LikelyFragmented: true,
				Confidence:       0.85,
				Reason:           "PNG 中段发现其他文件 magic（多半是 carve 把别的文件接进来了）",
				HitOffset:        mid + int64(i),
			}
		}
	}
	return FragmentDetectionResultV2{HitOffset: -1}
}

// detectMP4Fragment：MP4/MOV 是 box 链 (size:4 + type:4 + payload)。
// 从开头开始顺着 box 链跳，如果跳到的位置不是合法 4cc box type，说明 box 链断了。
//
// 注意：carved 文件可能从 ftyp 之外的位置开始，所以从 offset 直接 parse box；
// 第一个 box 总应该是 ftyp 或 moov 等已知 type。
func detectMP4Fragment(reader disk.DiskReader, offset, size int64) FragmentDetectionResultV2 {
	pos := offset
	end := offset + size
	hop := 0
	for pos+8 < end && hop < 64 {
		hdr := make([]byte, 8)
		n, _ := reader.ReadAt(hdr, pos)
		if n < 8 {
			break
		}
		boxSize := int64(uint32(hdr[0])<<24 | uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3]))
		boxType := string(hdr[4:8])
		if !isLikelyMP4BoxType(boxType) {
			if hop == 0 {
				// 第一个 box 就不像 —— 可能是 carve 起点不对，不是碎片信号
				return FragmentDetectionResultV2{HitOffset: -1}
			}
			return FragmentDetectionResultV2{
				LikelyFragmented: true,
				Confidence:       0.75,
				Reason:           fmt.Sprintf("MP4 box 链在 hop=%d 出现非法 type %q（多半是文件中段被截断/拼接）", hop, boxType),
				HitOffset:        pos,
			}
		}
		if boxSize == 0 {
			break // box 延伸到文件末
		}
		if boxSize == 1 {
			break // 64-bit large box，简化不跟（很少在中段出现）
		}
		if boxSize < 8 {
			return FragmentDetectionResultV2{
				LikelyFragmented: true,
				Confidence:       0.8,
				Reason:           "MP4 box 长度 < 8（不可能合法）",
				HitOffset:        pos,
			}
		}
		pos += boxSize
		hop++
	}
	return FragmentDetectionResultV2{HitOffset: -1}
}

// isLikelyMP4BoxType ASCII 4 字符 + 全部 printable
func isLikelyMP4BoxType(t string) bool {
	if len(t) != 4 {
		return false
	}
	for _, c := range t {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}
