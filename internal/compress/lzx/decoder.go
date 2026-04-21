package lzx

import (
	"encoding/binary"
	"fmt"
)

// LZX 常量（[MS-WIM] 2.10）
const (
	// Block types
	blockVerbatim      = 1
	blockAlignedOffset = 2
	blockUncompressed  = 3

	// 符号表大小
	mainTreeMaxSymbols  = 256 + 8*50 // literals + match headers (position-slot based)
	lengthTreeSymbols   = 249        // secondary length tree
	alignedOffsetSymbols = 8
	pretreeSymbols      = 20 // pretree 本身的 code length 码
)

// positionSlotBase + positionSlotFootBits 是 LZX 的 position slot → offset 映射。
// 前 30 个 slot 足够覆盖 32KB 窗口（LZX 最小 window）。完整表支持到 64KB+ 窗口。
var positionSlotBase = []uint32{
	0, 1, 2, 3, 4, 6, 8, 12, 16, 24,
	32, 48, 64, 96, 128, 192, 256, 384, 512, 768,
	1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576,
	32768, 49152, 65536, 98304, 131072, 196608, 262144, 393216, 524288, 655360,
	786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864, 1703936, 1835008, 1966080,
}
var positionSlotFootBits = []uint{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
	4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
	9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
	14, 14, 15, 15, 16, 16, 17, 17, 17, 17,
	17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
}

// Decoder LZX 解压器，持有滑动窗口 + 历史 huffman tree（跨 block 继承 code length
// "no change"语义时用）。
type Decoder struct {
	window     []byte
	winPos     int
	winSize    int

	// 历史 code lengths —— LZX 的 "pretree delta encoding" 允许下一个 block 继承上个的
	// code length，只编码"哪些 symbol 变化了"
	prevMainLens    [mainTreeMaxSymbols]byte
	prevLengthLens  [lengthTreeSymbols]byte

	// LRU repeated offsets（r0 r1 r2）— LZX 的"最近 3 个 match offset"缓存
	r0, r1, r2 uint32

	// 已输出字节数（跨 block 累计）
	outWritten int

	// 目标未压缩大小（chunk 级）
	uncompressedSize int

	// 是否启用 E8 preprocessing（CAB / WIM 里通常启用；前 12 字节的 E8 byte 不处理）
	e8Enabled bool
	e8Filter  uint32 // 文件总大小限制，E8 translation 范围
}

// NewDecoder windowSize: 2^15..2^21 (32KB - 2MB)；WIM 用 32768 (2^15)
func NewDecoder(windowSize int, uncompressedSize int) *Decoder {
	d := &Decoder{
		window:           make([]byte, windowSize),
		winSize:          windowSize,
		uncompressedSize: uncompressedSize,
		r0:               1, r1: 1, r2: 1,
		e8Enabled: true,
		e8Filter:  12 * 1024 * 1024, // 标准值
	}
	return d
}

// Decode 把 src 里的 LZX 数据解到 dst。dst 长度必须 >= 未压缩大小。
func (d *Decoder) Decode(src, dst []byte) (int, error) {
	r := newBitReader(src)
	d.outWritten = 0
	dstCap := len(dst)

	// LZX spec：第一个 bit 决定"是否有 E8 translation header"；1 表示有
	hasE8 := r.read(1) == 1
	if hasE8 {
		hi := r.read(16)
		lo := r.read(16)
		d.e8Filter = hi<<16 | lo
	}

	// 连续解 block 直到输出达 uncompressedSize
	for d.outWritten < d.uncompressedSize {
		if r.err != nil {
			return d.outWritten, r.err
		}
		if err := d.decodeBlock(r, dst, dstCap); err != nil {
			return d.outWritten, err
		}
	}

	// E8 postprocessing（如果启用且输出 >= 6 字节）
	if hasE8 && d.outWritten >= 6 {
		d.e8Postprocess(dst[:d.outWritten])
	}
	return d.outWritten, nil
}

// decodeBlock 解单个 block
func (d *Decoder) decodeBlock(r *bitReader, dst []byte, dstCap int) error {
	blockType := int(r.read(3))
	blockSize := int(r.read(24)) // 原始字节数
	if blockSize == 0 {
		return fmt.Errorf("block size = 0")
	}
	if d.outWritten+blockSize > d.uncompressedSize {
		blockSize = d.uncompressedSize - d.outWritten // clip
	}

	switch blockType {
	case blockUncompressed:
		return d.decodeUncompressed(r, dst, dstCap, blockSize)
	case blockVerbatim:
		return d.decodeHuffmanBlock(r, dst, dstCap, blockSize, false)
	case blockAlignedOffset:
		return d.decodeHuffmanBlock(r, dst, dstCap, blockSize, true)
	}
	return fmt.Errorf("未知 LZX block type %d", blockType)
}

// decodeUncompressed 未压缩 block
func (d *Decoder) decodeUncompressed(r *bitReader, dst []byte, dstCap int, size int) error {
	// 对齐到 16-bit 边界
	r.alignToWord()
	// 读 3 个 uint32 的 LRU（r0 r1 r2 从 byte stream 直接读，不走 bitreader）
	if r.pos+12 > len(r.src) {
		return fmt.Errorf("uncompressed block LRU 越界")
	}
	d.r0 = binary.LittleEndian.Uint32(r.src[r.pos:])
	d.r1 = binary.LittleEndian.Uint32(r.src[r.pos+4:])
	d.r2 = binary.LittleEndian.Uint32(r.src[r.pos+8:])
	r.pos += 12
	r.buf = 0
	r.nbit = 0

	// 直接拷 size 字节
	if r.pos+size > len(r.src) {
		return fmt.Errorf("uncompressed block 数据越界")
	}
	end := d.outWritten + size
	if end > dstCap {
		end = dstCap
	}
	copy(dst[d.outWritten:end], r.src[r.pos:r.pos+size])
	for i := 0; i < size; i++ {
		d.window[d.winPos] = r.src[r.pos+i]
		d.winPos = (d.winPos + 1) % d.winSize
	}
	d.outWritten = end
	r.pos += size
	// 末尾如果 size 是奇数，要 pad 一个字节回到 16-bit 对齐
	if size%2 != 0 {
		r.pos++
	}
	return nil
}

// decodeHuffmanBlock verbatim / aligned-offset block。
//
// 两种 block 差异仅在：aligned-offset 额外解一棵 "aligned offset tree" (3-bit, 8 symbol)，
// 用于 position slot >= 3 时的低 3 bit 残余。
func (d *Decoder) decodeHuffmanBlock(r *bitReader, dst []byte, dstCap int, size int, aligned bool) error {
	// 1. aligned offset 模式先读 8 个 3-bit 码长 → 建 aligned huffman tree
	var alignedTree *canonicalTable
	if aligned {
		alignedLens := make([]byte, alignedOffsetSymbols)
		for i := 0; i < alignedOffsetSymbols; i++ {
			alignedLens[i] = byte(r.read(3))
		}
		t, err := buildCanonical(alignedLens)
		if err != nil {
			return fmt.Errorf("build aligned: %w", err)
		}
		alignedTree = t
	}

	// 2. 读 main tree 码长：分两段 (前 256 literal + 之后 match headers)，每段都用
	//    pretree delta 编码
	if err := d.readDeltaCodeLengths(r, d.prevMainLens[:256]); err != nil {
		return err
	}
	if err := d.readDeltaCodeLengths(r, d.prevMainLens[256:]); err != nil {
		return err
	}
	mainTree, err := buildCanonical(d.prevMainLens[:])
	if err != nil {
		return fmt.Errorf("build main: %w", err)
	}

	// 3. 读 length tree（secondary length tree）
	if err := d.readDeltaCodeLengths(r, d.prevLengthLens[:]); err != nil {
		return err
	}
	lengthTree, err := buildCanonical(d.prevLengthLens[:])
	if err != nil {
		return fmt.Errorf("build length: %w", err)
	}

	// 4. 按 main tree 解 block 数据
	written := 0
	for written < size {
		sym, err := mainTree.decodeSymbol(r)
		if err != nil {
			return err
		}
		if sym < 256 {
			// literal
			if d.outWritten >= dstCap {
				return fmt.Errorf("dst 越界")
			}
			dst[d.outWritten] = byte(sym)
			d.window[d.winPos] = byte(sym)
			d.winPos = (d.winPos + 1) % d.winSize
			d.outWritten++
			written++
			continue
		}
		// match header：sym - 256 = (position_slot << 3) | length_header
		matchHdr := sym - 256
		lenHeader := matchHdr & 7
		posSlot := matchHdr >> 3

		// 长度
		var matchLen int
		if lenHeader == 7 {
			extra, err := lengthTree.decodeSymbol(r)
			if err != nil {
				return err
			}
			matchLen = extra + 7 + 2
		} else {
			matchLen = lenHeader + 2
		}

		// 偏移：0/1/2 是 LRU，否则计算
		var offset uint32
		switch posSlot {
		case 0:
			offset = d.r0
		case 1:
			offset = d.r1
			d.r1, d.r0 = d.r0, d.r1
		case 2:
			offset = d.r2
			d.r2, d.r0 = d.r0, d.r2
		default:
			if posSlot >= len(positionSlotBase) {
				return fmt.Errorf("position slot %d 越界", posSlot)
			}
			foot := positionSlotFootBits[posSlot]
			var footBits uint32
			if aligned && foot >= 3 {
				// 剩 3 位用 aligned tree 的 symbol 代替
				if foot > 3 {
					high := r.read(foot - 3)
					alignedSym, err := alignedTree.decodeSymbol(r)
					if err != nil {
						return err
					}
					footBits = high<<3 | uint32(alignedSym)
				} else {
					alignedSym, err := alignedTree.decodeSymbol(r)
					if err != nil {
						return err
					}
					footBits = uint32(alignedSym)
				}
			} else {
				footBits = r.read(foot)
			}
			offset = positionSlotBase[posSlot] + footBits - 2 // LZX: offset = base + foot - 2
			// 更新 LRU
			d.r2 = d.r1
			d.r1 = d.r0
			d.r0 = offset
		}

		// LZ77 拷贝
		if offset == 0 || d.outWritten+matchLen > dstCap {
			return fmt.Errorf("match 越界 offset=%d len=%d outpos=%d", offset, matchLen, d.outWritten)
		}
		for i := 0; i < matchLen; i++ {
			srcIdx := (d.winPos - int(offset) + d.winSize) % d.winSize
			b := d.window[srcIdx]
			dst[d.outWritten] = b
			d.window[d.winPos] = b
			d.winPos = (d.winPos + 1) % d.winSize
			d.outWritten++
		}
		written += matchLen
	}
	return nil
}

// readDeltaCodeLengths 读"前一次码长"+delta 编码的新码长数组。
//
// LZX 用 pretree 嵌套 huffman：
//   - 先读 20 个 4-bit 码长构建 pretree
//   - 用 pretree 解 delta code，应用到 prev 码长上得到新码长
//
// delta symbol 含义：
//   0..16: 新码长 = (prev - symbol + 17) mod 17
//   17: 后续 4 位 + 4 = 连续 N 个 0 码长
//   18: 后续 5 位 + 20 = 更长的 0 连续
//   19: 后续 1 位 + 4 + (下一个 pretree symbol 0..16 + prev → 新码长) 连续 N 个相同
func (d *Decoder) readDeltaCodeLengths(r *bitReader, prevLens []byte) error {
	// 读 pretree 码长
	preLens := make([]byte, pretreeSymbols)
	for i := 0; i < pretreeSymbols; i++ {
		preLens[i] = byte(r.read(4))
	}
	pretree, err := buildCanonical(preLens)
	if err != nil {
		return fmt.Errorf("build pretree: %w", err)
	}

	i := 0
	for i < len(prevLens) {
		sym, err := pretree.decodeSymbol(r)
		if err != nil {
			return err
		}
		switch {
		case sym <= 16:
			newLen := (int(prevLens[i]) - sym + 17) % 17
			prevLens[i] = byte(newLen)
			i++
		case sym == 17:
			zeros := int(r.read(4)) + 4
			for k := 0; k < zeros && i < len(prevLens); k++ {
				prevLens[i] = 0
				i++
			}
		case sym == 18:
			zeros := int(r.read(5)) + 20
			for k := 0; k < zeros && i < len(prevLens); k++ {
				prevLens[i] = 0
				i++
			}
		case sym == 19:
			count := int(r.read(1)) + 4
			inner, err := pretree.decodeSymbol(r)
			if err != nil {
				return err
			}
			if inner > 16 {
				return fmt.Errorf("delta symbol 19 inner > 16")
			}
			newLen := (int(prevLens[i]) - inner + 17) % 17
			for k := 0; k < count && i < len(prevLens); k++ {
				prevLens[i] = byte(newLen)
				i++
			}
		default:
			return fmt.Errorf("delta symbol %d 越界", sym)
		}
	}
	return nil
}

// e8Postprocess x86 call 指令的反向：把绝对偏移转回相对偏移。
//
// 压缩时：遇到 0xE8（x86 CALL near）+ 4 字节相对偏移 → 转成相对于文件起点的绝对偏移
// （因为 call 地址更可能在文件间重复，提升压缩率）。解压末步反向。
//
// 只在数据末尾 10 字节之前应用；且只应用于 first e8Filter 字节（默认 12MB）。
func (d *Decoder) e8Postprocess(data []byte) {
	n := len(data)
	if n < 10 {
		return
	}
	limit := n - 10
	for i := 0; i < limit; {
		if data[i] != 0xE8 {
			i++
			continue
		}
		// 读 4 字节 LE 绝对地址
		abs := int32(binary.LittleEndian.Uint32(data[i+1 : i+5]))
		if abs >= 0 && abs < int32(d.e8Filter) {
			rel := abs - int32(i)
			binary.LittleEndian.PutUint32(data[i+1:i+5], uint32(rel))
		} else if abs < 0 && abs >= -int32(i) {
			// 有时被编码成负，反向对称
			newAbs := abs + int32(d.e8Filter)
			if newAbs >= 0 && newAbs < int32(d.e8Filter) {
				binary.LittleEndian.PutUint32(data[i+1:i+5], uint32(newAbs))
			}
		}
		i += 5 // 跳过 call 指令
	}
}
