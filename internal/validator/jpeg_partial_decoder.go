package validator

// 最小 baseline JPEG decoder —— 专为 **partial decode** 优化的 in-tree fork。
//
// 设计目标（与 stdlib `image/jpeg` 区别）：
//
//   - Stdlib：碰到 entropy 流损坏 → 返回 error，**已 decode 的 MCU 全部丢弃**
//     （因为 stdlib 内部状态封闭，无法 emit 部分图像）
//   - 本实现：碰到 entropy 损坏 → 返回 PartialImage（已 decode 的 MCU 区域 +
//     未 decode 区域填中性灰 + corruption_mcu_index）
//
// 仅支持 baseline JPEG (SOF0)：
//   - 8-bit precision
//   - YCbCr 3-channel（Y/Cb/Cr）或 1-channel grayscale
//   - 4:4:4 / 4:2:2 / 4:2:0 chroma subsampling
//   - DHT (Huffman tables) + DQT (quantization)
//   - **不**支持：progressive (SOF2) / 12-bit / arithmetic coding / lossless
//
// 这覆盖 Photoshop / Lightroom / iPhone / 安卓相机 / 截图工具的 99%+ 输出。
// Progressive 走 stdlib + 我们的 fallback。
//
// 代码组织：
//   - 本文件：framework + 入口 PartialDecode + entropy 解码主循环
//   - 不分多文件，因为整个 decoder 仅 ~600 行（vs stdlib jpeg 的 ~3000 行）

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"io"
)

// PartialImage 是 PartialDecode 的输出
type PartialImage struct {
	Image           image.Image
	TotalMCUs       int  // 总 MCU 数（按 SOF 算的）
	DecodedMCUs     int  // 实际 decode 出来的 MCU 数
	CorruptionMCU   int  // 损坏发生的 MCU 索引（-1 = 全部成功）
	CorruptionByte  int  // entropy 流里损坏字节 offset (-1 = 全部成功)
	CorruptionError error // 损坏的具体原因
	Width, Height   int
}

// jpegSegment 是 JPEG marker 段
type jpegSegment struct {
	marker byte
	data   []byte // 段 payload（不含 length 字段）
}

// PartialDecode 解一个 baseline JPEG，碰损坏不 abort 而返回部分图像。
//
// 用法：
//
//	pi, err := PartialDecode(data)
//	if err != nil {
//	    // 文件根本不是 JPEG 或 header 损坏（甚至前 1 个 MCU 都没解出）
//	}
//	// pi.Image 含 [0, pi.DecodedMCUs) 区域的真像素，剩余部分填中性灰
//	// 用户/UI 看到 "图像 70% 已恢复（损坏在 MCU 245/350）"
func PartialDecode(data []byte) (*PartialImage, error) {
	d := &partialDecoder{data: data}
	if err := d.parseSegments(); err != nil {
		return nil, fmt.Errorf("解析 segments: %w", err)
	}
	if d.sof == nil {
		return nil, errors.New("没找到 SOF（Start of Frame）段")
	}
	if d.sof.marker != 0xC0 {
		return nil, fmt.Errorf("仅支持 baseline JPEG (SOF0)，本文件是 SOF%d", d.sof.marker-0xC0)
	}
	if err := d.parseSOF(); err != nil {
		return nil, fmt.Errorf("SOF: %w", err)
	}
	if err := d.parseDQTs(); err != nil {
		return nil, fmt.Errorf("DQT: %w", err)
	}
	if err := d.parseDHTs(); err != nil {
		return nil, fmt.Errorf("DHT: %w", err)
	}
	if d.sos == nil {
		return nil, errors.New("没找到 SOS")
	}
	return d.decodeScan()
}

// partialDecoder 主结构
type partialDecoder struct {
	data []byte

	// parsed segments
	sof *jpegSegment
	sos *jpegSegment
	dqt []*jpegSegment
	dht []*jpegSegment

	// from SOF
	width, height                  int
	componentCount                 int
	components                     [4]component // index by Cs from SOS（对齐到 1..N）
	maxHSamp, maxVSamp             int

	// quant tables (4 张)
	qTables [4][64]int32

	// huffman tables (DC×4, AC×4)
	hDC [4]*huffTable
	hAC [4]*huffTable

	// scan-time entropy stream
	entropyStart int
}

type component struct {
	id     uint8 // SOF 里给的 component id
	hSamp  int   // horizontal sampling factor
	vSamp  int   // vertical sampling factor
	qSelect uint8 // 用哪张 quant table

	// SOS 选 Huffman table
	hDCSel uint8
	hACSel uint8

	// blocks per MCU
	blocksPerMCU int
}

// =============================================================================
// Segment 扫描
// =============================================================================

func (d *partialDecoder) parseSegments() error {
	if len(d.data) < 4 || d.data[0] != 0xFF || d.data[1] != 0xD8 {
		return errors.New("非 JPEG（缺 SOI）")
	}
	pos := 2
	for pos+1 < len(d.data) {
		// 找 0xFF marker
		if d.data[pos] != 0xFF {
			pos++
			continue
		}
		// 跳过 fill bytes (FF FF...)
		for pos < len(d.data) && d.data[pos] == 0xFF {
			pos++
		}
		if pos >= len(d.data) {
			break
		}
		marker := d.data[pos]
		pos++
		// stand-alone markers (no length)
		if marker == 0x00 || marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) {
			continue
		}
		if marker == 0xD9 { // EOI
			break
		}
		// length-prefixed segment
		if pos+2 > len(d.data) {
			return errors.New("段长字段越界")
		}
		segLen := int(binary.BigEndian.Uint16(d.data[pos : pos+2]))
		if segLen < 2 || pos+segLen > len(d.data) {
			return fmt.Errorf("段长度异常 (marker=%X len=%d)", marker, segLen)
		}
		seg := &jpegSegment{
			marker: marker,
			data:   d.data[pos+2 : pos+segLen],
		}
		switch {
		case marker == 0xC0: // SOF0
			d.sof = seg
		case marker == 0xC1, marker == 0xC2, marker == 0xC3, marker == 0xC5, marker == 0xC6, marker == 0xC7,
			marker == 0xC9, marker == 0xCA, marker == 0xCB, marker == 0xCD, marker == 0xCE, marker == 0xCF:
			// 其他 SOF 类型（progressive / arithmetic）—— 仍记录但 decode 时拒绝
			d.sof = seg
		case marker == 0xDB: // DQT
			d.dqt = append(d.dqt, seg)
		case marker == 0xC4: // DHT
			d.dht = append(d.dht, seg)
		case marker == 0xDA: // SOS
			d.sos = seg
			d.entropyStart = pos + segLen
			// **关键**：SOS 之后是 entropy 流，0xFF 是 byte-stuff 不是 marker。
			// 不能继续扫，否则会把 entropy 流里的字节当成段头解析。
			return nil
		}
		pos += segLen
	}
	return nil
}

// =============================================================================
// SOF / DQT / DHT 解析
// =============================================================================

func (d *partialDecoder) parseSOF() error {
	p := d.sof.data
	if len(p) < 6 {
		return errors.New("SOF 段太短")
	}
	if p[0] != 8 {
		return fmt.Errorf("仅支持 8-bit precision，本文件 %d-bit", p[0])
	}
	d.height = int(binary.BigEndian.Uint16(p[1:3]))
	d.width = int(binary.BigEndian.Uint16(p[3:5]))
	d.componentCount = int(p[5])
	if d.componentCount != 1 && d.componentCount != 3 {
		return fmt.Errorf("仅支持 1/3 component，本文件 %d", d.componentCount)
	}
	if len(p) < 6+d.componentCount*3 {
		return errors.New("SOF component table 长度不足")
	}
	for i := 0; i < d.componentCount; i++ {
		off := 6 + i*3
		c := component{
			id:      p[off],
			hSamp:   int(p[off+1] >> 4),
			vSamp:   int(p[off+1] & 0x0F),
			qSelect: p[off+2],
		}
		if c.hSamp == 0 || c.vSamp == 0 || c.hSamp > 4 || c.vSamp > 4 {
			return fmt.Errorf("component %d sampling 异常 (h=%d v=%d)", i, c.hSamp, c.vSamp)
		}
		c.blocksPerMCU = c.hSamp * c.vSamp
		if c.hSamp > d.maxHSamp {
			d.maxHSamp = c.hSamp
		}
		if c.vSamp > d.maxVSamp {
			d.maxVSamp = c.vSamp
		}
		// 用 component_id 作为 1..N 映射；assume id 是 1, 2, 3
		if c.id >= 1 && c.id <= 3 {
			d.components[c.id] = c
		}
	}
	return nil
}

func (d *partialDecoder) parseDQTs() error {
	for _, seg := range d.dqt {
		p := seg.data
		pos := 0
		for pos < len(p) {
			pq := int(p[pos] >> 4)   // 0=8-bit, 1=16-bit
			tq := int(p[pos] & 0x0F) // table id 0..3
			if tq > 3 {
				return fmt.Errorf("quant table id %d 越界", tq)
			}
			pos++
			tableSize := 64
			if pq == 1 {
				tableSize = 128
			}
			if pos+tableSize > len(p) {
				return errors.New("quant table 截断")
			}
			for i := 0; i < 64; i++ {
				if pq == 0 {
					d.qTables[tq][i] = int32(p[pos+i])
				} else {
					d.qTables[tq][i] = int32(binary.BigEndian.Uint16(p[pos+i*2 : pos+i*2+2]))
				}
			}
			pos += tableSize
		}
	}
	return nil
}

func (d *partialDecoder) parseDHTs() error {
	for _, seg := range d.dht {
		p := seg.data
		pos := 0
		for pos < len(p) {
			tcTh := p[pos]
			pos++
			tc := int(tcTh >> 4)   // 0=DC, 1=AC
			th := int(tcTh & 0x0F) // table id 0..3
			if th > 3 || tc > 1 {
				return fmt.Errorf("huffman tcTh=%X 越界", tcTh)
			}
			if pos+16 > len(p) {
				return errors.New("huffman BITS 表截断")
			}
			var bits [16]int
			totalVals := 0
			for i := 0; i < 16; i++ {
				bits[i] = int(p[pos+i])
				totalVals += bits[i]
			}
			pos += 16
			if pos+totalVals > len(p) {
				return errors.New("huffman HUFFVAL 截断")
			}
			vals := make([]uint8, totalVals)
			copy(vals, p[pos:pos+totalVals])
			pos += totalVals

			tbl, err := buildHuffTable(bits, vals)
			if err != nil {
				return fmt.Errorf("build Huffman table: %w", err)
			}
			if tc == 0 {
				d.hDC[th] = tbl
			} else {
				d.hAC[th] = tbl
			}
		}
	}
	return nil
}

// =============================================================================
// Huffman table 构造（spec ITU T.81 Annex C）
// =============================================================================

type huffTable struct {
	// 简化版：lookup 表 + slow path
	// fast: 9-bit 索引（多数 code 长 ≤ 9 bit），值 = (symbol<<8 | nbits)
	fast    [512]uint16
	// slow path：长 code 走完整解码（用 minCode/maxCode/valptr 三表）
	minCode [16]int32
	maxCode [16]int32
	valPtr  [16]int
	huffval []uint8
}

func buildHuffTable(bits [16]int, vals []uint8) (*huffTable, error) {
	t := &huffTable{huffval: vals}
	// Generate huffsize / huffcode 序列
	var huffsize []int
	for i := 0; i < 16; i++ {
		for j := 0; j < bits[i]; j++ {
			huffsize = append(huffsize, i+1)
		}
	}
	if len(huffsize) != len(vals) {
		return nil, fmt.Errorf("BITS sum %d != HUFFVAL count %d", len(huffsize), len(vals))
	}
	huffcode := make([]int32, len(huffsize))
	if len(huffsize) > 0 {
		code := int32(0)
		size := huffsize[0]
		for i := 0; i < len(huffsize); i++ {
			for huffsize[i] != size {
				code <<= 1
				size++
			}
			huffcode[i] = code
			code++
		}
	}
	// 初始化 minCode / maxCode / valPtr
	for i := 0; i < 16; i++ {
		t.minCode[i] = -1
		t.maxCode[i] = -1
	}
	j := 0
	for i := 0; i < 16; i++ {
		if bits[i] == 0 {
			continue
		}
		t.valPtr[i] = j
		t.minCode[i] = huffcode[j]
		t.maxCode[i] = huffcode[j+bits[i]-1]
		j += bits[i]
	}
	// fast lookup table（9-bit）
	for i := range t.fast {
		t.fast[i] = 0xFFFF
	}
	for k, sz := range huffsize {
		if sz > 9 {
			continue
		}
		// 把 huffcode 左移到 9-bit 位置（高位对齐）
		base := huffcode[k] << uint(9-sz)
		fill := 1 << uint(9-sz)
		for f := int32(0); f < int32(fill); f++ {
			t.fast[base+f] = uint16(vals[k])<<8 | uint16(sz)
		}
	}
	return t, nil
}

// =============================================================================
// Bit reader
// =============================================================================

type bitReader struct {
	data    []byte
	pos     int
	accum   uint64
	nbits   uint8
	corrupt bool // 碰到 0xFF + 非合法 marker 后置位
}

func (br *bitReader) ensure(n uint8) error {
	for br.nbits < n {
		if br.pos >= len(br.data) {
			return io.EOF
		}
		b := br.data[br.pos]
		br.pos++
		if b == 0xFF {
			// byte stuff: FF 00 → FF
			if br.pos >= len(br.data) {
				return io.EOF
			}
			next := br.data[br.pos]
			br.pos++
			if next != 0 {
				// Marker！（RST/EOI/SOS 等）这是 entropy 流"边界"
				// 把 marker push 回（pos -= 2）让上层看到
				br.pos -= 2
				br.corrupt = true
				return io.EOF
			}
		}
		br.accum = (br.accum << 8) | uint64(b)
		br.nbits += 8
	}
	return nil
}

func (br *bitReader) peek(n uint8) (uint32, error) {
	if err := br.ensure(n); err != nil {
		return 0, err
	}
	return uint32((br.accum >> (br.nbits - n)) & ((1 << n) - 1)), nil
}

func (br *bitReader) drop(n uint8) {
	br.nbits -= n
	br.accum &= (1 << br.nbits) - 1
}

func (br *bitReader) recv(n uint8) (int32, error) {
	if n == 0 {
		return 0, nil
	}
	v, err := br.peek(n)
	if err != nil {
		return 0, err
	}
	br.drop(n)
	// extend (JPEG spec: if MSB=0, value is negative)
	r := int32(v)
	if r < (1 << (n - 1)) {
		r += int32(-(1 << n)) + 1
	}
	return r, nil
}

func (br *bitReader) decode(t *huffTable) (uint8, error) {
	// 先尝试 9-bit fast path
	bits9, err := br.peek(9)
	if err == nil {
		fast := t.fast[bits9]
		if fast != 0xFFFF {
			sym := uint8(fast >> 8)
			sz := uint8(fast & 0xFF)
			br.drop(sz)
			return sym, nil
		}
	}
	// slow path：1 bit 一次累加直到落到 maxCode 范围
	var code int32
	for l := 0; l < 16; l++ {
		bit, err := br.peek(1)
		if err != nil {
			return 0, err
		}
		br.drop(1)
		code = (code << 1) | int32(bit)
		if t.maxCode[l] >= 0 && code <= t.maxCode[l] {
			j := t.valPtr[l] + int(code-t.minCode[l])
			if j < 0 || j >= len(t.huffval) {
				return 0, errors.New("huffman decode 越界")
			}
			return t.huffval[j], nil
		}
	}
	return 0, errors.New("huffman 16-bit 都没匹配")
}
