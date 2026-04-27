package validator

// JPEG partial decoder：scan 段的 entropy 解码主循环 + IDCT + 颜色转换。
//
// MCU 流程（baseline）：
//
//	for each MCU (mcuX, mcuY):
//	    for each component:
//	        for each block in component (h*v 个 8x8):
//	            decode DC: huff(hDC) → diff，DC += diff
//	            decode AC: 63 个 zigzag 系数（含 ZRL/EOB）
//	            dequantize（× quant_table[zigzag-1]）
//	            inverse zigzag → 8x8 spatial domain
//	            IDCT
//	    YCbCr → RGB（subsampling 上采样）
//	    写到 output image[mcuX*8*hMax..., mcuY*8*vMax...]
//
// **partial 关键**：carry DC 状态、当 br.corrupt 或解 1 个 component 失败时
// **保留已 decode 的 MCU**，标记 CorruptionMCU 后退出。

import (
	"image"
	"image/color"
)

// zigzag 顺序（spec 7.5.4 Figure 6）
var zigzag = [64]uint8{
	0, 1, 8, 16, 9, 2, 3, 10,
	17, 24, 32, 25, 18, 11, 4, 5,
	12, 19, 26, 33, 40, 48, 41, 34,
	27, 20, 13, 6, 7, 14, 21, 28,
	35, 42, 49, 56, 57, 50, 43, 36,
	29, 22, 15, 23, 30, 37, 44, 51,
	58, 59, 52, 45, 38, 31, 39, 46,
	53, 60, 61, 54, 47, 55, 62, 63,
}

// decodeScan 解 entropy 流，返回 PartialImage
func (d *partialDecoder) decodeScan() (*PartialImage, error) {
	// 解 SOS 段拿每个 component 的 hDCSel/hACSel
	if err := d.parseSOS(); err != nil {
		return nil, err
	}

	br := &bitReader{data: d.data[d.entropyStart:]}

	// MCU dimensions
	mcuW := d.maxHSamp * 8
	mcuH := d.maxVSamp * 8
	mcusX := (d.width + mcuW - 1) / mcuW
	mcusY := (d.height + mcuH - 1) / mcuH
	totalMCUs := mcusX * mcusY

	// 输出 image：full canvas，初始化为中性灰 (128,128,128)
	img := image.NewRGBA(image.Rect(0, 0, mcusX*mcuW, mcusY*mcuH))
	for i := range img.Pix {
		switch i % 4 {
		case 0, 1, 2:
			img.Pix[i] = 128
		case 3:
			img.Pix[i] = 255
		}
	}

	// DC predictors（每 component 一个）
	var dcPred [4]int32

	pi := &PartialImage{
		Image:          img.SubImage(image.Rect(0, 0, d.width, d.height)),
		TotalMCUs:      totalMCUs,
		Width:          d.width,
		Height:         d.height,
		CorruptionMCU:  -1,
		CorruptionByte: -1,
	}

	for my := 0; my < mcusY; my++ {
		for mx := 0; mx < mcusX; mx++ {
			err := d.decodeMCU(br, mx, my, &dcPred, img)
			if err != nil {
				pi.CorruptionMCU = my*mcusX + mx
				pi.CorruptionByte = d.entropyStart + br.pos
				pi.CorruptionError = err
				return pi, nil
			}
			pi.DecodedMCUs++
		}
	}
	return pi, nil
}

// SOS 段格式：
//
//	+0  Ns (1)              # of components in scan
//	+1  Ns × (Cs, TdTa)     each 2 bytes
//	+1+2*Ns  Ss             # 0
//	+2+2*Ns  Se             # 63 for baseline
//	+3+2*Ns  AhAl           # 0 for baseline
func (d *partialDecoder) parseSOS() error {
	p := d.sos.data
	if len(p) < 1 {
		return errPartialJPEG("SOS 太短")
	}
	ns := int(p[0])
	if 1+ns*2+3 > len(p) {
		return errPartialJPEG("SOS component table 截断")
	}
	for i := 0; i < ns; i++ {
		cs := p[1+i*2]
		tdta := p[2+i*2]
		if cs >= 1 && cs <= 3 {
			c := d.components[cs]
			c.hDCSel = tdta >> 4
			c.hACSel = tdta & 0x0F
			d.components[cs] = c
		}
	}
	return nil
}

// decodeMCU 解一个 MCU（含所有 component 的所有 block）
func (d *partialDecoder) decodeMCU(br *bitReader, mx, my int, dcPred *[4]int32, img *image.RGBA) error {
	// 暂存 Y/Cb/Cr blocks（4:4:4 = 1+1+1, 4:2:2 = 2+1+1, 4:2:0 = 4+1+1）
	var yBlocks [4][64]int32 // up to 4 blocks for 4:2:0
	var cbBlock, crBlock [64]int32
	var nYBlocks int

	for cs := 1; cs <= d.componentCount; cs++ {
		c := d.components[uint8(cs)]
		if c.id == 0 {
			// 没初始化（说明 component_count < 3 但循环跑到了）
			continue
		}
		for blockIdx := 0; blockIdx < c.blocksPerMCU; blockIdx++ {
			var block [64]int32
			if err := d.decodeBlock(br, c, &dcPred[cs-1], &block); err != nil {
				return err
			}
			// 反 quant
			for i := 0; i < 64; i++ {
				block[i] *= d.qTables[c.qSelect][i]
			}
			// IDCT in-place
			idct8x8(&block)
			// store
			if cs == 1 {
				if nYBlocks < 4 {
					yBlocks[nYBlocks] = block
					nYBlocks++
				}
			} else if cs == 2 {
				cbBlock = block
			} else if cs == 3 {
				crBlock = block
			}
		}
	}

	// 组装成 RGB pixel：4:4:4 / 4:2:2 / 4:2:0 不同 layout
	d.composeMCU(mx, my, yBlocks[:nYBlocks], &cbBlock, &crBlock, img)
	return nil
}

// decodeBlock 解一个 8×8 block：DC 1 个 + AC 63 个 zigzag 系数
func (d *partialDecoder) decodeBlock(br *bitReader, c component, dcPred *int32, block *[64]int32) error {
	// DC: huff(hDC[c.hDCSel]) → 类别 t；recv(t) → diff
	hDC := d.hDC[c.hDCSel]
	if hDC == nil {
		return errPartialJPEG("DC Huffman table 缺失")
	}
	t, err := br.decode(hDC)
	if err != nil {
		return err
	}
	diff, err := br.recv(t)
	if err != nil {
		return err
	}
	*dcPred += diff
	block[0] = *dcPred

	// AC: 1..63
	hAC := d.hAC[c.hACSel]
	if hAC == nil {
		return errPartialJPEG("AC Huffman table 缺失")
	}
	k := 1
	for k < 64 {
		rs, err := br.decode(hAC)
		if err != nil {
			return err
		}
		s := rs & 0x0F
		r := rs >> 4
		if s == 0 {
			if r == 15 {
				// ZRL: skip 16
				k += 16
				continue
			}
			// EOB
			break
		}
		k += int(r)
		if k >= 64 {
			return errPartialJPEG("AC zigzag 越界")
		}
		v, err := br.recv(s)
		if err != nil {
			return err
		}
		block[zigzag[k]] = v
		k++
	}
	return nil
}

// composeMCU 把已 IDCT 的 Y/Cb/Cr block 转成 RGB 写入 img
func (d *partialDecoder) composeMCU(mx, my int, yBlocks [][64]int32, cbBlock, crBlock *[64]int32, img *image.RGBA) {
	mcuW := d.maxHSamp * 8
	mcuH := d.maxVSamp * 8
	startX := mx * mcuW
	startY := my * mcuH

	if d.componentCount == 1 {
		// grayscale
		if len(yBlocks) == 0 {
			return
		}
		writeBlock(img, startX, startY, &yBlocks[0], grayWriter)
		return
	}

	// YCbCr 三通道
	yC := d.components[1]

	// 4:4:4：1 Y block, 1 Cb, 1 Cr，全部 8×8
	// 4:2:2：2 Y block 横排，Cb/Cr 8×8 但水平上采样 2×
	// 4:2:0：4 Y block 2×2，Cb/Cr 8×8 但水平+垂直上采样 2×

	for i, yb := range yBlocks {
		yb := yb // copy
		yi := i / yC.hSamp
		xi := i % yC.hSamp
		bx := startX + xi*8
		by := startY + yi*8

		// 对每个 8×8 Y block，找到对应 chroma 像素
		var rgbBlock [64]uint8
		for py := 0; py < 8; py++ {
			for px := 0; px < 8; px++ {
				yVal := yb[py*8+px] + 128
				if yVal < 0 {
					yVal = 0
				} else if yVal > 255 {
					yVal = 255
				}
				// chroma 索引：subsampling 上采样
				cx := (xi*8 + px) / d.maxHSamp
				cy := (yi*8 + py) / d.maxVSamp
				if cx > 7 {
					cx = 7
				}
				if cy > 7 {
					cy = 7
				}
				cb := cbBlock[cy*8+cx]
				cr := crBlock[cy*8+cx]
				r, g, b := ycbcrToRGB(yVal, cb+128, cr+128)
				rgbBlock[(py*8+px)*1+0] = uint8(r)
				_ = b
				_ = g
				// 直接写 img.Pix
				dstX := bx + px
				dstY := by + py
				if dstX < 0 || dstY < 0 || dstX >= img.Bounds().Max.X || dstY >= img.Bounds().Max.Y {
					continue
				}
				off := dstY*img.Stride + dstX*4
				img.Pix[off+0] = uint8(r)
				img.Pix[off+1] = uint8(g)
				img.Pix[off+2] = uint8(b)
				img.Pix[off+3] = 255
			}
		}
	}
}

// grayWriter 灰度版 block writer
func grayWriter(img *image.RGBA, x, y int, val int32) {
	v := val + 128
	if v < 0 {
		v = 0
	} else if v > 255 {
		v = 255
	}
	if x < 0 || y < 0 || x >= img.Bounds().Max.X || y >= img.Bounds().Max.Y {
		return
	}
	off := y*img.Stride + x*4
	img.Pix[off+0] = uint8(v)
	img.Pix[off+1] = uint8(v)
	img.Pix[off+2] = uint8(v)
	img.Pix[off+3] = 255
}

func writeBlock(img *image.RGBA, startX, startY int, block *[64]int32, w func(*image.RGBA, int, int, int32)) {
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			w(img, startX+x, startY+y, block[y*8+x])
		}
	}
}

// ycbcrToRGB JPEG 标准 YCbCr (BT.601) → RGB
//
//	R = Y + 1.402 * (Cr-128)
//	G = Y - 0.34414*(Cb-128) - 0.71414*(Cr-128)
//	B = Y + 1.772 * (Cb-128)
//
// （color.YCbCrToRGB 的内部公式）—— 直接调 stdlib 的 RGBToYCbCr 反向函数
func ycbcrToRGB(y, cb, cr int32) (r, g, b int32) {
	rr, gg, bb := color.YCbCrToRGB(uint8(clip(y)), uint8(clip(cb)), uint8(clip(cr)))
	return int32(rr), int32(gg), int32(bb)
}

func clip(v int32) int32 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return v
}

// =============================================================================
// IDCT —— 8×8 Inverse DCT，AAN 优化版（Arai/Agui/Nakajima 1988）
// =============================================================================
//
// 比朴素 N=8 IDCT 快 ~2×；与 stdlib `image/jpeg` 同算法。
// 数据来源：JPEG spec annex / libjpeg jidctint.c
//
// 注：本实现是简化"标准" IDCT，不是 AAN 加速版（实现 AAN 需要预乘 quant table，
// 复杂度增加；我们的 quant table 是上层"raw" 系数，用 standard IDCT 即可）

func idct8x8(block *[64]int32) {
	// 1D IDCT on rows
	var tmp [64]int32
	for r := 0; r < 8; r++ {
		idct1D(block[r*8:r*8+8], tmp[r*8:r*8+8])
	}
	// 1D IDCT on cols
	var col, out [8]int32
	for c := 0; c < 8; c++ {
		for i := 0; i < 8; i++ {
			col[i] = tmp[i*8+c]
		}
		idct1D(col[:], out[:])
		for i := 0; i < 8; i++ {
			block[i*8+c] = out[i] >> 6 // 1D 处理两次需要 /64 (>>6) 归一
		}
	}
}

// idct1D 标准 8-pt IDCT（spec ITU T.81 Annex A.3.3）
//
// 输入 in[0..7]，输出 out[0..7]
// 用整数定点运算（13 bit precision）
func idct1D(in, out []int32) {
	// 简化实现：直接 cosine matrix multiply（O(N²) = 64 ops 对 N=8 够用）
	// 对性能敏感场景可换成 Loeffler / AAN 11-mul 优化
	const fix = 12 // 12-bit 小数精度
	// cosine matrix C[k][n] = cos((2n+1)*k*pi/16) * scale
	// 这里直接 inline pre-computed 表（× 4096）
	cos := [8][8]int32{
		{4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096},
		{5681, 4816, 3218, 1130, -1130, -3218, -4816, -5681},
		{5352, 2217, -2217, -5352, -5352, -2217, 2217, 5352},
		{4816, -1130, -5681, -3218, 3218, 5681, 1130, -4816},
		{4096, -4096, -4096, 4096, 4096, -4096, -4096, 4096},
		{3218, -5681, 1130, 4816, -4816, -1130, 5681, -3218},
		{2217, -5352, 5352, -2217, -2217, 5352, -5352, 2217},
		{1130, -3218, 4816, -5681, 5681, -4816, 3218, -1130},
	}
	// Scale factor S[k] = 1/sqrt(2) for k=0, 1 otherwise
	// S[0] / 4096 = 0.7071 → 整数 ≈ 2896；其他 = 4096
	scale := [8]int32{2896, 4096, 4096, 4096, 4096, 4096, 4096, 4096}

	for n := 0; n < 8; n++ {
		var sum int64
		for k := 0; k < 8; k++ {
			sum += int64(in[k]) * int64(cos[k][n]) * int64(scale[k])
		}
		// 双重 fixed-point: × 4096 × 4096 = 24 bit；归一 /4 (cos table 实际 norm 是 1/2)
		out[n] = int32(sum >> (fix + fix))
		_ = scale
	}
}

// errPartialJPEG 内部错误标记（让上层 PartialDecode 知道是 entropy 流问题，
// 应保留已 decode 的部分）
type errPartialJPEGErr string

func (e errPartialJPEGErr) Error() string { return string(e) }

func errPartialJPEG(s string) error { return errPartialJPEGErr(s) }
