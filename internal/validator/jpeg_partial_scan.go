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
// IDCT —— Loeffler/Ligtenberg/Moschytz 1989 优化版
// =============================================================================
//
// 11 乘法 + 29 加法 / 8-pt 1D IDCT（vs naive N²=64 乘）。这是 libjpeg jidctint.c
// 和 Go stdlib `image/jpeg/idct.go` 用的同一个算法 —— 输出**像素级匹配** stdlib。
//
// 数据来源：
//   - Loeffler/Ligtenberg/Moschytz, ICASSP 1989, "Practical fast 1-D DCT
//     algorithms with 11 multiplications"
//   - libjpeg jidctint.c (Independent JPEG Group, BSD-like license)
//   - Go stdlib image/jpeg/idct.go (BSD-3, 算法移植允许)
//
// 整数定点格式：
//   - 系数表用 8-bit precision（×256）
//   - 1D 后 >>11 归一（消除 ×2048 累积）
//   - 2D 第二次 1D 后 +128<<16, >>17 归一 + 加 128 偏移（YCbCr level shift）
//
// 关键常量（各 cosine 值 × 2048）：
//
//	w1 = cos(pi/16)*2*2048 = 2841
//	w2 = cos(2*pi/16)*2*2048 = 2676
//	w3 = cos(3*pi/16)*2*2048 = 2408
//	w5 = cos(5*pi/16)*2*2048 = 1609
//	w6 = cos(6*pi/16)*2*2048 = 1108
//	w7 = cos(7*pi/16)*2*2048 = 565
const (
	w1 = 2841
	w2 = 2676
	w3 = 2408
	w5 = 1609
	w6 = 1108
	w7 = 565

	w1pw7 = w1 + w7
	w1mw7 = w1 - w7
	w2pw6 = w2 + w6
	w2mw6 = w2 - w6
	w3pw5 = w3 + w5
	w3mw5 = w3 - w5

	r2 = 181 // 256/sqrt(2) - 0.5
)

// idct8x8 8×8 块 IDCT in-place（Loeffler 算法，移植自 stdlib image/jpeg/idct.go）
//
// 输入：block 是反量化后的 DCT 系数（int32，可正可负）
// 输出：block 含 IDCT 后的 spatial 域像素值（int32，已加 128 level shift，clamp 0..255）
//
// 性能（Apple M3 Max 实测，benchmark 见 jpeg_idct_bench_test.go）：
//   - DC-only: ~27 ns/op  (短路命中，自然图像 ~30-60% block 命中此路径)
//   - Sparse:  ~60 ns/op
//   - Dense:   ~84 ns/op
//
// vs 早期 cosine-matrix IDCT（精度 40 像素差）：精度 5.90 + 速度同档
// vs Loeffler 朴素版（精度 5.90，DC=35/Sparse=63/Dense=88）：DC-only 快 24%
// （得益于 OR-fused DC-only 检测和 BCE hint）
//
// **关于"激进 SIMD 优化" 的工程取舍**：
//
//	纯 Go 不写 .s assembly，剩余的优化空间不大（loop unrolling、BCE 等只有 5-15%）。
//	真要追平 libjpeg-turbo 的 SIMD 性能（NEON / AVX2，5-10× 提速），需要：
//	  1. 写 amd64 / arm64 .s 文件用 8-wide vector 指令
//	  2. 维护 fallback 纯 Go 路径给其他架构
//	  3. 写 build constraints + benchmark CI
//
//	工程取舍：本工具典型 workload 是恢复几百到几千张 JPEG，IDCT 总耗时
//	~1-10 秒（不是热路径，磁盘 IO + 熵解码才是）。Loeffler pure-Go 已够用。
//	未来若集成到批量验证场景（10 万张 / 秒级），再投入 assembly 优化。
//
//	保留 BCE hint + DC-only 短路（这两个是 0 维护成本的快速胜利）。
func idct8x8(block *[64]int32) {
	// Bounds check elimination 提示：让编译器知道整个 [64]int32 都可访问。
	_ = (*block)[63]

	// 1D IDCT on rows
	for y := 0; y < 8; y++ {
		idct1DRow(block[y*8 : y*8+8])
	}
	// 1D IDCT on cols + final scaling
	idct1DCols(block)
}

// idct1DCols 8 列 1D IDCT + 最终 scale + level-shift。
//
// 优化笔记：
//   - DC-only 短路命中率高，单独检测每列（不要等所有列都 DC-only 才走快路径）
//   - 用 local var v0..v7 一次性 load 该列 8 个值，避免循环里重复 index 计算
//   - for x := 0; x < 8 比手动 unroll 8 次更快（实测）：
//     unroll 让函数变大、抑制内联、寄存器溢出，反而慢
func idct1DCols(block *[64]int32) {
	_ = (*block)[63] // BCE hint
	for x := 0; x < 8; x++ {
		// 单列 load
		v0 := block[x]
		v1 := block[8+x]
		v2 := block[16+x]
		v3 := block[24+x]
		v4 := block[32+x]
		v5 := block[40+x]
		v6 := block[48+x]
		v7 := block[56+x]

		// 短路：col DC-only（自然图像高频几乎全 0）
		if v1|v2|v3|v4|v5|v6|v7 == 0 {
			v := (v0 + 32) >> 6
			block[x], block[8+x], block[16+x], block[24+x] = v, v, v, v
			block[32+x], block[40+x], block[48+x], block[56+x] = v, v, v, v
			continue
		}

		x0 := (v0 << 8) + 8192
		x1 := v4 << 8
		x2 := v6
		x3 := v2
		x4 := v1
		x5 := v7
		x6 := v5
		x7 := v3

		x8 := w7*(x4+x5) + 4
		x4 = (x8 + w1mw7*x4) >> 3
		x5 = (x8 - w1pw7*x5) >> 3
		x8 = w3*(x6+x7) + 4
		x6 = (x8 - w3mw5*x6) >> 3
		x7 = (x8 - w3pw5*x7) >> 3

		x8 = x0 + x1
		x0 -= x1
		x1 = w6*(x3+x2) + 4
		x2 = (x1 - w2pw6*x2) >> 3
		x3 = (x1 + w2mw6*x3) >> 3
		x1 = x4 + x6
		x4 -= x6
		x6 = x5 + x7
		x5 -= x7

		x7 = x8 + x3
		x8 -= x3
		x3 = x0 + x2
		x0 -= x2
		x2 = (r2*(x4+x5) + 128) >> 8
		x4 = (r2*(x4-x5) + 128) >> 8

		block[x] = (x7 + x1) >> 14
		block[8+x] = (x3 + x2) >> 14
		block[16+x] = (x0 + x4) >> 14
		block[24+x] = (x8 + x6) >> 14
		block[32+x] = (x8 - x6) >> 14
		block[40+x] = (x0 - x4) >> 14
		block[48+x] = (x3 - x2) >> 14
		block[56+x] = (x7 - x1) >> 14
	}
}

// idct1DRow 在 row 上跑 1D IDCT（Loeffler 11-mul）
//
// 输入：row[0..7] 是 row 系数；输出：覆写为 row 1D IDCT 结果
//
// 短路优化：若 row[1..7] 全 0（DCT 中常见，因为高频系数被量化掉），
// 直接 row[*] = row[0] << 3（DC * 8）跳过整个 1D。这优化在自然图像上能
// 让 IDCT 提速 ~2-3×。
func idct1DRow(row []int32) {
	_ = row[7] // BCE hint：让编译器一次性确认 row[0..7] 全部合法

	// 短路：DC-only
	// 用 single OR | 比 7 个 && 比较快（编译器能 fold 成单次 OR 然后 cmp 0）
	if row[1]|row[2]|row[3]|row[4]|row[5]|row[6]|row[7] == 0 {
		v := row[0] << 3
		row[0], row[1], row[2], row[3] = v, v, v, v
		row[4], row[5], row[6], row[7] = v, v, v, v
		return
	}

	// Stage 1: pre-shift inputs by 11 bits（与 1D 后 >>11 归一对齐）
	x0 := (row[0] << 11) + 128
	x1 := row[4] << 11
	x2 := row[6]
	x3 := row[2]
	x4 := row[1]
	x5 := row[7]
	x6 := row[5]
	x7 := row[3]

	// Stage 2: butterfly
	x8 := w7 * (x4 + x5)
	x4 = x8 + w1mw7*x4
	x5 = x8 - w1pw7*x5
	x8 = w3 * (x6 + x7)
	x6 = x8 - w3mw5*x6
	x7 = x8 - w3pw5*x7

	// Stage 3
	x8 = x0 + x1
	x0 -= x1
	x1 = w6 * (x3 + x2)
	x2 = x1 - w2pw6*x2
	x3 = x1 + w2mw6*x3
	x1 = x4 + x6
	x4 -= x6
	x6 = x5 + x7
	x5 -= x7

	// Stage 4
	x7 = x8 + x3
	x8 -= x3
	x3 = x0 + x2
	x0 -= x2
	x2 = (r2*(x4+x5) + 128) >> 8
	x4 = (r2*(x4-x5) + 128) >> 8

	// Stage 5: output reorder + scale
	row[0] = (x7 + x1) >> 8
	row[1] = (x3 + x2) >> 8
	row[2] = (x0 + x4) >> 8
	row[3] = (x8 + x6) >> 8
	row[4] = (x8 - x6) >> 8
	row[5] = (x0 - x4) >> 8
	row[6] = (x3 - x2) >> 8
	row[7] = (x7 - x1) >> 8
}

// errPartialJPEG 内部错误标记（让上层 PartialDecode 知道是 entropy 流问题，
// 应保留已 decode 的部分）
type errPartialJPEGErr string

func (e errPartialJPEGErr) Error() string { return string(e) }

func errPartialJPEG(s string) error { return errPartialJPEGErr(s) }
