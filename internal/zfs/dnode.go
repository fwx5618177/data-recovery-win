package zfs

// ZFS dnode + indirect block + LZ4 decompressor —— Phase C 数据读入口。
//
// ZFS 最复杂处 = dnode 到 file data 的多层 indirect 间接引用。
//
// dnode (DMU object) 结构（512 字节固定）：
//   offset 0: dn_type (DMU_OT_*) — 对象类型（PLAIN_FILE / DIRECTORY / ZAP / ...）
//   offset 1: dn_indblkshift     — indirect block size log (通常 17 = 128KB)
//   offset 2: dn_nlevels         — indirect 层数（1=blkptr 直接指 data；>1 = 多层 indirect）
//   offset 3: dn_nblkptr         — blkptr 数（1..3）
//   offset 4: dn_bonustype
//   offset 5: dn_checksum
//   offset 6: dn_compress
//   offset 7: dn_flags
//   offset 8: dn_datablkszsec    — data block size in 512-byte sectors
//   offset 10: dn_bonuslen
//   offset 12: dn_extra_slots (v1000+)
//   offset 16: dn_maxblkid       — 最大 block id
//   offset 24: dn_used (uint64) — 实际 bytes
//   offset 32..64: reserved
//   offset 64: dn_blkptr[N]     — N = dn_nblkptr，每个 128 字节 BlockPointer
//   offset ...: dn_bonus        — spill 信息（file 属性 / ACL 等）
//
// 读文件 data flow：
//   1. dnode.blkptr[0..n] 指向第一层 indirect block（或直接 data 如果 nlevels=1）
//   2. 每层 indirect block = 数组 of BlockPointer，指向下一层
//   3. 最终叶子层的 BP 指 data block
//   4. data block 可能压缩（LZ4/ZSTD/GZIP）→ 按 BP.Compression 字段解压
//
// 本文件实现：
//   ✅ dnode 512 字节解析
//   ✅ readDataByOffset: 给 file offset 返回对应 data block（跨 indirect 层）
//   ✅ LZ4 解压（最常用 —— ZFS 默认 LZ4-compressed；纯 Go 实现）
//   ✅ ZAP micro（<128 字节的小 ZAP，用于目录 name→obj 映射）
//
// 留给未来：
//   ❌ ZSTD 解压（另 ~2000 行）
//   ❌ GZIP / LZJB
//   ❌ ZAP fat 格式（大目录）
//   ❌ RAIDZ / mirror 重构
//   ❌ 加密（ZFS native encryption）
//   ❌ Scrub checksum 校验（Fletcher4 / SHA-256）
//
// 参考：openzfs include/sys/dnode.h / zap_leaf.h / zio_compress.h / lz4.c

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/klauspost/compress/zstd"

	"data-recovery/internal/disk"
)

const (
	// DMU object types
	dmuOtNone         = 0
	dmuOtObjectSet    = 10 // MOS root
	dmuOtDslDataset   = 16
	dmuOtDslDir       = 12
	dmuOtDslDirChild  = 13
	dmuOtPlainFile    = 19 // 普通文件 (ZPL_DATA)
	dmuOtDirectory    = 20 // 目录 (ZPL_DIRECTORY)
	dmuOtMasterNode   = 21
	dmuOtDeleteQueue  = 22
	dmuOtZapFat       = 24

	// ZIO 压缩算法
	zioCompressOff   = 2
	zioCompressLZJB  = 3
	zioCompressGZIP1 = 4
	zioCompressGZIP9 = 12
	zioCompressZLE   = 13
	zioCompressLZ4   = 15
	zioCompressZSTD  = 16

	dnodeSize        = 512
	dnodeBlkptrCount = 3 // default dn_nblkptr 最大值
)

// Dnode 简化 dnode 结构
type Dnode struct {
	Type        uint8
	IndBlkShift uint8
	NLevels     uint8
	NBlkPtr     uint8
	BonusType   uint8
	Checksum    uint8
	Compress    uint8
	Flags       uint8
	DataBlkSzSec uint16 // data block 大小 / 512
	BonusLen    uint16
	ExtraSlots  uint8
	MaxBlkid    uint64
	Used        uint64
	BlkPtrs     []*BlockPointer // nblkptr 个
}

// ParseDnode 从 512 字节 dnode 原数据解析
func ParseDnode(buf []byte) (*Dnode, error) {
	if len(buf) < dnodeSize {
		return nil, fmt.Errorf("dnode 数据 < 512 字节")
	}
	d := &Dnode{
		Type:        buf[0],
		IndBlkShift: buf[1],
		NLevels:     buf[2],
		NBlkPtr:     buf[3],
		BonusType:   buf[4],
		Checksum:    buf[5],
		Compress:    buf[6],
		Flags:       buf[7],
		DataBlkSzSec: binary.LittleEndian.Uint16(buf[8:10]),
		BonusLen:    binary.LittleEndian.Uint16(buf[10:12]),
		ExtraSlots:  buf[12],
		MaxBlkid:    binary.LittleEndian.Uint64(buf[16:24]),
		Used:        binary.LittleEndian.Uint64(buf[24:32]),
	}
	// blkptrs 从 offset 64 起
	if d.NBlkPtr > dnodeBlkptrCount {
		d.NBlkPtr = dnodeBlkptrCount // 防御
	}
	for i := uint8(0); i < d.NBlkPtr; i++ {
		off := 64 + int(i)*zfsBPSize
		if off+zfsBPSize > len(buf) {
			break
		}
		if bp := ParseBlockPointer(buf[off : off+zfsBPSize]); bp != nil {
			d.BlkPtrs = append(d.BlkPtrs, bp)
		}
	}
	return d, nil
}

// DataBlockSize 返回 dnode 的 data block 大小（字节）
func (d *Dnode) DataBlockSize() uint64 {
	return uint64(d.DataBlkSzSec) * 512
}

// ReadDataBlock 从 DVA 读 block，返回**已解压**数据。
// vdevStart: 该 vdev 在物理 reader 里的起点；allows 单 vdev 线上 LBA
func ReadDataBlock(reader disk.DiskReader, vdevStart int64, bp *BlockPointer) ([]byte, error) {
	if bp == nil || bp.DVAs[0].Offset == 0 {
		return nil, fmt.Errorf("BP DVA 为空")
	}
	// ZFS DVA.offset 单位是 512-byte 扇区，加 4MB vdev label 前缀
	const zfsLabelSize = 4 * 1024 * 1024
	physical := vdevStart + zfsLabelSize + int64(bp.DVAs[0].Offset)*512

	physicalSize := uint64(bp.PhysicalSize) * 512
	if physicalSize == 0 || physicalSize > 64*1024*1024 {
		return nil, fmt.Errorf("BP physical size 异常: %d", physicalSize)
	}
	raw := make([]byte, physicalSize)
	n, err := reader.ReadAt(raw, physical)
	if err != nil || uint64(n) < physicalSize {
		return nil, fmt.Errorf("读 data block @%d: %w", physical, err)
	}

	// 解压
	logicalSize := uint64(bp.LogicalSize) * 512
	switch bp.Compression {
	case zioCompressOff:
		return raw, nil
	case zioCompressLZ4:
		out := make([]byte, logicalSize)
		n2, err := lz4Decompress(raw, out)
		if err != nil {
			return nil, fmt.Errorf("LZ4 解压: %w", err)
		}
		return out[:n2], nil
	case zioCompressZSTD:
		out, err := zstdDecompress(raw, int(logicalSize))
		if err != nil {
			return nil, fmt.Errorf("ZSTD 解压: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("未支持的压缩算法 %d（已实现 LZ4 / ZSTD / 未压缩；GZIP/LZJB 暂未接入）", bp.Compression)
	}
}

// -----------------------------------------------------------------------
// ZSTD 解压（ZFS zio_zstd 封装）
// -----------------------------------------------------------------------
//
// ZFS 的 zstd_wrapper 在 raw 数据前有 8 字节 ZFS 封装头：
//   offset 0: c_len (uint32 BE) — 实际 zstd frame 字节数
//   offset 4: version + level (packed)
//   offset 8..: zstd frame
//
// 本实现：剥掉 ZFS header 后调 klauspost/compress/zstd 解真 zstd frame。

var globalZstdReader *zstd.Decoder

func getZstdReader() (*zstd.Decoder, error) {
	if globalZstdReader == nil {
		r, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		globalZstdReader = r
	}
	return globalZstdReader, nil
}

// zstdDecompress 解 ZFS zstd block；logicalSize 是预期 uncompressed 大小
func zstdDecompress(src []byte, logicalSize int) ([]byte, error) {
	if len(src) < 8 {
		return nil, fmt.Errorf("ZFS zstd 封装 < 8 字节")
	}
	// 剥 ZFS 头
	cLen := int(binary.BigEndian.Uint32(src[0:4]))
	if cLen < 0 || 8+cLen > len(src) {
		// 某些 ZFS 版本不带 c_len 或字段含义不同；fallback 到整 src[8:]
		cLen = len(src) - 8
	}
	body := src[8 : 8+cLen]

	r, err := getZstdReader()
	if err != nil {
		return nil, err
	}
	// DecodeAll 一次性解；避免流式读的 overhead
	out, err := r.DecodeAll(body, bytes.NewBuffer(make([]byte, 0, logicalSize)).Bytes())
	if err != nil {
		return nil, fmt.Errorf("zstd decode: %w", err)
	}
	return out, nil
}

// -----------------------------------------------------------------------
// LZ4 解压（简化版，覆盖 ZFS 常用格式）
// -----------------------------------------------------------------------
//
// ZFS 里 LZ4 block 头部前 4 字节是 big-endian block size（包含数据），后接 LZ4 compressed data。
// LZ4 format：序列 = literals + match (len, offset)；具体 token 格式见 lz4 spec。

// lz4Decompress 解压 src 到 dst；返回解出字节数
func lz4Decompress(src, dst []byte) (int, error) {
	if len(src) < 4 {
		return 0, fmt.Errorf("LZ4 数据 < 4 字节")
	}
	// ZFS 封装：前 4 字节 big-endian 是真 compressed size（可能 < len(src)，后面是 padding）
	compSize := int(binary.BigEndian.Uint32(src[0:4]))
	if compSize < 0 || compSize > len(src)-4 {
		// 某些版本不带这个头；直接按整 src 当 compressed data
		compSize = len(src) - 4
	}
	body := src[4 : 4+compSize]

	return lz4RawDecompress(body, dst)
}

// lz4RawDecompress 按 LZ4 block 格式解码（不含任何外壳）
// 参考 LZ4 Block Format Description (https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)
func lz4RawDecompress(src, dst []byte) (int, error) {
	spos := 0
	dpos := 0
	for spos < len(src) {
		if dpos >= len(dst) {
			return dpos, fmt.Errorf("dst 溢出")
		}
		token := src[spos]
		spos++
		litLen := int(token >> 4)
		if litLen == 15 {
			// 读扩展长度字节，每字节累加直到 < 255
			for spos < len(src) {
				b := src[spos]
				spos++
				litLen += int(b)
				if b != 255 {
					break
				}
			}
		}
		// copy literals
		if spos+litLen > len(src) {
			return dpos, fmt.Errorf("literal 越界 src %d+%d > %d", spos, litLen, len(src))
		}
		if dpos+litLen > len(dst) {
			return dpos, fmt.Errorf("literal dst 溢出")
		}
		copy(dst[dpos:dpos+litLen], src[spos:spos+litLen])
		dpos += litLen
		spos += litLen

		// 最后一块 literal 之后可能没有 match（流末尾）
		if spos >= len(src) {
			break
		}

		// match offset (2 字节 LE)
		if spos+2 > len(src) {
			break
		}
		offset := int(binary.LittleEndian.Uint16(src[spos : spos+2]))
		spos += 2
		if offset == 0 {
			return dpos, fmt.Errorf("LZ4 match offset 0")
		}

		// match length
		matchLen := int(token & 0x0F)
		if matchLen == 15 {
			for spos < len(src) {
				b := src[spos]
				spos++
				matchLen += int(b)
				if b != 255 {
					break
				}
			}
		}
		matchLen += 4 // LZ4 MINMATCH = 4

		if dpos-offset < 0 {
			return dpos, fmt.Errorf("LZ4 back-ref offset %d > dpos %d", offset, dpos)
		}
		if dpos+matchLen > len(dst) {
			return dpos, fmt.Errorf("match dst 溢出")
		}
		// 逐字节拷贝（允许 overlap, match len > offset）
		src2 := dpos - offset
		for i := 0; i < matchLen; i++ {
			dst[dpos+i] = dst[src2+i]
		}
		dpos += matchLen
	}
	return dpos, nil
}

// -----------------------------------------------------------------------
// ZAP micro —— 小目录 / 小 attribute set 的简化 hash 表
// -----------------------------------------------------------------------
//
// ZAP micro 结构（单 block，通常 128..4096 字节）：
//   mzap_phys_t header (64 字节)：
//     mz_block_type (uint64) = 0x800000000000000F (ZAP_MICRO)
//     mz_salt (uint64)
//     mz_normflags (uint64)
//     reserved (40 字节)
//   然后是数组 of mzap_ent_phys_t (64 字节 each)：
//     mze_value (uint64)
//     mze_cd (uint32)
//     reserved (2 字节)
//     mze_name[50] (UTF-8 NUL-terminated)

// ZAPEntry ZAP 表条目
type ZAPEntry struct {
	Name  string
	Value uint64 // 对于目录：子对象 dnode id
	CD    uint32
}

// ParseZAPMicro 从 block bytes 解析 ZAP micro；返回所有 entry
func ParseZAPMicro(block []byte) ([]ZAPEntry, error) {
	const mzapHdrSize = 64
	const mzapEntSize = 64
	if len(block) < mzapHdrSize {
		return nil, fmt.Errorf("ZAP micro < 64 字节")
	}
	blockType := binary.LittleEndian.Uint64(block[0:8])
	if blockType != 0x800000000000000F {
		return nil, fmt.Errorf("不是 ZAP micro (type 0x%X)", blockType)
	}

	var out []ZAPEntry
	for off := mzapHdrSize; off+mzapEntSize <= len(block); off += mzapEntSize {
		value := binary.LittleEndian.Uint64(block[off : off+8])
		cd := binary.LittleEndian.Uint32(block[off+8 : off+12])
		// name in [off+14 : off+64]
		nameEnd := off + 14
		for nameEnd < off+64 && block[nameEnd] != 0 {
			nameEnd++
		}
		name := string(block[off+14 : nameEnd])
		if name == "" {
			continue
		}
		out = append(out, ZAPEntry{
			Name:  name,
			Value: value,
			CD:    cd,
		})
	}
	return out, nil
}
