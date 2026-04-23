package zfs

// ZFS Uberblock + MOS (Meta-Object Set) 入口 —— Phase 7 基础设施。
//
// ZFS 极复杂（Sun 设计的 volume manager + FS 合体）；完整 dataset 文件枚举
// ≈ 15000 行（openzfs 源码级）。本文件仅做**入口层**：
//   ✅ Uberblock 数组解析（每 vdev label 尾部 128 KB 存 128 个 uberblock，循环写）
//   ✅ 找最新（txg 最大）的 active uberblock
//   ✅ 从 uberblock 抽 MOS root dnode 的 block pointer (bp)
//   ✅ Block Pointer 128 字节结构解析（含 DVA 数组 / 压缩 / 校验和类型）
//   ✅ DVA → (vdev, offset) 翻译
//
// 留给未来：
//   ❌ 读 MOS dnode → 找 DSL directory → 找各 dataset root
//   ❌ dnode 树遍历（间接 block 层级展开）
//   ❌ 压缩解（LZ4 / ZSTD / GZIP / LZJB）
//   ❌ 加密（AES-GCM）
//   ❌ RAIDZ / mirror / dRAID 重构
//   ❌ Fletcher / SHA-256 校验
//   ❌ bp rewrite / scrub metadata
//
// 参考：
//   openzfs include/sys/spa.h, zio.h, dmu.h, dnode.h, uberblock_impl.h
//   "ZFS Evil Tuning Guide" + FreeBSD Handbook ZFS 章节

import (
	"encoding/binary"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

const (
	// ZFS vdev label 是 256 KB（4 份，每份 256 KB 在 vdev 起点 / 末尾）
	zfsVdevLabelSize = 256 * 1024

	// Uberblock 数组从 label 的 128 KB 偏移开始
	zfsUberblockArrayOffset = 128 * 1024

	// Uberblock 大小固定 1 KB；共 128 个（128 KB / 1 KB）
	zfsUberblockSize    = 1024
	zfsUberblocksInLabel = 128

	// Uberblock magic 0x00bab10c（little-endian "boobla" 之类约定）
	zfsUberblockMagic uint64 = 0x00bab10c

	// Block Pointer 固定 128 字节
	zfsBPSize = 128
)

// Uberblock 一个 ZFS 超块（pool 状态的 root snapshot）
type Uberblock struct {
	Magic      uint64
	Version    uint64
	TXG        uint64 // transaction group 号 —— 越大越新，active 的一定是 max
	GUIDSum    uint64
	Timestamp  uint64
	RootBP     BlockPointer // 指向 MOS root dnode 的 block pointer
	Label      int          // 本 uberblock 属于第几个 label (0..3)
	IndexInArr int          // 本 label 内 uberblock 数组的第几项
	PhysOffset int64        // 在盘上的字节位置（方便验证 / debug）
}

// BlockPointer ZFS 128 字节 block_pointer_t 的简化解析
type BlockPointer struct {
	DVAs    [3]DVA // 最多 3 份（ditto block）；大多数普通 BP 只用 [0]
	Props   uint64 // compression / encryption / checksum type 等 bit-field
	BirthTXG uint64
	FillCount uint64
	Cksum   [32]byte // 校验和 (256 bits)

	// 方便字段
	LogicalSize  uint32 // 从 Props bit-field 抽出
	PhysicalSize uint32
	Compression  uint8
	Checksum     uint8
	DedupFlag    bool
	Level        uint8 // indirect block 层级
}

// DVA Data Virtual Address：告诉你数据在哪个 vdev 的哪个 offset
type DVA struct {
	VDev   uint32 // pool 里的 vdev 编号
	GANGed bool   // gang block（分散成多块）
	ASize  uint32 // allocated size（扇区数 × 2^SHIFT）
	Offset uint64 // 在 vdev 里的 offset（扇区单位）
}

// ParseBlockPointer 128 字节 bp 解析
func ParseBlockPointer(b []byte) *BlockPointer {
	if len(b) < zfsBPSize {
		return nil
	}
	bp := &BlockPointer{}
	// 3 × 16 字节 DVA（0..47）
	for i := 0; i < 3; i++ {
		off := i * 16
		word0 := binary.LittleEndian.Uint64(b[off : off+8])
		word1 := binary.LittleEndian.Uint64(b[off+8 : off+16])
		bp.DVAs[i].VDev = uint32(word0 >> 32)
		bp.DVAs[i].GANGed = word0&(1<<63) != 0
		bp.DVAs[i].ASize = uint32(word0 & 0xFFFFFF)
		bp.DVAs[i].Offset = word1 & 0x7FFFFFFFFFFFFFFF
	}
	bp.Props = binary.LittleEndian.Uint64(b[48:56])

	// Props bit-field (openzfs block_pointer_t 定义)：
	//   bits 0-15:  lsize - 1 （实际 lsize 以扇区数 << SHIFT，这里按 uint16）
	//   bits 16-31: psize - 1
	//   bits 32-39: compression
	//   bits 40-47: checksum
	//   bits 48-55: type (DMU_OT_*)
	//   bits 56-60: level
	//   bit 61: encryption
	//   bit 62: dedup
	//   bit 63: little-endian flag
	bp.LogicalSize = uint32(bp.Props&0xFFFF) + 1
	bp.PhysicalSize = uint32((bp.Props>>16)&0xFFFF) + 1
	bp.Compression = uint8((bp.Props >> 32) & 0xFF)
	bp.Checksum = uint8((bp.Props >> 40) & 0xFF)
	bp.Level = uint8((bp.Props >> 56) & 0x1F)
	bp.DedupFlag = bp.Props&(1<<62) != 0

	bp.BirthTXG = binary.LittleEndian.Uint64(b[56:64])
	bp.FillCount = binary.LittleEndian.Uint64(b[64:72])
	copy(bp.Cksum[:], b[96:128])
	return bp
}

// ParseUberblock 1 KB 的 uberblock 解析
func ParseUberblock(b []byte) (*Uberblock, error) {
	if len(b) < zfsUberblockSize {
		return nil, fmt.Errorf("uberblock < 1KB")
	}
	u := &Uberblock{}
	u.Magic = binary.LittleEndian.Uint64(b[0:8])
	if u.Magic != zfsUberblockMagic {
		return nil, fmt.Errorf("uberblock magic 不匹配: 0x%X", u.Magic)
	}
	u.Version = binary.LittleEndian.Uint64(b[8:16])
	u.TXG = binary.LittleEndian.Uint64(b[16:24])
	u.GUIDSum = binary.LittleEndian.Uint64(b[24:32])
	u.Timestamp = binary.LittleEndian.Uint64(b[32:40])
	// rootbp 在 offset 40，128 字节
	if bp := ParseBlockPointer(b[40 : 40+zfsBPSize]); bp != nil {
		u.RootBP = *bp
	}
	return u, nil
}

// LoadActiveUberblock 扫 4 个 vdev label 的 uberblock 数组，返回 txg 最大的 active 那个。
//
// vdev label 位置（相对 vdev 起点）：
//   L0: 0 KB
//   L1: 256 KB
//   L2: vdev_size - 512 KB
//   L3: vdev_size - 256 KB
func LoadActiveUberblock(reader disk.DiskReader, vdevStart, vdevSize int64) (*Uberblock, error) {
	labelOffsets := []int64{
		0,
		zfsVdevLabelSize,
		vdevSize - 2*zfsVdevLabelSize,
		vdevSize - zfsVdevLabelSize,
	}
	var best *Uberblock
	for labelIdx, labelOff := range labelOffsets {
		if labelOff < 0 || labelOff+zfsVdevLabelSize > vdevSize {
			continue
		}
		// 扫这个 label 的 128 个 uberblock
		for i := 0; i < zfsUberblocksInLabel; i++ {
			ubOff := vdevStart + labelOff + zfsUberblockArrayOffset + int64(i)*zfsUberblockSize
			buf := make([]byte, zfsUberblockSize)
			n, err := reader.ReadAt(buf, ubOff)
			if err != nil && err != io.EOF {
				continue
			}
			if n < zfsUberblockSize {
				continue
			}
			u, err := ParseUberblock(buf)
			if err != nil {
				continue // 这槽位没 active uberblock 很正常
			}
			u.Label = labelIdx
			u.IndexInArr = i
			u.PhysOffset = ubOff
			if best == nil || u.TXG > best.TXG {
				best = u
			}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("四个 vdev label 里没找到合法 uberblock")
	}
	return best, nil
}

// DescribePool 返回活 uberblock 的摘要 —— 给用户看 "这是个什么池"
func DescribePool(u *Uberblock) string {
	return fmt.Sprintf(
		"ZFS pool: version=%d txg=%d guidSum=0x%X timestamp=%d MOSrootDVA0=(vdev=%d offset=0x%X asize=%d) compression=%d",
		u.Version, u.TXG, u.GUIDSum, u.Timestamp,
		u.RootBP.DVAs[0].VDev, u.RootBP.DVAs[0].Offset, u.RootBP.DVAs[0].ASize,
		u.RootBP.Compression,
	)
}
