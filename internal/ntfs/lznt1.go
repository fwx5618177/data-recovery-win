package ntfs

import (
	"encoding/binary"
	"fmt"
)

// LZNT1 是 NTFS 压缩文件使用的压缩算法 —— LZ77 变种。
//
// 为什么需要：
//   Windows 允许用户开启"压缩"属性（explorer → 属性 → 高级 → 压缩内容以节省磁盘空间），
//   系统文件和大文本文件经常带这个属性。开启后文件数据在盘上按 "compression unit"
//   （默认 16 个 cluster）压缩存储；不解压直接复制出来的是**压缩后的二进制**，
//   用户拿到文件打不开。这是我们此前能恢复但恢复出来不能用的一个大类场景。
//
// 数据布局（官方规范：[MS-XCA] §2.5 / NTFS 社区逆向文档）：
//
//   一个 compression unit → 若干 compressed block，每个 block <= 4096 字节解压后大小。
//   每个 compressed block 头 2 字节：
//     bits 0-11:  length = 数据区字节数 - 1
//     bit  12-14: block 签名（忽略）
//     bit  15:    1 = 压缩；0 = 原样存
//   压缩 block 内：按 8-token "组"解码，每组前一字节是 flag byte（bit 0 = token 0,
//   bit 1 = token 1 ...），bit=0 的 token 是 literal 字节、bit=1 的 token 是
//   (offset, length) 复制回指；offset/length 的位宽按解压光标位置动态确定。
//
// 本实现参考自多个开源工具（ntfs-3g / libyal / impacket）在 LZNT1 部分的交叉验证。

const (
	// LZNT1 最大块大小：压缩前后都是 4KB，超过这个一定是坏数据
	lznt1MaxBlockSize = 4096
	// block header 标志位
	lznt1BlockHeaderCompressed = 0x8000
)

// DecompressLZNT1 解压 NTFS LZNT1 压缩流。输入是一个或多个 compression unit
// 拼接后的原始字节流（从磁盘读出来的 compression unit 数据）。
//
// 输出是完整解压后的原始文件内容 ——
// 调用方通常按 file.Size 截断（解压尾部可能多几个零字节来对齐 cluster 边界）。
//
// 对于"稀疏" compression unit（整块是零，没占磁盘空间），调用方责任用 0 填充后传入。
func DecompressLZNT1(compressed []byte) ([]byte, error) {
	out := make([]byte, 0, len(compressed)*2)
	pos := 0

	for pos < len(compressed) {
		// 读 2 字节 block header
		if pos+2 > len(compressed) {
			break // 正常尾部对齐，不是错误
		}
		header := binary.LittleEndian.Uint16(compressed[pos : pos+2])
		pos += 2

		// header == 0 表示后续是 padding 零块，通常是 compression unit 未用完的尾部
		if header == 0 {
			break
		}

		length := int(header&0x0FFF) + 1
		isCompressed := header&lznt1BlockHeaderCompressed != 0

		if pos+length > len(compressed) {
			return out, fmt.Errorf("LZNT1: block 声明长度 %d 超过剩余数据 %d", length, len(compressed)-pos)
		}

		if !isCompressed {
			// 原样存储，直接拷贝
			out = append(out, compressed[pos:pos+length]...)
			pos += length
			continue
		}

		// 压缩块：逐 token 解码
		decoded, err := decompressBlock(compressed[pos : pos+length])
		if err != nil {
			return out, fmt.Errorf("LZNT1: 解压 block (@pos=%d) 失败: %w", pos, err)
		}
		out = append(out, decoded...)
		pos += length
	}

	return out, nil
}

// decompressBlock 解压单个 LZNT1 压缩块。
func decompressBlock(block []byte) ([]byte, error) {
	out := make([]byte, 0, lznt1MaxBlockSize)
	pos := 0

	for pos < len(block) {
		// 一个 flag byte + 最多 8 个 token
		flags := block[pos]
		pos++

		for bit := 0; bit < 8 && pos < len(block); bit++ {
			if flags&(1<<bit) == 0 {
				// Literal 字节
				out = append(out, block[pos])
				pos++
				continue
			}

			// (offset, length) 回指 token，共 2 字节 uint16 LE
			if pos+2 > len(block) {
				return out, fmt.Errorf("token 超出 block")
			}
			token := binary.LittleEndian.Uint16(block[pos : pos+2])
			pos += 2

			// offset / length 的位宽随 out 的长度动态变化：
			// 已解压字节数越多，可回指的最大范围越大，offset 需要更多位
			offsetBits := computeOffsetBits(len(out))
			lengthBits := 16 - offsetBits

			lengthMask := uint16((1 << lengthBits) - 1)
			length := int(token&lengthMask) + 3
			offset := int(token>>lengthBits) + 1

			if offset > len(out) {
				return out, fmt.Errorf("LZNT1 回指 offset=%d 超过已解压字节数 %d", offset, len(out))
			}

			// 复制回指 —— 注意源可以和目的重叠（"自复制"扩展运行长度编码），必须逐字节
			srcStart := len(out) - offset
			for i := 0; i < length; i++ {
				out = append(out, out[srcStart+i])
			}
		}
	}

	return out, nil
}

// computeOffsetBits 根据已解压字节数 n 返回 offset 的位数（LZNT1 规范表）。
// offset 可回指的最大距离随 n 增长；规范用查找表形式：
//
//	n ∈ [0, 16):      offsetBits = 12 (lengthBits = 4)
//	n ∈ [16, 32):     offsetBits = 11
//	n ∈ [32, 64):     offsetBits = 10
//	n ∈ [64, 128):    offsetBits = 9
//	n ∈ [128, 256):   offsetBits = 8
//	n ∈ [256, 512):   offsetBits = 7
//	n ∈ [512, 1024):  offsetBits = 6
//	n ∈ [1024, 2048): offsetBits = 5
//	n ∈ [2048, 4096): offsetBits = 4
//
// 对应 lengthBits = 16 - offsetBits。
func computeOffsetBits(n int) int {
	switch {
	case n < 0x10:
		return 12
	case n < 0x20:
		return 11
	case n < 0x40:
		return 10
	case n < 0x80:
		return 9
	case n < 0x100:
		return 8
	case n < 0x200:
		return 7
	case n < 0x400:
		return 6
	case n < 0x800:
		return 5
	default:
		return 4
	}
}
