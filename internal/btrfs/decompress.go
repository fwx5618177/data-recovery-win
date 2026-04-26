package btrfs

// Btrfs extent 解压
//
// Btrfs EXTENT_DATA.compression：
//
//	0  none   (raw data)
//	1  zlib   (RFC 1950 zlib stream)
//	2  LZO    (lzo1x_1)
//	3  ZSTD
//
// 当前覆盖：
//   ✅ zlib（compress/zlib stdlib）
//   ✅ ZSTD（github.com/klauspost/compress/zstd）
//   ❌ LZO（无现成纯 Go 实现；用户遇到 LZO 卷需用 btrfs-progs / mount 后再扫）
//
// 重要细节：btrfs 的压缩 extent 在盘上的字节数 = DiskNumBytes（压缩后），
// 解压后的字节数 = ExtentLength（FSExtent.Length，对应 num_bytes）。
// extent 内还有 ExtentOffset（指向 extent 内某偏移开始的子段）—— 我们
// 解压整个 extent 后再切片到 [ExtentOffset, ExtentOffset+Length)。

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// Btrfs compression type 常量
const (
	BTRFS_COMPRESSION_NONE = 0
	BTRFS_COMPRESSION_ZLIB = 1
	BTRFS_COMPRESSION_LZO  = 2
	BTRFS_COMPRESSION_ZSTD = 3
)

// ErrCompressionUnsupported 当前不支持的压缩类型（如 LZO）
var ErrCompressionUnsupported = errors.New("btrfs: 不支持的压缩类型")

// DecompressExtent 把单个 extent 的盘上字节流解压成原文。
//
//	rawDiskBytes  从盘上按 ExtentOffset / DiskNumBytes 读出来的字节
//	compression   FSExtent.Compression
//	expectedLen   解压后期望的字节数（= FSExtent.Length，用作上限保护）
//	extentOffset  在解压结果里的起始位置（FSExtent.ExtentOffset）
//
// 返回 [extentOffset, extentOffset+expectedLen) 的解压字节。
//
// 不区分 "解压后比 expectedLen 短" 与 "刚好" —— 短读返回拿到的字节，
// 让 writer 上层决定是否补零；这样对部分损坏的 extent 仍能恢复一段。
func DecompressExtent(rawDiskBytes []byte, compression uint8, expectedLen uint64, extentOffset uint64) ([]byte, error) {
	if compression == BTRFS_COMPRESSION_NONE {
		// 不压缩：直接按 [extentOffset, extentOffset+expectedLen) 切
		start := int(extentOffset)
		end := start + int(expectedLen)
		if start > len(rawDiskBytes) {
			return nil, nil
		}
		if end > len(rawDiskBytes) {
			end = len(rawDiskBytes)
		}
		out := make([]byte, end-start)
		copy(out, rawDiskBytes[start:end])
		return out, nil
	}

	var decoded []byte
	var err error
	switch compression {
	case BTRFS_COMPRESSION_ZLIB:
		decoded, err = decompressZlib(rawDiskBytes, expectedLen+extentOffset)
	case BTRFS_COMPRESSION_ZSTD:
		decoded, err = decompressZstd(rawDiskBytes, expectedLen+extentOffset)
	case BTRFS_COMPRESSION_LZO:
		return nil, fmt.Errorf("%w: LZO（请挂载或用 btrfs-progs 后再扫）", ErrCompressionUnsupported)
	default:
		return nil, fmt.Errorf("%w: type=%d", ErrCompressionUnsupported, compression)
	}
	if err != nil {
		return nil, err
	}

	// 切到 [extentOffset, extentOffset+expectedLen)
	start := int(extentOffset)
	end := start + int(expectedLen)
	if start > len(decoded) {
		return nil, nil
	}
	if end > len(decoded) {
		end = len(decoded)
	}
	out := make([]byte, end-start)
	copy(out, decoded[start:end])
	return out, nil
}

// decompressZlib 用 stdlib 解 zlib 流（btrfs 用 RFC 1950 wrapped format）。
//
// maxOut 是预期解压字节数的上限 —— 防御性，超过则报错（损坏 / 恶意流可能解出 GB 级垃圾）。
func decompressZlib(src []byte, maxOut uint64) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("zlib reader 初始化: %w", err)
	}
	defer r.Close()
	limit := int64(maxOut + 1024) // 给点余量
	if limit > 256*1024*1024 {
		// 上限 256MB；btrfs 单 extent 一般 ≤ 128KB
		limit = 256 * 1024 * 1024
	}
	out, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("zlib 解压: %w", err)
	}
	return out, nil
}

// decompressZstd 用 klauspost/compress/zstd 解 ZSTD 流。
func decompressZstd(src []byte, maxOut uint64) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("zstd reader: %w", err)
	}
	defer dec.Close()
	out, err := dec.DecodeAll(src, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd DecodeAll: %w", err)
	}
	if uint64(len(out)) > maxOut+1024 && maxOut > 0 {
		// 严防解压炸弹（zip-bomb 防御）
		return nil, fmt.Errorf("zstd 解压结果 %d 远超预期 %d", len(out), maxOut)
	}
	return out, nil
}
