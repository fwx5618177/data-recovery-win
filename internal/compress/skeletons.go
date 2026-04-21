// Package compress 提供压缩格式骨架 — HFS+ decmpfs / NTFS LZX。
//
// **关键现实**：
//   - 完整 LZFSE entropy coder ~1500 行（Apple BSD 源码移植 + Go 适配）
//   - LZX (cabinet/WIM) ~800 行 sliding window LZ77 + huffman
//
// 这些是独立项目级工作量。本包只提供**识别 + 占位接口**，让上层知道"这是什么压缩"，
// 并给用户明确的"用 X 工具解压" 指引；不实际做完整解压。
//
// 真要用：
//   - HFS+ decmpfs + LZFSE：cgo 包 lzfse_decode_buffer 或纯 Go 移植 lzfse 项目
//   - NTFS LZX：移植 mscompress / Linux fs/ntfs3 的 LZX decoder
package compress

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"data-recovery/internal/compress/lzx"
)

// DecmpfsHeader HFS+ com.apple.decmpfs xattr 的头部（16 字节）：
//
//	+0x00 magic "fpmc" (LE uint32 = 0x636D7066)
//	+0x04 type      uint32 LE
//	+0x08 raw size  uint64 LE
//	+0x10 ... data
//
// type 取值：
//   1 = uncompressed, inline in xattr
//   3 = zlib-deflate, inline (data follows header)
//   4 = zlib-deflate, in resource fork
//   5 = "no" (sparse) — extents 全 0
//   7 = LZVN, inline
//   8 = LZVN, in resource fork
//  11 = LZFSE, inline
//  12 = LZFSE, in resource fork
const decmpfsMagic uint32 = 0x636D7066 // "fpmc"

type DecmpfsHeader struct {
	Type    uint32
	RawSize uint64
}

// ParseDecmpfsHeader 解 16 字节头
func ParseDecmpfsHeader(b []byte) (*DecmpfsHeader, error) {
	if len(b) < 16 {
		return nil, fmt.Errorf("decmpfs header 太短")
	}
	if binary.LittleEndian.Uint32(b[0:4]) != decmpfsMagic {
		return nil, fmt.Errorf("非 decmpfs xattr (magic %X)", b[0:4])
	}
	return &DecmpfsHeader{
		Type:    binary.LittleEndian.Uint32(b[4:8]),
		RawSize: binary.LittleEndian.Uint64(b[8:16]),
	}, nil
}

// DecompressDecmpfsInline 解开 type=3 (zlib inline) 的 decmpfs data。
// 其它 type（LZVN/LZFSE/resource fork）返回 ErrUnsupported — 上层 fallback 跳过文件。
func DecompressDecmpfsInline(data []byte) ([]byte, error) {
	hdr, err := ParseDecmpfsHeader(data)
	if err != nil {
		return nil, err
	}
	body := data[16:]
	switch hdr.Type {
	case 1:
		// uncompressed inline — body 前 1 byte 可能是 0xFF 标记，跳过
		if len(body) > 0 && body[0] == 0xFF {
			body = body[1:]
		}
		return body, nil
	case 3: // zlib inline
		// body 前 1 byte 0x78 是 zlib header — 标准 zlib 流
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("zlib reader: %w", err)
		}
		defer zr.Close()
		out := bytes.NewBuffer(make([]byte, 0, hdr.RawSize))
		if _, err := io.Copy(out, zr); err != nil {
			return nil, fmt.Errorf("zlib copy: %w", err)
		}
		return out.Bytes(), nil
	case 5: // sparse 全 0
		return make([]byte, hdr.RawSize), nil
	}
	return nil, ErrUnsupported
}

// ErrUnsupported 上层应跳过此文件并展示"原文件 LZVN/LZFSE/resource fork 压缩，
// 暂未支持完整解压"提示
var ErrUnsupported = errors.New("decmpfs type 未支持（LZVN/LZFSE/resource fork）")

// =============================================================
// NTFS LZX (Compact OS) 占位接口
// Compact OS 用 WIM 风格 LZX 压缩系统文件；解压完整算法 ~800 行。
// 本工具识别 + 提示用户 "用 PowerShell: compact /U <file> 解压" 。
// =============================================================

// LZXFileHeader 在 NTFS Win10+ 系统文件 + 资源 fork 里出现，magic "WIM\0"
const wimMagic = "MSWIM\x00\x00\x00"

// IsLZXCompact NTFS LZX (Compact OS) 文件识别
func IsLZXCompact(b []byte) bool {
	return len(b) >= 8 && string(b[0:8]) == wimMagic
}

// WIMHeader WIM 文件头关键字段（按 Microsoft WIM Specification v1.2）：
//
//	+0x00 magic "MSWIM\0\0\0" (8)
//	+0x08 header_size  uint32  通常 208
//	+0x0C version     uint32
//	+0x10 flags        uint32  compression type (FLAG_COMPRESSION_XPRESS=0x20000,
//	                                              FLAG_COMPRESSION_LZX=0x40000,
//	                                              FLAG_COMPRESSION_LZMS=0x80000)
//	+0x14 chunk_size   uint32  通常 0x8000 = 32KB
//	...
type WIMHeader struct {
	HeaderSize      uint32
	Version         uint32
	Flags           uint32
	ChunkSize       uint32
	Compression     string // "LZX" / "XPRESS" / "LZMS" / "uncompressed"
}

// ParseWIMHeader 解前 208 字节；返回压缩类型。识别后上层可决定是否调用外部解压（compact /U）
// 或跳过。
func ParseWIMHeader(b []byte) (*WIMHeader, error) {
	if !IsLZXCompact(b) {
		return nil, errors.New("非 WIM / MSWIM magic")
	}
	if len(b) < 0x18 {
		return nil, errors.New("WIM header 太短")
	}
	hdr := &WIMHeader{
		HeaderSize: leU32(b[8:12]),
		Version:    leU32(b[12:16]),
		Flags:      leU32(b[16:20]),
		ChunkSize:  leU32(b[20:24]),
	}
	switch {
	case hdr.Flags&0x20000 != 0:
		hdr.Compression = "XPRESS"
	case hdr.Flags&0x40000 != 0:
		hdr.Compression = "LZX"
	case hdr.Flags&0x80000 != 0:
		hdr.Compression = "LZMS"
	default:
		hdr.Compression = "uncompressed"
	}
	return hdr, nil
}

// DecompressLZX 用 internal/compress/lzx 的解压器解一个 LZX chunk。
//
// 输入是单个 WIM chunk 的 LZX stream（每个 WIM chunk 独立解，前 2 字节 compressed size
// 由调用方剥掉再传进来）。windowSize 默认 32KB（WIM），CAB 可传 2^15..2^21。
// uncompressedSize 来自 WIM chunk 表。
func DecompressLZX(src []byte, uncompressedSize, windowSize int) ([]byte, error) {
	if uncompressedSize <= 0 {
		return nil, errors.New("uncompressedSize 必须 > 0")
	}
	if windowSize <= 0 {
		windowSize = 32 * 1024
	}
	d := lzx.NewDecoder(windowSize, uncompressedSize)
	out := make([]byte, uncompressedSize)
	n, err := d.Decode(src, out)
	if err != nil {
		return out[:n], err
	}
	return out[:n], nil
}

// leU32 little-endian uint32（避免引 encoding/binary 只为此）
func leU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
