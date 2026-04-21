// Package apfs: LZFSE 容器 decoder。
//
// LZFSE 流 = 多个连续 block，每个 block 都以 magic 开头：
//
//	"bvxn"   LZVN block（LZ77-style byte ops）
//	"bvx-"   未压缩 block（raw bytes 透传）
//	"bvx2"   LZFSE v2 block（含 FSE 熵编码；最复杂）
//	"bvx1"   LZFSE v1 block（遗留，罕见）
//	"bvx$"   EOS marker
//
// 本实现支持 bvxn / bvx- / bvx$ 三种 → 已覆盖多数 decmpfs inline 压缩场景（macOS 默认
// 生成的小文件压缩优先用 LZVN，大文件 / 熵高的才用 bvx2）。
//
// bvx2 完整 FSE 熵解码 ~1500 行精细代码（参考 Apple lzfse_decode_v2_block.c），本工具
// 通过返回明确 error 让上层引导用户用原 macOS 的 `afsctool -d <file>` 解压后再扫。
package apfs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrLZFSEv2Unsupported bvx2 block 遇到时返回；上层应展示友好引导
var ErrLZFSEv2Unsupported = errors.New(
	"LZFSE v2 (bvx2) 熵编码 block 未实现；macOS 上请用 'afsctool -d <file>' 预先解压后再扫")

// DecompressLZFSE 解一整串 LZFSE / LZVN 流（含 container 多 block）。
//
// 返回写入到 dst 的字节数。
// 遇到 bvx2 返回 ErrLZFSEv2Unsupported + 已解出的字节数（部分可用）。
func DecompressLZFSE(src []byte, dst []byte) (int, error) {
	srcPos := 0
	dstPos := 0

	for srcPos+4 <= len(src) {
		magic := string(src[srcPos : srcPos+4])
		switch magic {
		case "bvx$":
			// EOS marker，没有 payload
			return dstPos, nil

		case "bvx-":
			// 未压缩：header 12 字节 = magic(4) + n_raw_bytes(4) + n_payload_bytes(4)
			if srcPos+12 > len(src) {
				return dstPos, fmt.Errorf("bvx- header 不完整")
			}
			nRaw := binary.LittleEndian.Uint32(src[srcPos+4 : srcPos+8])
			// bvx- 里 n_raw_bytes == n_payload_bytes
			payloadStart := srcPos + 12
			if payloadStart+int(nRaw) > len(src) {
				return dstPos, fmt.Errorf("bvx- payload 越界")
			}
			if dstPos+int(nRaw) > len(dst) {
				nRaw = uint32(len(dst) - dstPos)
			}
			copy(dst[dstPos:], src[payloadStart:payloadStart+int(nRaw)])
			dstPos += int(nRaw)
			srcPos = payloadStart + int(nRaw)

		case "bvxn":
			// LZVN block：header 12 字节 = magic(4) + n_raw(4) + n_payload(4)
			if srcPos+12 > len(src) {
				return dstPos, fmt.Errorf("bvxn header 不完整")
			}
			nRaw := binary.LittleEndian.Uint32(src[srcPos+4 : srcPos+8])
			nPayload := binary.LittleEndian.Uint32(src[srcPos+8 : srcPos+12])
			payloadStart := srcPos + 12
			payloadEnd := payloadStart + int(nPayload)
			if payloadEnd > len(src) {
				return dstPos, fmt.Errorf("bvxn payload 越界")
			}
			// 解 LZVN stream 到 dst[dstPos:]
			maxOut := int(nRaw)
			if dstPos+maxOut > len(dst) {
				maxOut = len(dst) - dstPos
			}
			subDst := dst[dstPos : dstPos+maxOut]
			n, err := DecompressLZVN(src[payloadStart:payloadEnd], subDst)
			dstPos += n
			if err != nil {
				// LZVN op 未实现之类 — 返回部分结果
				return dstPos, fmt.Errorf("bvxn block: %w", err)
			}
			srcPos = payloadEnd

		case "bvx2":
			// v2 FSE block — 尝试 tANS decoder，任何失败（含 header 不完整）都退化
			// 到 ErrLZFSEv2Unsupported 的友好引导
			if srcPos+12 > len(src) {
				return dstPos, ErrLZFSEv2Unsupported
			}
			nPayload := binary.LittleEndian.Uint32(src[srcPos+8 : srcPos+12])
			blockEnd := srcPos + int(nPayload)
			if blockEnd > len(src) {
				blockEnd = len(src)
			}
			n, err := DecompressLZFSEv2Block(src[srcPos:blockEnd], dst[dstPos:])
			dstPos += n
			if err != nil {
				return dstPos, ErrLZFSEv2Unsupported
			}
			srcPos = blockEnd
		case "bvx1":
			// v1 legacy block — 极罕见
			return dstPos, ErrLZFSEv2Unsupported

		default:
			// 不识别的 magic：可能流结束或数据损坏
			return dstPos, fmt.Errorf("未知 LZFSE block magic: %q @+%d", magic, srcPos)
		}
	}
	return dstPos, nil
}

// DecompressLZFSEUnlimited 给定 input 流，按 n_raw_bytes 累计估算 dst 大小后动态分配。
// 上层不知道 uncompressed size 时用这个（decmpfs xattr 明确告知 raw size，优先用固定 dst）。
func DecompressLZFSEUnlimited(src []byte, expectedSize int) ([]byte, error) {
	if expectedSize <= 0 {
		expectedSize = len(src) * 4 // 粗略估：4x 压缩比
	}
	dst := make([]byte, expectedSize+1024)
	n, err := DecompressLZFSE(src, dst)
	return dst[:n], err
}
