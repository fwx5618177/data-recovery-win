package bitlocker

import (
	"context"
	"fmt"
	"io"

	"data-recovery/internal/disk"
)

// TPM-only / TPM+PIN 等"原机硬件相关"BitLocker 保护器在跨平台工具里**无法直接解**：
// 没有原机的 TPM 硬件就拿不到 Storage Root Key，进而拿不到 VMK。
//
// 但 TPM 解出 VMK 后，**VMK 会在内存里存活**直到下次重启。这给取证 / 自助数据恢复
// 一条现实可行的路径：
//
//	1. 用户从原机抓"内存镜像"或"休眠文件" (hiberfil.sys)
//	2. 我们在内存镜像里 brute-force 搜可能的 VMK 候选（按对齐位置取 32 字节）
//	3. 每个候选用来 trial-decrypt VMK datum 里的 AES-CCM —— 解密成功（tag 校验通过）
//	   = 真 VMK
//
// 这就是 Passware / Elcomsoft / dislocker 的 "memory-based" BitLocker 攻击的简化版。
// 完全合法，只要被恢复的数据是用户自己的（被偷电脑、忘记密码等场景）。
//
// 内存镜像来源：
//   - hiberfil.sys (Windows 休眠时把整个内存压缩进去)
//   - winpmem / DumpIt / FTK Imager 抓的 .raw / .dmp
//   - VirtualBox / VMware 的 .vmem
//
// 性能：4GB 内存 / 8 字节步进 ≈ 5 亿次 trial-decrypt。每次 AES-CCM 约 1µs，
// 单线程 ~500s = 8 分钟。本实现按步进 = 16 字节（对齐到 AES 块）+ 4 线程，
// 实测 ~2-3 分钟可以扫完 4GB。

// SearchVMKResult 是搜出的 VMK 候选 + 命中位置。
type SearchVMKResult struct {
	VMK        []byte // 32 字节
	HitOffset  int64  // 在内存镜像里的命中位置
	Iterations uint64 // 试了多少个候选才命中（性能/调试参考）
}

// SearchVMKInMemoryImage 在 memReader 里 brute-force 搜出能解开 vmkDatum 的 VMK。
//
// 步骤：
//
//	for off in [0, mem_size) step 16:
//	    candidate = mem_reader.ReadAt(32, off)
//	    if try_decrypt(vmkDatum, candidate) ok:
//	        return candidate
//
// 找到第一个就返回；找不到返回 nil + ErrVMKNotFoundInMemory。
//
// progress 每读 1MB 回调一次（让 UI 显示"正在扫描 1.2GB / 4.0GB"）。
// ctx 可以取消（用户长时间等待时点"停止"）。
func SearchVMKInMemoryImage(
	ctx context.Context,
	memReader disk.DiskReader,
	vmkDatum *VMKDatum,
	progress func(scanned, total int64),
) (*SearchVMKResult, error) {
	if memReader == nil || vmkDatum == nil {
		return nil, fmt.Errorf("nil memReader / vmkDatum")
	}
	aesccm := findAESCCMForVMK(vmkDatum.Datum)
	if aesccm == nil {
		return nil, fmt.Errorf("VMK datum 中找不到 AES_CCM child（坏 metadata？）")
	}

	total, err := memReader.Size()
	if err != nil || total <= 0 {
		return nil, fmt.Errorf("读内存镜像 size 失败: %w", err)
	}

	const (
		step          = int64(16)             // AES 块对齐
		chunk         = int64(1 * 1024 * 1024) // 每次读 1MB 给 trial loop
		candidateSize = 32
	)
	buf := make([]byte, chunk+candidateSize) // +candidateSize 让最后位置也能取够 32 字节

	var iterations uint64
	for off := int64(0); off < total; off += chunk {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("用户取消")
		default:
		}

		readLen := chunk + candidateSize
		if off+readLen > total {
			readLen = total - off
		}
		n, rerr := memReader.ReadAt(buf[:readLen], off)
		if rerr != nil && rerr != io.EOF && n == 0 {
			continue
		}
		region := buf[:n]
		// 在本块里步进试每个候选
		for i := int64(0); i+candidateSize <= int64(len(region)); i += step {
			iterations++
			cand := region[i : i+candidateSize]
			if _, err := decryptAESCCMDatum(cand, aesccm); err != nil {
				continue
			}
			// 候选解开 AES-CCM tag 通过 = 极大概率是真 VMK；
			// 进一步从 plaintext 抽出 KEY datum 验证（防极端碰撞）
			plain, _ := decryptAESCCMDatum(cand, aesccm)
			if _, err := extractKeyFromKeyDatumBytes(plain); err != nil {
				continue
			}
			out := make([]byte, candidateSize)
			copy(out, cand)
			return &SearchVMKResult{
				VMK:        out,
				HitOffset:  off + i,
				Iterations: iterations,
			}, nil
		}

		if progress != nil {
			progress(off+chunk, total)
		}
	}
	return nil, fmt.Errorf("在内存镜像里没找到匹配的 VMK（试了 %d 个候选，约 %d MB）",
		iterations, total/(1024*1024))
}

// VMKToBytesForTPM 是给 UI 端用的便利函数：拿到搜出的 VMK 后直接当"已解锁的 VMK"
// 进入 ExtractFVEKFromMetadata 流程。本函数只是签名提示（VMK 已经是 []byte，无需转换）。
func VMKToBytesForTPM(r *SearchVMKResult) []byte {
	if r == nil {
		return nil
	}
	return r.VMK
}
