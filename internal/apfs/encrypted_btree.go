package apfs

import (
	"data-recovery/internal/disk"
)

// EncryptedReader 是给 FileVault 卷"在 ParseBTreeNode 之前透明解密节点字节"的桥。
//
// FileVault 卷里所有 fs tree 节点 + 文件 extent 都是 AES-XTS 加密的（VEK 派生）。
// 上层 FSTreeCrawler 想读节点字节调 reader.ReadAt(node_phys_block * blockSize)，
// 我们用 FileVaultXTSCipher 在返回前解密一次即可让 ParseBTreeNode 正常工作。
//
// 与 BitLocker DecryptingReader 的差别：
//   - BitLocker 整卷连续加密；扇区号 = 卷内 byte_offset / 512
//   - APFS FileVault 加密单位是 4KB block；XTS sector_number = block 号（容器内）
//
// 本实现是简化版：假设调用方按 4KB 对齐读 + 每次只读 1 个 block。完整版要支持任意
// offset/size，类似 bitlocker.DecryptingReader 那样按块切分 + 切片返回。
type EncryptedReader struct {
	underlying      disk.DiskReader
	cipher          *FileVaultXTSCipher
	blockSize       uint32
	containerOffset int64
}

// NewEncryptedReader 用解出来的 VEK 构造透明解密 reader。
func NewEncryptedReader(underlying disk.DiskReader, vek []byte, blockSize uint32, containerOffset int64) (*EncryptedReader, error) {
	c, err := NewFileVaultCipher(vek, int(blockSize))
	if err != nil {
		return nil, err
	}
	return &EncryptedReader{
		underlying:      underlying,
		cipher:          c,
		blockSize:       blockSize,
		containerOffset: containerOffset,
	}, nil
}

func (r *EncryptedReader) Open() error          { return r.underlying.Open() }
func (r *EncryptedReader) Close() error         { return r.underlying.Close() }
func (r *EncryptedReader) Size() (int64, error) { return r.underlying.Size() }
func (r *EncryptedReader) SectorSize() int      { return int(r.blockSize) }
func (r *EncryptedReader) DevicePath() string   { return r.underlying.DevicePath() }

// ReadAt 按 4KB 块对齐切，每个块单独 XTS 解密。
//
// XTS sector_number = (offset_in_container) / blockSize（容器内逻辑块号）。
// 调用方传的 offset 应已是容器内 absolute offset（即 containerOffset + relative）。
func (r *EncryptedReader) ReadAt(p []byte, offset int64) (int, error) {
	bs := int64(r.blockSize)
	if offset%bs != 0 || int64(len(p))%bs != 0 {
		// 非对齐请求 — 先按对齐范围读 + 切（简化：调用方应对齐）
		startBlk := offset / bs
		endBlk := (offset + int64(len(p)) + bs - 1) / bs
		alignedLen := (endBlk - startBlk) * bs
		alignedOff := startBlk * bs
		buf := make([]byte, alignedLen)
		n, err := r.readAligned(buf, alignedOff)
		if n == 0 {
			return 0, err
		}
		copy(p, buf[offset-alignedOff:])
		got := int64(n) - (offset - alignedOff)
		if got > int64(len(p)) {
			got = int64(len(p))
		}
		return int(got), err
	}
	return r.readAligned(p, offset)
}

func (r *EncryptedReader) readAligned(p []byte, offset int64) (int, error) {
	bs := int64(r.blockSize)
	n, err := r.underlying.ReadAt(p, offset)
	if n == 0 {
		return 0, err
	}
	// 逐块 in-place 解密
	for i := int64(0); i+bs <= int64(n); i += bs {
		blkNum := uint64((offset + i) / bs)
		// 容器内逻辑 block 号 = (绝对 offset - containerOffset) / bs
		if r.containerOffset > 0 {
			blkNum = uint64((offset + i - r.containerOffset) / bs)
		}
		if err := r.cipher.DecryptSector(p[i:i+bs], p[i:i+bs], blkNum); err != nil {
			return int(i), err
		}
	}
	return n, err
}

// 编译期断言
var _ disk.DiskReader = (*EncryptedReader)(nil)
