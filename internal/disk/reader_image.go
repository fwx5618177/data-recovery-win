package disk

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// imageFileReader 从本地磁盘镜像文件读取 —— 这是业界恢复最佳实践：
// 先把源盘用 ddrescue / HDDSuperClone / DMDE clone 整盘复制成一个 .img 文件，
// 再对 .img 做扫描，源盘放一边不再动。好处：
//   1. 源盘只读一次，避免扫描中意外写入（我们默认只读，但系统/驱动仍可能写缓存）
//   2. 坏道只踩一次，镜像工具能带退避重试；扫描器专注算法
//   3. 可反复重试不同工具不同参数
//
// 这个实现通过 os.File.ReadAt 直接读；操作系统会做 readahead 缓存，性能通常好于直读原盘。
type imageFileReader struct {
	path string
	file *os.File
	size int64
	mu   sync.Mutex // 保护 Open/Close 的状态切换；ReadAt 本身并发安全
}

func newImageFileReader(path string) DiskReader {
	return &imageFileReader{path: path}
}

func (r *imageFileReader) Open() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		return nil
	}
	f, err := os.Open(r.path)
	if err != nil {
		return fmt.Errorf("打开镜像文件失败 [%s]: %w", r.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("读取镜像文件元信息失败: %w", err)
	}
	if info.IsDir() {
		f.Close()
		return fmt.Errorf("镜像路径是目录，不是文件: %s", r.path)
	}
	if info.Size() == 0 {
		f.Close()
		return fmt.Errorf("镜像文件为空: %s", r.path)
	}
	r.file = f
	r.size = info.Size()
	return nil
}

func (r *imageFileReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func (r *imageFileReader) ReadAt(buf []byte, offset int64) (int, error) {
	// os.File.ReadAt 自带并发安全、无需我们加锁
	r.mu.Lock()
	f := r.file
	size := r.size
	r.mu.Unlock()

	if f == nil {
		return 0, fmt.Errorf("镜像文件未打开")
	}
	if offset < 0 || offset >= size {
		return 0, fmt.Errorf("偏移越界 offset=%d size=%d", offset, size)
	}
	return f.ReadAt(buf, offset)
}

func (r *imageFileReader) Size() (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return 0, fmt.Errorf("镜像文件未打开")
	}
	return r.size, nil
}

// SectorSize 镜像文件没有物理扇区概念，报告 512 让其余 NTFS / carver 代码沿用默认假设。
// 若镜像实际来自 4K 原生盘，NTFS 引导扇区里 BytesPerSector 会自己给出真实值，不影响解析。
func (r *imageFileReader) SectorSize() int { return 512 }

func (r *imageFileReader) DevicePath() string { return r.path }

// looksLikeDevicePath 粗略判断一个路径"像不像"操作系统的原盘设备：
//   - Windows 原盘:          `\\.\PhysicalDriveN` / `\\.\C:` / `\\.\X:`
//   - Windows 卷影副本 (VSS): `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`
//   - Unix/macOS:            `/dev/...`
//
// 不在这些形态里的一律当普通文件处理，走 imageFileReader。
func looksLikeDevicePath(p string) bool {
	clean := strings.TrimSpace(p)
	if clean == "" {
		return false
	}
	lower := strings.ToLower(clean)
	if strings.HasPrefix(lower, `\\.\`) {
		return true
	}
	// VSS shadow copy 路径：CreateFile 能直接读，和原盘一样用
	if strings.HasPrefix(lower, `\\?\globalroot\`) {
		return true
	}
	if strings.HasPrefix(clean, "/dev/") {
		return true
	}
	return false
}
