package bitlocker

// Memory Image 自动发现 —— 帮用户定位可用来爆破 TPM BitLocker 的内存源。
//
// 真实用户场景：电脑被盗重置 / 忘记密码，TPM-only BitLocker 没 recovery key 就得靠
// 内存里残留的 VMK。常见的 VMK 可提取源（按可用性排序）：
//
//   1. C:\hiberfil.sys       —— Windows 休眠文件（现成；电源关掉前休眠过就有）
//   2. C:\pagefile.sys       —— 页面文件（残留可能性低；随用随覆盖）
//   3. C:\swapfile.sys       —— Windows 10+ UWP app 的 swap
//   4. C:\Windows\MEMORY.DMP —— 内核小转储（BSOD 触发生成）
//   5. C:\Windows\Minidump\  —— 轻量 minidump
//   6. winpmem / DumpIt 实时抓取 —— 需要系统还能开机
//
// 本模块从**卷的根目录**（挂在系统的 C 盘镜像）用 NTFS MFT 扫描找上述文件。
// 前端拿到候选列表后可以一键选中直接喂给 UnlockBitLockerWithMemoryImage。
//
// 现实局限：
//   - 系统被彻底重置（zero-fill）→ 所有文件都没了；碎片里可能还有残片但本模块不做
//   - SSD TRIM 已执行 → 哪怕碎片都清了
//   - hiberfil.sys 被压缩（Win10 默认）→ 需先解压 LZXPRESS（本库已有 compress/lzx）

import (
	"fmt"
	"path/filepath"
	"strings"

	"data-recovery/internal/disk"
	"data-recovery/internal/ntfs"
)

// MemoryImageCandidate 找到的候选 memory image
type MemoryImageCandidate struct {
	Name        string // 展示用："hiberfil.sys (C:)" 或 "Minidump/xxx.dmp"
	Path        string // NTFS 内的相对路径（供展示）
	VolumeOff   int64  // 所在分区 offset
	MFTEntry    int64  // MFT entry 号（用于 recovery）
	Size        int64  // 文件大小（字节）
	Confidence  string // "high" / "medium" / "low"
	Note        string // 使用建议
}

// 候选文件的优先级规则（NTFS 路径前缀 → Confidence + Note）
var memoryImageRules = []struct {
	pattern    string // 小写路径前缀
	name       string
	confidence string
	note       string
}{
	{"hiberfil.sys", "hiberfil.sys", "high",
		"休眠文件 —— 最可能含 VMK；如果是 Win10+ 需要 LZXPRESS 解压（本工具自动）"},
	{"windows/memory.dmp", "MEMORY.DMP", "high",
		"内核完整 memory dump（BSOD 触发）—— 通常含完整内存"},
	{"windows/minidump/", "Minidump/*.dmp", "low",
		"小型 minidump —— 只含崩溃上下文，VMK 命中率低"},
	{"swapfile.sys", "swapfile.sys", "medium",
		"UWP app swap —— VMK 有中等概率残留"},
	{"pagefile.sys", "pagefile.sys", "low",
		"页面文件 —— VMK 残留概率低（频繁覆盖）"},
}

// FindMemoryImagesInVolume 在一个 NTFS 卷上搜索所有候选 memory image 文件。
// volumeOffset 是该 NTFS 分区在物理盘上的 offset（0 = 卷即盘）。
//
// 实现：用 ntfs.Scanner 扫 MFT，对每个文件检查路径前缀是否匹配规则。
// 比完整 NTFS 扫描轻 —— 不做已删除文件恢复，只枚举活文件。
func FindMemoryImagesInVolume(reader disk.DiskReader, volumeOffset int64) ([]MemoryImageCandidate, error) {
	scanner := ntfs.NewScanner(reader)
	boot, err := scanner.ParseBootSector(volumeOffset)
	if err != nil {
		return nil, fmt.Errorf("解析 NTFS boot: %w", err)
	}

	var candidates []MemoryImageCandidate

	// 不做 ctx 取消（这个扫描应该在秒级完成，系统级文件量不大）
	scanErr := scanner.ScanMFT(nil, boot, volumeOffset,
		nil,
		func(entry *ntfs.MFTEntry) {
			if entry == nil || entry.IsDeleted {
				return // 只要活文件
			}
			if entry.FileSize < 1024*1024 {
				return // 小于 1MB 不可能是 memory image
			}
			path := strings.ReplaceAll(strings.ToLower(entry.FullPath), "\\", "/")
			// 根目录情况：FullPath 可能只是文件名
			if path == "" {
				path = strings.ToLower(entry.FileName)
			}
			for _, rule := range memoryImageRules {
				if strings.HasPrefix(path, rule.pattern) ||
					strings.Contains(path, "/"+rule.pattern) {
					candidates = append(candidates, MemoryImageCandidate{
						Name:       rule.name + " @ " + filepath.Base(entry.FullPath),
						Path:       entry.FullPath,
						VolumeOff:  volumeOffset,
						MFTEntry:   entry.EntryNumber,
						Size:       entry.FileSize,
						Confidence: rule.confidence,
						Note:       rule.note,
					})
					return
				}
			}
		},
	)
	if scanErr != nil {
		return nil, fmt.Errorf("扫 MFT: %w", scanErr)
	}
	return candidates, nil
}

// GuessTypicalPaths 返回标准 Windows 路径建议（不扫磁盘，只给文字提示）。
// 前端在"文件选择器" 旁展示给用户参考。
func GuessTypicalPaths() []string {
	return []string{
		`C:\hiberfil.sys`,
		`C:\pagefile.sys`,
		`C:\swapfile.sys`,
		`C:\Windows\MEMORY.DMP`,
		`C:\Windows\Minidump\*.dmp`,
	}
}
