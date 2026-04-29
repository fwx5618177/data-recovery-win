package types

import (
	"fmt"
	"time"
)

// FileCategory 文件分类
type FileCategory string

const (
	CategoryImage    FileCategory = "image"
	CategoryDocument FileCategory = "document"
	CategoryVideo    FileCategory = "video"
	CategoryAudio    FileCategory = "audio"
	CategoryArchive  FileCategory = "archive"
	CategoryDatabase FileCategory = "database"
	CategoryOther    FileCategory = "other"
)

// CategoryLabel 返回分类的中文名称
func (c FileCategory) Label() string {
	switch c {
	case CategoryImage:
		return "图片"
	case CategoryDocument:
		return "文档"
	case CategoryVideo:
		return "视频"
	case CategoryAudio:
		return "音频"
	case CategoryArchive:
		return "压缩包"
	case CategoryDatabase:
		return "数据库"
	default:
		return "其他"
	}
}

// CategoryIcon 返回分类 emoji
func (c FileCategory) Icon() string {
	switch c {
	case CategoryImage:
		return "🖼️"
	case CategoryDocument:
		return "📄"
	case CategoryVideo:
		return "🎬"
	case CategoryAudio:
		return "🎵"
	case CategoryArchive:
		return "📦"
	case CategoryDatabase:
		return "🗃️"
	default:
		return "📁"
	}
}

// ScanMode 扫描模式
type ScanMode string

const (
	ScanQuick ScanMode = "quick" // 快速：仅 NTFS MFT
	ScanDeep  ScanMode = "deep"  // 深度：仅深度扫描
	ScanFull  ScanMode = "full"  // 完整：NTFS + 深度扫描
)

// ScanOptions 扫描参数包。把 Mode + 取证开关 + 未来要加的可选项打包传入 Engine。
//
// IncludeDeletedPartitions 控制 brute-force 全盘签名扫描是否启用：
//
//   - false（默认）：只走 MBR / GPT / offset-0 的 fast path。健康磁盘上 fast path
//     在微秒内拿到答案 —— 跳过 brute-force 是行业标准（R-Studio "Quick scan" /
//     PhotoRec 默认 / DMDE "Quick" / TestDisk 默认）。fast path 失败时也直接返回
//     空，让上层决定要不要换 forensic 模式重扫。**不做 fallback 类的隐式重试。**
//
//   - true（取证模式 / 找已删除分区）：在 fast path 之外**总是**额外跑 brute-force。
//     用于 R-Studio 的 "deleted partition recovery" / DMDE 的 "Full scan" / 重置过
//     的笔记本找回旧 NTFS 残骸 / 司法取证场景。代价：每个支持 brute-force 的 FS
//     都额外读一遍全盘。125GB 盘 ≈ 1-2 小时（USB 3.0），对应每 FS 一遍。
//
// 决策依据：默认场景下，brute-force 在 healthy disk 上**找不到任何 fast path 没找到的东西**
// （strategy-a 命中后 brute-force 找到的同一个分区会被 dedup 干掉）—— 就是纯浪费 IO。
// v2.8.7 之前的行为是"永远 brute-force"，本质上把所有用户的扫描时间放大 N×
// （N = brute-force 跑的 FS 数），换不到任何额外文件。
type ScanOptions struct {
	Mode                     ScanMode
	IncludeDeletedPartitions bool
}

// DriveInfo 驱动器信息
type DriveInfo struct {
	Path        string `json:"path"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	SizeHuman   string `json:"sizeHuman"`
	DriveType   string `json:"driveType"` // "physical" / "logical"
	FileSystem  string `json:"fileSystem"`
	IsRemovable bool   `json:"isRemovable"`
}

// FileSignature 文件签名定义
type FileSignature struct {
	Extension   string       `json:"extension"`
	Description string       `json:"description"`
	Category    FileCategory `json:"category"`
	Headers     [][]byte     `json:"-"` // 魔术字节头部（可能有多个变体）
	Footers     [][]byte     `json:"-"` // 可选尾部标记
	MaxSize     int64        `json:"maxSize"`
}

// RecoveredFile 统一的恢复文件信息
type RecoveredFile struct {
	ID            string       `json:"id"`
	Source        string       `json:"source"` // "carver" / "ntfs"
	FileName      string       `json:"fileName"`
	Extension     string       `json:"extension"`
	Category      FileCategory `json:"category"`
	Size          int64        `json:"size"`
	SizeHuman     string       `json:"sizeHuman"`
	Offset        int64        `json:"offset"`
	Confidence    float64      `json:"confidence"` // 0.0 - 1.0
	CreatedTime   *time.Time   `json:"createdTime,omitempty"`
	ModifiedTime  *time.Time   `json:"modifiedTime,omitempty"`
	IsDeleted     bool         `json:"isDeleted"`
	OriginalPath  string       `json:"originalPath"`
	Description   string       `json:"description"`
	IsValid       bool         `json:"isValid"`
	ValidationMsg string       `json:"validationMsg"`
	SHA256        string       `json:"sha256,omitempty"` // 写入完成后回填，用于 manifest 与跨源去重
}

// ScanProgress 扫描进度（实时推送到前端）
type ScanProgress struct {
	Phase        string  `json:"phase"`   // "ntfs" / "carving" / "validating"
	Percent      float64 `json:"percent"` // 0-100
	BytesScanned int64   `json:"bytesScanned"`
	TotalBytes   int64   `json:"totalBytes"`
	FilesFound   int     `json:"filesFound"`
	CurrentFile  string  `json:"currentFile"`
	Speed        int64   `json:"speed"` // bytes/sec
	ETA          string  `json:"eta"`
	Elapsed      string  `json:"elapsed"`
}

// RecoveryProgress 恢复进度
type RecoveryProgress struct {
	Current      int    `json:"current"`
	Total        int    `json:"total"`
	CurrentFile  string `json:"currentFile"`
	BytesWritten int64  `json:"bytesWritten"`
	Success      int    `json:"success"`
	Partial      int    `json:"partial"`
	Failed       int    `json:"failed"`
}

// ScanResult 扫描结果汇总
type ScanResult struct {
	Files        []*RecoveredFile `json:"files"`
	Duration     float64          `json:"duration"` // 秒
	TotalScanned int64            `json:"totalScanned"`
	Stats        map[string]int   `json:"stats"` // category -> count
}

// FormatSize 将字节数转为人类可读的字符串
func FormatSize(bytes int64) string {
	if bytes < 0 {
		return "未知"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div),
		[]string{"KB", "MB", "GB", "TB", "PB"}[exp])
}

// FormatDuration 将秒数转为可读时长
func FormatDuration(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%.1f 秒", seconds)
	} else if seconds < 3600 {
		m := int(seconds) / 60
		s := int(seconds) % 60
		return fmt.Sprintf("%d 分 %d 秒", m, s)
	}
	h := int(seconds) / 3600
	m := (int(seconds) % 3600) / 60
	return fmt.Sprintf("%d 小时 %d 分", h, m)
}
