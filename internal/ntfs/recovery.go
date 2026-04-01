package ntfs

import (
	"path/filepath"
	"strings"

	"data-recovery/internal/types"
)

// ========== 扩展名到文件分类的映射表 ==========

// extensionCategoryMap 维护文件扩展名到分类的映射
// 键为小写扩展名（不含点号），值为文件分类
var extensionCategoryMap = map[string]types.FileCategory{
	// 图片格式
	"jpg":  types.CategoryImage,
	"jpeg": types.CategoryImage,
	"png":  types.CategoryImage,
	"gif":  types.CategoryImage,
	"bmp":  types.CategoryImage,
	"tiff": types.CategoryImage,
	"tif":  types.CategoryImage,
	"webp": types.CategoryImage,
	"psd":  types.CategoryImage,
	"svg":  types.CategoryImage,
	"ico":  types.CategoryImage,
	"raw":  types.CategoryImage,
	"cr2":  types.CategoryImage,
	"nef":  types.CategoryImage,
	"heic": types.CategoryImage,
	"heif": types.CategoryImage,

	// 文档格式
	"pdf":  types.CategoryDocument,
	"doc":  types.CategoryDocument,
	"docx": types.CategoryDocument,
	"xls":  types.CategoryDocument,
	"xlsx": types.CategoryDocument,
	"ppt":  types.CategoryDocument,
	"pptx": types.CategoryDocument,
	"rtf":  types.CategoryDocument,
	"txt":  types.CategoryDocument,
	"odt":  types.CategoryDocument,
	"ods":  types.CategoryDocument,
	"odp":  types.CategoryDocument,
	"csv":  types.CategoryDocument,
	"md":   types.CategoryDocument,
	"html": types.CategoryDocument,
	"htm":  types.CategoryDocument,
	"xml":  types.CategoryDocument,
	"json": types.CategoryDocument,
	"yaml": types.CategoryDocument,
	"yml":  types.CategoryDocument,
	"log":  types.CategoryDocument,
	"tex":  types.CategoryDocument,
	"epub": types.CategoryDocument,

	// 视频格式
	"mp4":  types.CategoryVideo,
	"avi":  types.CategoryVideo,
	"mkv":  types.CategoryVideo,
	"mov":  types.CategoryVideo,
	"flv":  types.CategoryVideo,
	"wmv":  types.CategoryVideo,
	"webm": types.CategoryVideo,
	"m4v":  types.CategoryVideo,
	"mpg":  types.CategoryVideo,
	"mpeg": types.CategoryVideo,
	"3gp":  types.CategoryVideo,
	"ts":   types.CategoryVideo,
	"vob":  types.CategoryVideo,
	"rm":   types.CategoryVideo,
	"rmvb": types.CategoryVideo,

	// 音频格式
	"mp3":  types.CategoryAudio,
	"wav":  types.CategoryAudio,
	"flac": types.CategoryAudio,
	"ogg":  types.CategoryAudio,
	"aac":  types.CategoryAudio,
	"wma":  types.CategoryAudio,
	"m4a":  types.CategoryAudio,
	"ape":  types.CategoryAudio,
	"aiff": types.CategoryAudio,
	"alac": types.CategoryAudio,
	"opus": types.CategoryAudio,
	"mid":  types.CategoryAudio,
	"midi": types.CategoryAudio,

	// 压缩包格式
	"zip": types.CategoryArchive,
	"rar": types.CategoryArchive,
	"7z":  types.CategoryArchive,
	"gz":  types.CategoryArchive,
	"tar": types.CategoryArchive,
	"bz2": types.CategoryArchive,
	"xz":  types.CategoryArchive,
	"zst": types.CategoryArchive,
	"lz4": types.CategoryArchive,
	"cab": types.CategoryArchive,
	"iso": types.CategoryArchive,
	"dmg": types.CategoryArchive,

	// 数据库格式
	"sqlite":  types.CategoryDatabase,
	"sqlite3": types.CategoryDatabase,
	"db":      types.CategoryDatabase,
	"mdb":     types.CategoryDatabase,
	"accdb":   types.CategoryDatabase,
	"dbf":     types.CategoryDatabase,
	"sql":     types.CategoryDatabase,
}

// ========== 公开函数 ==========

// MFTEntryToRecoveredFile 将 MFTEntry 转换为统一的 RecoveredFile 结构
//
// 该函数负责:
//   - 从文件名提取扩展名
//   - 根据扩展名判断文件分类 (Category)
//   - 设置数据来源为 "ntfs"
//   - 根据数据完整性评估置信度 (Confidence)
//   - 保留原始路径和删除状态等元信息
func MFTEntryToRecoveredFile(entry *MFTEntry) *types.RecoveredFile {
	if entry == nil {
		return nil
	}

	// 从文件名提取扩展名（去掉点号，转小写）
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(entry.FileName), "."))

	// 根据扩展名判断文件分类
	category := ExtensionToCategory(ext)

	// 评估置信度
	// 有完整 DataRuns 且 FileSize > 0 → 高置信度 0.9
	// 有驻留数据 → 中高置信度 0.8
	// 其他情况 → 中等置信度 0.6
	confidence := 0.6
	if len(entry.DataRuns) > 0 && entry.FileSize > 0 {
		confidence = 0.9
	} else if entry.IsResident && len(entry.ResidentData) > 0 {
		confidence = 0.8
	}

	// 确定磁盘偏移（用于前端展示和定位）
	// 使用第一个 DataRun 的簇偏移作为文件在磁盘上的起始位置
	var diskOffset int64
	if len(entry.DataRuns) > 0 {
		diskOffset = entry.DataRuns[0].ClusterOffset
	}

	// 确定原始路径
	originalPath := entry.FullPath
	if originalPath == "" {
		originalPath = entry.FileName
	}

	// 生成唯一 ID: 使用 "ntfs-" 前缀 + MFT 条目号
	id := formatEntryID(entry.EntryNumber)

	return &types.RecoveredFile{
		ID:           id,
		Source:       "ntfs",
		FileName:     entry.FileName,
		Extension:    ext,
		Category:     category,
		Size:         entry.FileSize,
		SizeHuman:    types.FormatSize(entry.FileSize),
		Offset:       diskOffset,
		Confidence:   confidence,
		CreatedTime:  entry.CreatedTime,
		ModifiedTime: entry.ModifiedTime,
		IsDeleted:    entry.IsDeleted,
		OriginalPath: originalPath,
		IsValid:      true,
	}
}

// ExtensionToCategory 根据文件扩展名返回文件分类
//
// ext 参数应为小写、不含点号的扩展名（例如 "jpg" 而非 ".JPG"）
// 如果扩展名未在映射表中找到，返回 CategoryOther
func ExtensionToCategory(ext string) types.FileCategory {
	// 统一转小写处理
	ext = strings.ToLower(strings.TrimPrefix(ext, "."))

	if ext == "" {
		return types.CategoryOther
	}

	category, found := extensionCategoryMap[ext]
	if !found {
		return types.CategoryOther
	}
	return category
}

// EstimateRecoverability 评估文件的可恢复概率
//
// 综合多个因素给出 0.0 到 1.0 之间的评分:
//   - 有完整 DataRuns:       +0.4 (数据位置信息完整，恢复可能性最高)
//   - FileSize > 0:          +0.2 (知道文件大小，能准确截断)
//   - IsResident 且有数据:    +0.3 (驻留数据直接可读，非常可靠)
//   - 文件名有效:             +0.1 (能保留原始文件名)
//
// 注意: 即使评分较高，实际恢复仍可能失败（例如簇已被覆盖）
func EstimateRecoverability(entry *MFTEntry) float64 {
	if entry == nil {
		return 0.0
	}

	var score float64

	// 因素 1: 有完整 DataRuns（非驻留文件的核心信息）
	if len(entry.DataRuns) > 0 {
		score += 0.4
	}

	// 因素 2: 已知文件大小（能准确恢复，不会多读或少读）
	if entry.FileSize > 0 {
		score += 0.2
	}

	// 因素 3: 驻留数据（小文件直接存储在 MFT 条目内，恢复最可靠）
	if entry.IsResident && len(entry.ResidentData) > 0 {
		score += 0.3
	}

	// 因素 4: 有效文件名（能以原始名称恢复）
	if entry.FileName != "" {
		score += 0.1
	}

	// 限制在 [0.0, 1.0] 范围内
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	return score
}

// ========== 内部辅助函数 ==========

// formatEntryID 生成 NTFS MFT 条目的唯一标识符
//
// 格式: "ntfs-{entryNumber}"
// 例如: "ntfs-12345"
func formatEntryID(entryNumber int64) string {
	// 使用简单的字符串拼接避免引入额外依赖
	return "ntfs-" + int64ToString(entryNumber)
}

// int64ToString 将 int64 转换为十进制字符串
// 不使用 fmt.Sprintf 或 strconv 以保持最小依赖（虽然实际项目中推荐用 strconv）
func int64ToString(n int64) string {
	if n == 0 {
		return "0"
	}

	negative := false
	if n < 0 {
		negative = true
		n = -n
	}

	// 从低位到高位提取数字
	var digits [20]byte // int64 最多 19 位数字 + 可能的负号
	pos := len(digits)

	for n > 0 {
		pos--
		digits[pos] = byte('0' + n%10)
		n /= 10
	}

	if negative {
		pos--
		digits[pos] = '-'
	}

	return string(digits[pos:])
}
