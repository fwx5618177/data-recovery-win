package recovery

import (
	"strings"

	"data-recovery/internal/disk"
	"data-recovery/internal/exif"
	"data-recovery/internal/types"
)

// exifArchiveSubdir 给 carver / 已确定 offset 的 file 读 256KB 头，按 EXIF 拍摄日期返回
// "yyyy/MM"。失败 / 没 EXIF 返回 ""，调用方退化到默认目录。
//
// 仅对 jpeg/jpg/heic/heif 调；其它扩展直接返回空。
func exifArchiveSubdir(reader disk.DiskReader, file *types.RecoveredFile) string {
	if reader == nil || file == nil {
		return ""
	}
	ext := strings.ToLower(file.Extension)
	if ext != "jpg" && ext != "jpeg" && ext != "heic" && ext != "heif" {
		return ""
	}
	if file.Offset == 0 && file.Source != "carver" {
		// 非 carver 来源没有简单的盘内 offset，跳过自动归档（用户可手工分类）
		return ""
	}
	probe := int64(256 * 1024)
	if file.Size > 0 && file.Size < probe {
		probe = file.Size
	}
	buf := make([]byte, probe)
	n, _ := reader.ReadAt(buf, file.Offset)
	if n <= 0 {
		return ""
	}
	var t = exif.ExtractDateTimeOrZero(buf[:n], ext)
	if t.IsZero() {
		return "" // 让调用方用默认目录
	}
	return exif.ArchiveSubdir(t)
}
