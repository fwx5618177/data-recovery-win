package ios

// ============================================================================
// Manifest.db 读取：iOS 备份的"文件清单"SQLite 数据库
//
// Schema（Apple 从 iOS 10 起稳定至今）：
//   CREATE TABLE Files(
//     fileID       TEXT PRIMARY KEY,   -- SHA1(domain-relativePath) 的 hex
//     domain       TEXT,               -- "CameraRollDomain", "AppDomain-com.whatsapp" 等
//     relativePath TEXT,               -- 如 "Media/DCIM/100APPLE/IMG_0001.JPG"
//     flags        INTEGER,            -- 1=file, 2=dir, 4=symlink
//     file         BLOB                -- bplist，记录 size/mode/protectionClass/encryptionKey 等
//   );
//   CREATE TABLE Properties(key, value);  -- 元数据，我们不强依赖
//
// 读取策略：
//   modernc.org/sqlite 注册进 database/sql；用标准 SQL 查询。
//   对加密备份，Manifest.db **本身**也被加密 —— 需要先用 ManifestKey 解密整个
//   数据库文件，再喂给 SQLite。本文件只负责读"已解密或未加密"的 Manifest.db；
//   加密路径由 decrypt.go 在调 OpenManifestDB 前先解出临时明文 .db 文件。
// ============================================================================

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	// 注册 SQLite 驱动
	_ "modernc.org/sqlite"
)

// FileRecord 一条 Manifest.db 的 Files 行
type FileRecord struct {
	FileID       string // sha1(domain-relativePath) hex
	Domain       string // "CameraRollDomain" 等
	RelativePath string // 域内相对路径
	Flags        int64  // 1/2/4
	FileBlob     []byte // bplist 原始字节（按需再解）

	// 解完 bplist 之后回填的字段（Enumerate 内部会做一次）
	Size            int64
	Mode            uint32
	UID             uint32
	GID             uint32
	MTime           int64
	BTime           int64
	ProtectionClass uint32 // 加密备份才有；非 0 表示该文件被加密
	EncryptionKey   []byte // 原始 wrapped key blob（class_id(4B LE) + wrapped_key(40B)）
}

// IsFile 根据 flags 判断是否普通文件（非目录、非符号链接）
func (r FileRecord) IsFile() bool { return r.Flags == 1 }

// DomainDisplayPath 把 (domain, relativePath) 映射成一个"像本地路径"的字符串，
// 方便 UI 展示。不追求严格对齐 iOS 文件系统（那需要 sandbox 知识），
// 只追求"用户一眼看懂是啥"。
//
// 例：
//
//	CameraRollDomain + "Media/DCIM/100APPLE/IMG_0001.JPG"
//	  → "照片/DCIM/100APPLE/IMG_0001.JPG"
//	AppDomain-com.whatsapp + "Documents/ChatStorage.sqlite"
//	  → "应用/WhatsApp/Documents/ChatStorage.sqlite"
//	HomeDomain + "Library/Mail/Mailboxes/INBOX.mbox/123.emlx"
//	  → "Home/Library/Mail/Mailboxes/INBOX.mbox/123.emlx"
func DomainDisplayPath(domain, relativePath string) string {
	switch {
	case domain == "CameraRollDomain":
		return "照片/" + relativePath
	case domain == "MediaDomain":
		return "媒体/" + relativePath
	case domain == "HomeDomain":
		return "Home/" + relativePath
	case domain == "RootDomain":
		return "System/" + relativePath
	case domain == "WirelessDomain":
		return "无线配置/" + relativePath
	case domain == "SystemPreferencesDomain":
		return "系统设置/" + relativePath
	case domain == "DatabaseDomain":
		return "数据库/" + relativePath
	case domain == "KeychainDomain":
		return "钥匙串/" + relativePath
	case domain == "HealthDomain":
		return "健康/" + relativePath
	case strings.HasPrefix(domain, "AppDomain-"):
		bundleID := strings.TrimPrefix(domain, "AppDomain-")
		return "应用/" + bundleID + "/" + relativePath
	case strings.HasPrefix(domain, "AppDomainGroup-"):
		groupID := strings.TrimPrefix(domain, "AppDomainGroup-")
		return "应用组/" + groupID + "/" + relativePath
	case strings.HasPrefix(domain, "SysContainerDomain-"):
		return "系统容器/" + strings.TrimPrefix(domain, "SysContainerDomain-") + "/" + relativePath
	case strings.HasPrefix(domain, "SysSharedContainerDomain-"):
		return "共享容器/" + strings.TrimPrefix(domain, "SysSharedContainerDomain-") + "/" + relativePath
	default:
		return domain + "/" + relativePath
	}
}

// OpenManifestDB 打开一个（已经明文的）Manifest.db 做只读查询。
func OpenManifestDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1&_pragma=journal_mode(OFF)")
	if err != nil {
		return nil, fmt.Errorf("打开 Manifest.db 失败: %w", err)
	}
	// 立刻 Ping 确认是 SQLite 且 schema 合法
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("manifest.db 不可读: %w", err)
	}
	return db, nil
}

// EnumerateFiles 遍历 Manifest.db 的 Files 表，把每一行转为 FileRecord。
// 对每条记录尝试解析 file BLOB（bplist）从中读出 size/mtime/protection class。
// 解析失败的记录仍然返回（Size=0），上层决定要不要跳过。
//
// onRecord 回调形式让调用方可以边扫边推到前端（备份最多几万文件，数据库
// 能一次性读完但仍采用流式 API 统一风格）。
func EnumerateFiles(ctx context.Context, db *sql.DB, onRecord func(FileRecord)) error {
	rows, err := db.QueryContext(ctx, `SELECT fileID, domain, relativePath, flags, file FROM Files`)
	if err != nil {
		return fmt.Errorf("查 Files 表失败: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var r FileRecord
		var fileID, domain, relPath sql.NullString
		var flags sql.NullInt64
		var blob []byte
		if err := rows.Scan(&fileID, &domain, &relPath, &flags, &blob); err != nil {
			continue
		}
		r.FileID = fileID.String
		r.Domain = domain.String
		r.RelativePath = relPath.String
		r.Flags = flags.Int64
		r.FileBlob = blob

		// file blob 是一个 NSKeyedArchiver 的 bplist —— 典型 "$objects" 数组 +
		// 根引用 "$top"。我们不需要完整 NSKeyedArchiver 反序列化，只要找到
		// 里面的 Size/Mode/ProtectionClass/EncryptionKey 这几个值。
		if len(blob) > 0 {
			extractFileAttrs(blob, &r)
		}

		onRecord(r)
	}
	return rows.Err()
}

// extractFileAttrs 从一条 Files.file BLOB 里提取关键字段。
//
// file BLOB 的内容是一棵 NSKeyedArchiver 的 bplist：
//
//	$archiver = NSKeyedArchiver
//	$version  = 100000
//	$objects  = [
//	  "$null",                                                // idx=0
//	  { NS.keys: [...], NS.objects: [...], $class: {CF$UID->n} }, // idx=1 = 根 dict
//	  ...UID→引用...
//	]
//	$top      = { root: UID(1) }
//
// 我们并不做完整反序列化。策略：扫 $objects 数组里每个 dict，遇到 "Size" 这种
// 键就记下对应 NS.objects[i]；最后按 NS.keys 顺序凑出属性表。
// 这是"够用"的近似；极少数边角场景可能拿不到 Size，那种 record 会 Size=0。
func extractFileAttrs(blob []byte, r *FileRecord) {
	root, err := ParsePlist(blob)
	if err != nil || root == nil || root.Kind != KindDict {
		return
	}
	objects := root.Dict["$objects"]
	if objects == nil || objects.Kind != KindArray {
		return
	}
	objs := objects.Array

	// 资深用户 note：NSKeyedArchiver 里 dict 的 "NS.keys" 和 "NS.objects" 各是
	// 一个 UID 数组，对应到 $objects[n] 的 string 或 data。我们按 UID 解引用。
	deref := func(v *Value) *Value {
		if v == nil {
			return nil
		}
		if v.Kind == KindUID && int(v.UID) < len(objs) {
			return objs[int(v.UID)]
		}
		return v
	}

	// 找到第一个"有 NS.keys + NS.objects"的 dict —— 这是文件属性 record
	for _, obj := range objs {
		if obj == nil || obj.Kind != KindDict {
			continue
		}
		keysRef := obj.Dict["NS.keys"]
		valsRef := obj.Dict["NS.objects"]
		if keysRef == nil || valsRef == nil {
			continue
		}
		if keysRef.Kind != KindArray || valsRef.Kind != KindArray {
			continue
		}
		if len(keysRef.Array) != len(valsRef.Array) {
			continue
		}
		for i, kref := range keysRef.Array {
			k := deref(kref)
			v := deref(valsRef.Array[i])
			if k == nil || v == nil || k.Kind != KindString {
				continue
			}
			switch k.String {
			case "Size":
				if v.Kind == KindInt {
					r.Size = v.Int
				}
			case "Mode":
				if v.Kind == KindInt {
					r.Mode = uint32(v.Int)
				}
			case "UserID":
				if v.Kind == KindInt {
					r.UID = uint32(v.Int)
				}
			case "GroupID":
				if v.Kind == KindInt {
					r.GID = uint32(v.Int)
				}
			case "LastModified":
				if v.Kind == KindInt {
					r.MTime = v.Int
				}
			case "Birth":
				if v.Kind == KindInt {
					r.BTime = v.Int
				}
			case "ProtectionClass":
				if v.Kind == KindInt {
					r.ProtectionClass = uint32(v.Int)
				}
			case "EncryptionKey":
				if v.Kind == KindData {
					r.EncryptionKey = v.Data
				}
			}
		}
		// 第一个"文件 record dict"拿到就够了
		return
	}
}

// BackupFilePath 根据 FileID 和备份根目录返回实际二进制文件的路径。
// iOS 10+ 开始：按 FileID 前 2 个 hex 分桶。
func BackupFilePath(backupRoot, fileID string) string {
	if len(fileID) < 2 {
		return ""
	}
	return strings.Join([]string{backupRoot, fileID[:2], fileID}, "/")
}
