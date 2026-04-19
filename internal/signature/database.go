package signature

import (
	hexlib "encoding/hex"
	"sort"

	"data-recovery/internal/types"
)

// 大小常量，用于定义文件签名的最大允许大小
const (
	MB int64 = 1024 * 1024
	GB int64 = 1024 * 1024 * 1024
)

// hex 辅助函数：将十六进制字符串解码为字节切片
// 简化魔术字节的定义，避免手写大量 []byte{0x..., 0x...}
func hex(s string) []byte {
	b, _ := hexlib.DecodeString(s)
	return b
}

// HeaderEntry 表示一个 (header 模式, 签名) 对，供 Aho-Corasick 匹配器使用
type HeaderEntry struct {
	Pattern   []byte               // 魔术字节模式
	Signature *types.FileSignature // 对应的文件签名
}

// SignatureDB 文件签名数据库
// 包含所有常见文件类型的魔术字节签名，支持按扩展名和分类快速查找
type SignatureDB struct {
	signatures []*types.FileSignature                        // 所有签名的有序列表
	byExt      map[string]*types.FileSignature               // 按扩展名索引
	byCat      map[types.FileCategory][]*types.FileSignature // 按分类索引
}

// NewSignatureDB 创建并初始化包含所有内置签名的数据库
// 数据库包含 27 种常见文件格式的签名，涵盖图片、文档、视频、音频、压缩包、数据库和可执行文件
func NewSignatureDB() *SignatureDB {
	db := &SignatureDB{
		byExt: make(map[string]*types.FileSignature),
		byCat: make(map[types.FileCategory][]*types.FileSignature),
	}
	db.initSignatures()
	return db
}

// add 向数据库中添加一个签名，同时更新扩展名索引和分类索引
func (db *SignatureDB) add(sig *types.FileSignature) {
	db.signatures = append(db.signatures, sig)
	db.byExt[sig.Extension] = sig
	db.byCat[sig.Category] = append(db.byCat[sig.Category], sig)
}

// All 返回所有已注册的文件签名
func (db *SignatureDB) All() []*types.FileSignature {
	return db.signatures
}

// ByExtension 根据扩展名查找对应的文件签名
// 如果找不到对应签名，返回 nil
func (db *SignatureDB) ByExtension(ext string) *types.FileSignature {
	return db.byExt[ext]
}

// ByCategory 根据文件分类查找该分类下的所有签名
// 如果该分类没有签名，返回 nil
func (db *SignatureDB) ByCategory(cat types.FileCategory) []*types.FileSignature {
	return db.byCat[cat]
}

// Categories 返回所有已注册的文件分类，按字母序排列
func (db *SignatureDB) Categories() []types.FileCategory {
	cats := make([]types.FileCategory, 0, len(db.byCat))
	for cat := range db.byCat {
		cats = append(cats, cat)
	}
	sort.Slice(cats, func(i, j int) bool {
		return cats[i] < cats[j]
	})
	return cats
}

// MaxHeaderLen 返回所有签名中最长 header 的字节长度
// 用于确定扫描时每次读取的最小缓冲区大小
func (db *SignatureDB) MaxHeaderLen() int {
	maxLen := 0
	for _, sig := range db.signatures {
		for _, h := range sig.Headers {
			if len(h) > maxLen {
				maxLen = len(h)
			}
		}
	}
	return maxLen
}

// AllHeaders 返回所有 (header_bytes, signature) 对，供 Aho-Corasick 匹配器使用
// 一个签名可能有多个 header 变体（如 JPEG 有 5 种），每个变体都会生成一个独立的 HeaderEntry
func (db *SignatureDB) AllHeaders() []HeaderEntry {
	var entries []HeaderEntry
	for _, sig := range db.signatures {
		for _, h := range sig.Headers {
			entries = append(entries, HeaderEntry{
				Pattern:   h,
				Signature: sig,
			})
		}
	}
	return entries
}

// initSignatures 初始化所有内置文件签名
// 签名数据来源于各文件格式的官方规范，魔术字节均经过验证
//
// 设计策略：
//   - RIFF 容器（AVI/WAV/WebP）共用 4 字节 header "RIFF"，carver 通过偏移 8-12 的子类型区分
//   - OLE2 容器（DOC/XLS/PPT）共用 8 字节 header，carver 通过内部结构区分
//   - ZIP 容器（DOCX/XLSX/PPTX/JAR 等）共用 4 字节 header "PK"，carver 通过内部文件名区分
//   - MP4/MOV 共用 ftyp atom 签名，carver 通过 brand 字段区分
func (db *SignatureDB) initSignatures() {
	// ==================== 图片类型 ====================

	// JPEG - 最常见的有损压缩图片格式
	// 5 种变体分别对应不同的 APP 标记段：
	//   FFE0 = JFIF, FFE1 = EXIF, FFE8 = SPIFF, FFDB = 量化表, FFEE = Adobe
	db.add(&types.FileSignature{
		Extension:   "jpg",
		Description: "JPEG 图片",
		Category:    types.CategoryImage,
		Headers: [][]byte{
			hex("ffd8ffe0"), // JFIF 格式
			hex("ffd8ffe1"), // EXIF 格式（数码相机常用）
			hex("ffd8ffe8"), // SPIFF 格式
			hex("ffd8ffdb"), // 直接以量化表开始
			hex("ffd8ffee"), // Adobe JPEG
		},
		Footers: [][]byte{
			hex("ffd9"), // EOI (End of Image) 标记
		},
		MaxSize: 50 * MB,
	})

	// PNG - 无损压缩图片格式，8 字节固定 header
	db.add(&types.FileSignature{
		Extension:   "png",
		Description: "PNG 图片",
		Category:    types.CategoryImage,
		Headers: [][]byte{
			hex("89504e470d0a1a0a"), // \x89PNG\r\n\x1a\n
		},
		Footers: [][]byte{
			hex("49454e44ae426082"), // IEND chunk + CRC
		},
		MaxSize: 50 * MB,
	})

	// GIF - 动图格式，两个版本：GIF87a 和 GIF89a
	db.add(&types.FileSignature{
		Extension:   "gif",
		Description: "GIF 动图",
		Category:    types.CategoryImage,
		Headers: [][]byte{
			hex("474946383761"), // GIF87a
			hex("474946383961"), // GIF89a（支持透明和动画）
		},
		Footers: [][]byte{
			hex("003b"), // GIF Trailer: 块终止符 + 文件终止符
		},
		MaxSize: 30 * MB,
	})

	// BMP - Windows 位图格式，以 "BM" 开头
	db.add(&types.FileSignature{
		Extension:   "bmp",
		Description: "BMP 位图",
		Category:    types.CategoryImage,
		Headers: [][]byte{
			hex("424d"), // "BM"
		},
		MaxSize: 50 * MB,
	})

	// TIFF - 标签图片文件格式，两种字节序
	db.add(&types.FileSignature{
		Extension:   "tiff",
		Description: "TIFF 图片",
		Category:    types.CategoryImage,
		Headers: [][]byte{
			hex("49492a00"), // "II*\0" Little-endian (Intel 字节序)
			hex("4d4d002a"), // "MM\0*" Big-endian (Motorola 字节序)
		},
		MaxSize: 200 * MB,
	})

	// RIFF 容器格式 - 涵盖 AVI 视频、WAV 音频、WebP 图片
	// 只存前 4 字节 "RIFF"，因为偏移 4-7 是文件大小（可变），偏移 8-11 才是子类型标识
	// carver 在发现 RIFF header 后，需检查偏移 8 处的 4 字节来确定实际格式：
	//   "AVI " = AVI 视频, "WAVE" = WAV 音频, "WEBP" = WebP 图片
	db.add(&types.FileSignature{
		Extension:   "riff",
		Description: "RIFF 容器 (AVI/WAV/WebP)",
		Category:    types.CategoryOther,
		Headers: [][]byte{
			hex("52494646"), // "RIFF"
		},
		MaxSize: 4 * GB,
	})

	// ICO - Windows 图标格式
	db.add(&types.FileSignature{
		Extension:   "ico",
		Description: "ICO 图标",
		Category:    types.CategoryImage,
		Headers: [][]byte{
			hex("00000100"), // 保留字段(0) + 类型(1=图标)
		},
		MaxSize: 5 * MB,
	})

	// PSD - Adobe Photoshop 文档，以 "8BPS" 开头
	db.add(&types.FileSignature{
		Extension:   "psd",
		Description: "Photoshop PSD",
		Category:    types.CategoryImage,
		Headers: [][]byte{
			hex("38425053"), // "8BPS"
		},
		MaxSize: 500 * MB,
	})

	// SVG - 可缩放矢量图形，本质是 XML 文本
	// 匹配 "<svg" 标签起始
	db.add(&types.FileSignature{
		Extension:   "svg",
		Description: "SVG 矢量图",
		Category:    types.CategoryImage,
		Headers: [][]byte{
			hex("3c737667"), // "<svg"
		},
		MaxSize: 10 * MB,
	})

	// ==================== 文档类型 ====================

	// PDF - 可移植文档格式，以 "%PDF" 开头，以 "%%EOF" 结尾
	db.add(&types.FileSignature{
		Extension:   "pdf",
		Description: "PDF 文档",
		Category:    types.CategoryDocument,
		Headers: [][]byte{
			hex("25504446"), // "%PDF"
		},
		Footers: [][]byte{
			hex("2525454f46"), // "%%EOF"
		},
		MaxSize: 500 * MB,
	})

	// OLE2 复合文档容器 - 涵盖 DOC、XLS、PPT 等 Microsoft Office 旧格式
	// 所有 OLE2 文件共享相同的 8 字节魔术数字 (DOCFILE 签名)
	// carver 需要解析 OLE2 内部目录流来区分具体是 Word/Excel/PowerPoint
	db.add(&types.FileSignature{
		Extension:   "ole2",
		Description: "OLE2 容器 (DOC/XLS/PPT)",
		Category:    types.CategoryDocument,
		Headers: [][]byte{
			hex("d0cf11e0a1b11ae1"), // OLE2 复合文档签名
		},
		MaxSize: 200 * MB,
	})

	// RTF - 富文本格式，以 "{\rtf" 开头，以 "}" 结尾
	db.add(&types.FileSignature{
		Extension:   "rtf",
		Description: "RTF 富文本",
		Category:    types.CategoryDocument,
		Headers: [][]byte{
			hex("7b5c727466"), // "{\rtf"
		},
		Footers: [][]byte{
			hex("7d"), // "}"
		},
		MaxSize: 100 * MB,
	})

	// ==================== 视频类型 ====================

	// MP4/MOV - MPEG-4 容器格式，基于 ISO Base Media File Format
	// 文件以 ftyp atom 开头：前 4 字节是 atom 大小，后 4 字节是 "ftyp"
	// 不同的 ftyp atom 大小取决于包含的 brand 数量
	// carver 可通过 ftyp 后的 brand 字段区分 MP4 和 MOV：
	//   "isom"/"mp41"/"mp42" = MP4, "qt  " = MOV, "M4A " = M4A
	db.add(&types.FileSignature{
		Extension:   "mp4",
		Description: "MP4/MOV 视频",
		Category:    types.CategoryVideo,
		Headers: [][]byte{
			hex("0000001466747970"), // 20 字节 ftyp atom
			hex("0000001866747970"), // 24 字节 ftyp atom（最常见）
			hex("0000001c66747970"), // 28 字节 ftyp atom
			hex("0000002066747970"), // 32 字节 ftyp atom
		},
		MaxSize: 4 * GB,
	})

	// MKV - Matroska 视频容器，基于 EBML (Extensible Binary Meta Language)
	db.add(&types.FileSignature{
		Extension:   "mkv",
		Description: "MKV 视频",
		Category:    types.CategoryVideo,
		Headers: [][]byte{
			hex("1a45dfa3"), // EBML header 标识
		},
		MaxSize: 4 * GB,
	})

	// FLV - Flash 视频格式，以 "FLV\x01" 开头
	db.add(&types.FileSignature{
		Extension:   "flv",
		Description: "FLV 视频",
		Category:    types.CategoryVideo,
		Headers: [][]byte{
			hex("464c5601"), // "FLV" + version 1
		},
		MaxSize: 4 * GB,
	})

	// WMV/ASF - Windows Media Video，基于 ASF (Advanced Systems Format) 容器
	// WMA 音频也使用相同的 ASF 容器格式，carver 需进一步区分
	db.add(&types.FileSignature{
		Extension:   "wmv",
		Description: "WMV/ASF 视频",
		Category:    types.CategoryVideo,
		Headers: [][]byte{
			hex("3026b2758e66cf11"), // ASF Header Object GUID 前 8 字节
		},
		MaxSize: 4 * GB,
	})

	// ==================== 音频类型 ====================

	// MP3 - 最流行的有损压缩音频格式
	// 帧同步字标识（高 11 位全为 1）+ MPEG 版本 + Layer 信息：
	//   FFFB = MPEG1/Layer3, FFF3 = MPEG2/Layer3, FFF2 = MPEG2.5/Layer3
	// 或以 ID3v2 标签开头（"ID3"）
	db.add(&types.FileSignature{
		Extension:   "mp3",
		Description: "MP3 音频",
		Category:    types.CategoryAudio,
		Headers: [][]byte{
			hex("fffb"),   // MPEG1 Audio Layer 3, 无 CRC
			hex("fff3"),   // MPEG2 Audio Layer 3, 无 CRC
			hex("fff2"),   // MPEG2.5 Audio Layer 3, 无 CRC
			hex("494433"), // "ID3" - ID3v2 标签头
		},
		MaxSize: 100 * MB,
	})

	// FLAC - 自由无损音频编码，以 "fLaC" 开头
	db.add(&types.FileSignature{
		Extension:   "flac",
		Description: "FLAC 无损音频",
		Category:    types.CategoryAudio,
		Headers: [][]byte{
			hex("664c6143"), // "fLaC" (大小写敏感)
		},
		MaxSize: 500 * MB,
	})

	// OGG - Ogg 容器格式，以 "OggS" 开头
	// 可包含 Vorbis 音频、Opus 音频或 Theora 视频
	db.add(&types.FileSignature{
		Extension:   "ogg",
		Description: "OGG 音频",
		Category:    types.CategoryAudio,
		Headers: [][]byte{
			hex("4f676753"), // "OggS" - Ogg 页面同步字
		},
		MaxSize: 200 * MB,
	})

	// AAC - 高级音频编码 (ADTS 封装格式)
	// ADTS 帧头前 12 位为同步字 (0xFFF)，第 13 位为 MPEG 版本
	db.add(&types.FileSignature{
		Extension:   "aac",
		Description: "AAC 音频",
		Category:    types.CategoryAudio,
		Headers: [][]byte{
			hex("fff1"), // ADTS, MPEG-4, protection absent
			hex("fff9"), // ADTS, MPEG-2, with protection
		},
		MaxSize: 100 * MB,
	})

	// ==================== 压缩包类型 ====================

	// ZIP - 最通用的压缩格式，也是 DOCX/XLSX/PPTX/JAR/ODT 等格式的基础容器
	// carver 发现 ZIP header 后，可通过检查内部文件路径来区分实际格式：
	//   含 "word/" = DOCX, 含 "xl/" = XLSX, 含 "ppt/" = PPTX
	db.add(&types.FileSignature{
		Extension:   "zip",
		Description: "ZIP 压缩包",
		Category:    types.CategoryArchive,
		Headers: [][]byte{
			hex("504b0304"), // "PK\x03\x04" - Local File Header 签名
		},
		Footers: [][]byte{
			hex("504b0506"), // "PK\x05\x06" - End of Central Directory 签名
		},
		MaxSize: 2 * GB,
	})

	// RAR - WinRAR 压缩格式，RAR4 和 RAR5 有不同的签名
	db.add(&types.FileSignature{
		Extension:   "rar",
		Description: "RAR 压缩包",
		Category:    types.CategoryArchive,
		Headers: [][]byte{
			hex("526172211a0700"),   // "Rar!\x1a\x07\x00" - RAR 4.x
			hex("526172211a070100"), // "Rar!\x1a\x07\x01\x00" - RAR 5.x
		},
		MaxSize: 2 * GB,
	})

	// 7z - 7-Zip 压缩格式，高压缩比
	db.add(&types.FileSignature{
		Extension:   "7z",
		Description: "7-Zip 压缩包",
		Category:    types.CategoryArchive,
		Headers: [][]byte{
			hex("377abcaf271c"), // 7z 签名: "7z\xBC\xAF\x27\x1C"
		},
		MaxSize: 2 * GB,
	})

	// GZIP - GNU 压缩格式，常用于 .tar.gz
	db.add(&types.FileSignature{
		Extension:   "gz",
		Description: "GZIP 压缩包",
		Category:    types.CategoryArchive,
		Headers: [][]byte{
			hex("1f8b"), // GZIP 魔术数字
		},
		MaxSize: 2 * GB,
	})

	// BZ2 - bzip2 压缩格式，常用于 .tar.bz2
	// header 以 "BZh" 开头，h 后的数字表示块大小 (1-9)
	db.add(&types.FileSignature{
		Extension:   "bz2",
		Description: "BZIP2 压缩包",
		Category:    types.CategoryArchive,
		Headers: [][]byte{
			hex("425a68"), // "BZh"
		},
		MaxSize: 1 * GB,
	})

	// ==================== 数据库类型 ====================

	// SQLite - 最广泛使用的嵌入式数据库
	// 文件以固定的 16 字节魔术字符串 "SQLite format 3\000" 开头
	db.add(&types.FileSignature{
		Extension:   "sqlite",
		Description: "SQLite 数据库",
		Category:    types.CategoryDatabase,
		Headers: [][]byte{
			hex("53514c69746520666f726d6174203300"), // "SQLite format 3\0" (16 字节)
		},
		MaxSize: 2 * GB,
	})

	// ==================== 可执行文件 ====================

	// EXE - Windows PE 可执行文件，以 "MZ" (Mark Zbikowski) 开头
	db.add(&types.FileSignature{
		Extension:   "exe",
		Description: "Windows 可执行文件",
		Category:    types.CategoryOther,
		Headers: [][]byte{
			hex("4d5a"), // "MZ" - DOS MZ 可执行文件头
		},
		MaxSize: 500 * MB,
	})

	// ELF - Linux/Unix 可执行与可链接格式
	db.add(&types.FileSignature{
		Extension:   "elf",
		Description: "Linux ELF 可执行文件",
		Category:    types.CategoryOther,
		Headers: [][]byte{
			hex("7f454c46"), // "\x7fELF"
		},
		MaxSize: 500 * MB,
	})

	// ==================== 扩展：只加能给出可靠文件大小的签名 ====================
	//
	// 本项目的一条硬约束：determineFileSize 返回 0 的签名会被直接丢弃
	// （避免凭空伪造文件大小输出垃圾文件）。所以新增签名必须满足以下之一：
	//   1. 有专用 detect*Size 函数解析格式结构；或
	//   2. 有足够特异的 footer 做 searchFooter 兜底
	// 只有 magic 没有大小判定的签名加了等于没加（AC 命中了但 collector 会丢）。
	//
	// PhotoRec 的 480+ 格式里有相当比例是"只留 magic + MaxSize 猜一刀"的估算方式，
	// 本项目目前偏保守，只引入能走结构解析的格式。后续要扩量的话：
	//   - 写专用 detect 函数（如 DjVu 的 FORM size、MOBI 的 PalmDB record0）
	//   - 或把策略改成 PhotoRec 风格的"猜最大 N MB 然后交给用户验证"

	// DjVu - 扫描书籍常用格式；IFF 容器有 FORM 大小字段，可解析
	db.add(&types.FileSignature{
		Extension:   "djvu",
		Description: "DjVu 扫描文档",
		Category:    types.CategoryDocument,
		Headers: [][]byte{
			hex("41542654464f524d"), // "AT&TFORM"
		},
		MaxSize: 500 * MB,
	})

	// MIDI - 轻量音频；MThd + 后续 MTrk chunk 链有明确长度，可解析
	db.add(&types.FileSignature{
		Extension:   "mid",
		Description: "MIDI 音乐",
		Category:    types.CategoryAudio,
		Headers: [][]byte{
			hex("4d546864"), // "MThd"
		},
		MaxSize: 10 * MB,
	})

	// XZ - 有明确尾部 "YZ" footer；长度短但有更前面的 footer magic block 可校验
	db.add(&types.FileSignature{
		Extension:   "xz",
		Description: "XZ 压缩包",
		Category:    types.CategoryArchive,
		Headers: [][]byte{
			hex("fd377a585a00"), // "\xFD7zXZ\x00"
		},
		Footers: [][]byte{
			// Stream Footer magic：完整为 12 字节，但末尾 "YZ" + "7zXZ backward" 相对可靠
			hex("595a"),
		},
		MaxSize: 4 * GB,
	})
}
