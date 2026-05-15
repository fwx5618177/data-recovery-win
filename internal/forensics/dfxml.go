package forensics

import (
	"encoding/xml"
	"fmt"
	"io"
	"runtime"
	"time"

	"data-recovery/internal/types"
)

// DFXML (Digital Forensics XML) — 取证报告业界标准。
// http://forensicswiki.org/wiki/Category:DFXML
//
// 我们输出 DFXML 1.0 子集，符合 NIST AFF/Sleuthkit / Autopsy / fiwalk 兼容范围：
//
//   <dfxml xmlns="..." xmlns:dc="..." version="1.0">
//     <metadata>
//       <dc:type>Disk Image Recovery</dc:type>
//       <dc:creator>data-recovery vX</dc:creator>
//       <dc:date>RFC3339 timestamp</dc:date>
//     </metadata>
//     <creator>
//       <program>data-recovery</program>
//       <version>vX.Y.Z</version>
//       <build_environment><os>darwin/arm64</os></build_environment>
//     </creator>
//     <source>
//       <image_filename>...</image_filename>
//     </source>
//     <fileobject>
//       <filename>...</filename>
//       <filesize>...</filesize>
//       <unalloc>1</unalloc>          ← 已删除 / 未分配
//       <byte_runs>
//         <byte_run img_offset="..." len="..."/>
//       </byte_runs>
//       <mtime>...</mtime>
//       <ctime>...</ctime>
//       <hashdigest type="sha256">...</hashdigest>
//     </fileobject>
//   </dfxml>
//
// 这个结构能被 Sleuthkit `fiwalk -X` 直接解析，也兼容 Autopsy 的 DFXML 模块导入。

// DFXML 命名空间常量
const (
	dfxmlNamespace = "http://www.forensicswiki.org/wiki/Category:DFXML"
	dcNamespace    = "http://purl.org/dc/elements/1.1/"
)

// SourceInfo 描述 DFXML <source> 区块（数据来源）。
// 取证审计要求记录被恢复数据的物理来源。
type SourceInfo struct {
	ImageFilename string // "/dev/sda" 或 "/path/to/disk.img"
	ImageSize     int64  // 字节
	SectorSize    int    // 默认 512
}

type dfxmlMetadata struct {
	XMLName xml.Name `xml:"metadata"`
	// Dublin Core 元数据：取证报告的最低描述
	DCType    string `xml:"dc:type"`
	DCCreator string `xml:"dc:creator"`
	DCDate    string `xml:"dc:date"`
}

type dfxmlCreator struct {
	XMLName  xml.Name `xml:"creator"`
	Program  string   `xml:"program"`
	Version  string   `xml:"version"`
	BuildEnv struct {
		OS string `xml:"os"`
	} `xml:"build_environment"`
}

type dfxmlSource struct {
	XMLName       xml.Name `xml:"source"`
	ImageFilename string   `xml:"image_filename,omitempty"`
	ImageSize     int64    `xml:"image_size,omitempty"`
	SectorSize    int      `xml:"sectorsize,omitempty"`
}

type dfxmlByteRun struct {
	XMLName   xml.Name `xml:"byte_run"`
	ImgOffset int64    `xml:"img_offset,attr"`
	Len       int64    `xml:"len,attr"`
}

type dfxmlByteRuns struct {
	XMLName  xml.Name       `xml:"byte_runs"`
	ByteRuns []dfxmlByteRun `xml:"byte_run"`
}

type dfxmlFileObject struct {
	XMLName   xml.Name       `xml:"fileobject"`
	Filename  string         `xml:"filename"`
	Filesize  int64          `xml:"filesize"`
	IsDeleted int            `xml:"unalloc,omitempty"` // 1 = 已删除/未分配；0 = 已分配（活动）
	Source    string         `xml:"_source,omitempty"`
	MTime     string         `xml:"mtime,omitempty"`
	CTime     string         `xml:"ctime,omitempty"`
	ByteRuns  *dfxmlByteRuns `xml:"byte_runs,omitempty"`
	Hashes    []dfxmlHash    `xml:"hashdigest"`
}

type dfxmlHash struct {
	XMLName xml.Name `xml:"hashdigest"`
	Type    string   `xml:"type,attr"`
	Value   string   `xml:",chardata"`
}

type dfxmlDoc struct {
	XMLName  xml.Name `xml:"dfxml"`
	XMLNS    string   `xml:"xmlns,attr"`
	XMLNSDC  string   `xml:"xmlns:dc,attr"`
	Version  string   `xml:"version,attr"`
	Metadata dfxmlMetadata
	Creator  dfxmlCreator
	Source   *dfxmlSource `xml:"source,omitempty"`
	Files    []dfxmlFileObject
}

// WriteDFXML 把 files 写成最小 DFXML 文档（无 source 信息）。
// 兼容旧调用方；新代码建议用 WriteDFXMLWithSource。
func WriteDFXML(w io.Writer, appName, appVersion string, files []*types.RecoveredFile) error {
	return WriteDFXMLWithSource(w, appName, appVersion, nil, files)
}

// WriteDFXMLWithSource 输出含 <source> 区块的完整 DFXML 文档。
// source 可以是 nil（兼容旧路径），但取证场景应当传 —— 否则下游工具（Autopsy）
// 不知道这些文件来自哪块盘。
func WriteDFXMLWithSource(w io.Writer, appName, appVersion string, source *SourceInfo, files []*types.RecoveredFile) error {
	doc := dfxmlDoc{
		XMLNS:   dfxmlNamespace,
		XMLNSDC: dcNamespace,
		Version: "1.0",
		Metadata: dfxmlMetadata{
			DCType:    "Disk Image File Recovery",
			DCCreator: fmt.Sprintf("%s %s", appName, appVersion),
			DCDate:    time.Now().UTC().Format(time.RFC3339),
		},
		Creator: dfxmlCreator{
			Program: appName,
			Version: appVersion,
		},
	}
	doc.Creator.BuildEnv.OS = runtime.GOOS + "/" + runtime.GOARCH

	if source != nil {
		ds := &dfxmlSource{
			ImageFilename: source.ImageFilename,
			ImageSize:     source.ImageSize,
			SectorSize:    source.SectorSize,
		}
		doc.Source = ds
	}

	for _, f := range files {
		if f == nil {
			continue
		}
		fo := dfxmlFileObject{
			Filename: f.OriginalPath,
			Filesize: f.Size,
			Source:   f.Source,
		}
		if f.IsDeleted {
			fo.IsDeleted = 1
		}
		if fo.Filename == "" {
			fo.Filename = f.FileName
		}
		if f.ModifiedTime != nil && !f.ModifiedTime.IsZero() {
			fo.MTime = f.ModifiedTime.UTC().Format(time.RFC3339)
		}
		if f.CreatedTime != nil && !f.CreatedTime.IsZero() {
			fo.CTime = f.CreatedTime.UTC().Format(time.RFC3339)
		}
		// byte_runs：取证报告里最关键的"数据从哪里来"指针
		if f.Offset > 0 && f.Size > 0 {
			fo.ByteRuns = &dfxmlByteRuns{
				ByteRuns: []dfxmlByteRun{
					{ImgOffset: f.Offset, Len: f.Size},
				},
			}
		}
		if f.SHA256 != "" {
			fo.Hashes = append(fo.Hashes, dfxmlHash{Type: "sha256", Value: f.SHA256})
		}
		doc.Files = append(doc.Files, fo)
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return fmt.Errorf("write xml header: %w", err)
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
