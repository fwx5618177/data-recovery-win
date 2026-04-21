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
// 我们输出最小可消费的 DFXML 子集：
//   <dfxml>
//     <metadata>...</metadata>
//     <fileobject>
//       <filename>...</filename>
//       <filesize>...</filesize>
//       <mtime>...</mtime>
//       <hashdigest type="sha256">...</hashdigest>
//     </fileobject>
//     ...
//   </dfxml>
//
// 完整 DFXML schema 含 byte_run / data_run / partition / volume 等几十个标签；
// 这里实现的是最小子集，能让 Sleuthkit / Autopsy 类工具识别为合法 DFXML。

type dfxmlMetadata struct {
	XMLName     xml.Name `xml:"metadata"`
	GeneratorVersion string `xml:"DC:creator>application>version,omitempty"`
	Generator   string   `xml:"DC:creator>application>name"`
	StartTime   string   `xml:"DC:date,omitempty"`
	OS          string   `xml:"build_environment>os,omitempty"`
}

type dfxmlFileObject struct {
	XMLName  xml.Name `xml:"fileobject"`
	Filename string   `xml:"filename"`
	Filesize int64    `xml:"filesize"`
	MTime    string   `xml:"mtime,omitempty"`
	CTime    string   `xml:"ctime,omitempty"`
	Source   string   `xml:"_source,omitempty"`
	IsDeleted bool    `xml:"unalloc,omitempty"`
	Hash     *dfxmlHash `xml:"hashdigest,omitempty"`
}

type dfxmlHash struct {
	XMLName xml.Name `xml:"hashdigest"`
	Type    string   `xml:"type,attr"`
	Value   string   `xml:",chardata"`
}

type dfxmlDoc struct {
	XMLName  xml.Name `xml:"dfxml"`
	Version  string   `xml:"version,attr"`
	Metadata dfxmlMetadata
	Files    []dfxmlFileObject
}

// WriteDFXML 把 files 写成 DFXML 文档到 w。
func WriteDFXML(w io.Writer, appName, appVersion string, files []*types.RecoveredFile) error {
	doc := dfxmlDoc{
		Version: "1.0",
		Metadata: dfxmlMetadata{
			Generator:        appName,
			GeneratorVersion: appVersion,
			StartTime:        time.Now().UTC().Format(time.RFC3339),
			OS:               runtime.GOOS + "/" + runtime.GOARCH,
		},
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		fo := dfxmlFileObject{
			Filename:  f.OriginalPath,
			Filesize:  f.Size,
			Source:    f.Source,
			IsDeleted: f.IsDeleted,
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
		if f.SHA256 != "" {
			fo.Hash = &dfxmlHash{Type: "sha256", Value: f.SHA256}
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
