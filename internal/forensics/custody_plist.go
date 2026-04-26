package forensics

// custody_plist.go：Custody manifest 的 binary plist 输出。
//
// 取证场景下 macOS 工具链（plutil / Apple Configurator / Magnet AXIOM /
// R-Studio Mac / X-Ways）原生吃 binary plist，比 JSON 更兼容。
// 本文件让 BuildAndWrite 同时输出 custody.json + custody.plist 两个 manifest，
// 内容等价 —— 第三方验证用 JSON 校 hash chain，工具链导入用 plist。

import (
	"fmt"
	"os"
	"path/filepath"

	"data-recovery/internal/ios"
)

// custodyToValue 把 Custody → ios.Value 树（保持 JSON 字段名一致，
// 让两份 manifest 字段语义对齐）
func custodyToValue(c Custody) *ios.Value {
	files := make([]*ios.Value, 0, len(c.OutputFiles))
	for _, f := range c.OutputFiles {
		files = append(files, &ios.Value{
			Kind: ios.KindDict,
			Dict: map[string]*ios.Value{
				"path":   {Kind: ios.KindString, String: f.Path},
				"size":   {Kind: ios.KindInt, Int: f.Size},
				"sha256": {Kind: ios.KindString, String: f.SHA256},
			},
		})
	}

	dict := map[string]*ios.Value{
		"toolName":       {Kind: ios.KindString, String: c.ToolName},
		"toolVersion":    {Kind: ios.KindString, String: c.ToolVersion},
		"operatorUser":   {Kind: ios.KindString, String: c.OperatorUser},
		"os":             {Kind: ios.KindString, String: c.OS},
		"arch":           {Kind: ios.KindString, String: c.Arch},
		"startedAt":      {Kind: ios.KindDate, Time: c.StartedAt},
		"completedAt":    {Kind: ios.KindDate, Time: c.CompletedAt},
		"sourceDevice":   {Kind: ios.KindString, String: c.SourceDevice},
		"manifestSHA256": {Kind: ios.KindString, String: c.ManifestSHA256},
		"outputFiles":    {Kind: ios.KindArray, Array: files},
	}
	if c.SourceSize > 0 {
		dict["sourceSize"] = &ios.Value{Kind: ios.KindInt, Int: c.SourceSize}
	}
	if c.SourceSHA256 != "" {
		dict["sourceSHA256"] = &ios.Value{Kind: ios.KindString, String: c.SourceSHA256}
	}
	return &ios.Value{Kind: ios.KindDict, Dict: dict}
}

// WriteCustodyPlist 把 Custody 编码成 binary plist 并落到 outputDir/custody.plist。
//
// 假设 c.ManifestSHA256 已经填好（来自 BuildAndWrite 流程）；
// plist 内容与 custody.json 字段语义一致 → 任一方 hash 比对都能验。
func WriteCustodyPlist(outputDir string, c Custody) (string, error) {
	if outputDir == "" {
		return "", fmt.Errorf("outputDir 为空")
	}
	root := custodyToValue(c)
	encoded, err := ios.EncodePlist(root)
	if err != nil {
		return "", fmt.Errorf("EncodePlist: %w", err)
	}
	dest := filepath.Join(outputDir, "custody.plist")
	if err := os.WriteFile(dest, encoded, 0o644); err != nil {
		return "", fmt.Errorf("写 custody.plist: %w", err)
	}
	return dest, nil
}
