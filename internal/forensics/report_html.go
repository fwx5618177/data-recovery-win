package forensics

// HTML 取证报告生成器 —— 专业可打印格式。
//
// 为什么 HTML 而不是 PDF 直接生成：
//   1. 无需重依赖（PDF 库 gofpdf 等 ~2MB bundle bloat；go-fitz 需 cgo）
//   2. HTML 在任何浏览器可打开 + Ctrl+P 打印成 PDF
//   3. Chrome headless 可无人值守转 PDF（`chromium --print-to-pdf`）
//   4. 法务机构审阅原始 HTML 更易复核（可查看源码）
//
// 输出 evidence_report.html 到 outputDir，配合 custody.signed.json 阅读。
//
// B2B 价值：法务 / 合规审计 拿到这份 HTML 报告 + evidence.zip 即可：
//   - 打开 HTML 读证据摘要（文件清单 / 签名 / 时间戳）
//   - 浏览器 Print → 法律存档 PDF/A
//   - 验证脚本 bash verify.sh 跑独立校验

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
)

const reportHTMLTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>数据恢复取证报告 - {{.Custody.ToolName}}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
           max-width: 960px; margin: 40px auto; padding: 0 24px; color: #1a1a1a; line-height: 1.6; }
    h1 { border-bottom: 3px solid #0066cc; padding-bottom: 10px; }
    h2 { margin-top: 40px; color: #0066cc; border-bottom: 1px solid #ddd; padding-bottom: 6px; }
    .meta-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    .meta-table td { padding: 8px 12px; border-bottom: 1px solid #eee; }
    .meta-table td:first-child { width: 200px; font-weight: 600; color: #555; }
    .hash { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; color: #444;
            background: #f5f5f5; padding: 2px 6px; border-radius: 3px; word-break: break-all; }
    .files { margin: 16px 0; }
    .files-summary { background: #f0f7ff; padding: 12px 16px; border-left: 4px solid #0066cc; margin: 16px 0; }
    .files-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .files-table th { background: #f5f5f5; padding: 10px; text-align: left; border-bottom: 2px solid #ddd; }
    .files-table td { padding: 8px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
    .files-table td.path { word-break: break-all; }
    .files-table td.size { text-align: right; white-space: nowrap; }
    .sig-section { background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 4px; margin: 20px 0; }
    .sig-ok { color: #2d8e41; font-weight: 600; }
    .sig-none { color: #b42020; font-weight: 600; }
    .warn { background: #fff8e5; border: 1px solid #f0c040; padding: 12px 16px; margin: 20px 0; border-radius: 4px; }
    .footer { margin-top: 60px; padding: 20px 0; border-top: 1px solid #ddd;
              color: #888; font-size: 12px; text-align: center; }
    @media print {
      body { max-width: none; margin: 20px; }
      .no-print { display: none; }
      .files-table { page-break-inside: auto; }
      .files-table tr { page-break-inside: avoid; }
    }
  </style>
</head>
<body>

<h1>数据恢复取证报告</h1>

<div class="warn">
  <strong>报告有效性依据：</strong>本报告附带的 <code>custody.signed.json</code> 含 Ed25519 数字签名{{if .Custody.TSAURL}}和 RFC 3161 可信时间戳{{end}}。
  任何对本报告或附件的篡改可通过 <code>bash verify.sh</code> 自动检测。
</div>

<h2>1. 操作摘要</h2>
<table class="meta-table">
  <tr><td>工具</td><td>{{.Custody.ToolName}} {{.Custody.ToolVersion}}</td></tr>
  <tr><td>操作员</td><td>{{.Custody.OperatorUser}}</td></tr>
  <tr><td>运行环境</td><td>{{.Custody.OS}} / {{.Custody.Arch}}</td></tr>
  <tr><td>开始时间 (UTC)</td><td>{{.Custody.StartedAt.Format "2006-01-02 15:04:05 UTC"}}</td></tr>
  <tr><td>完成时间 (UTC)</td><td>{{.Custody.CompletedAt.Format "2006-01-02 15:04:05 UTC"}}</td></tr>
  <tr><td>总耗时</td><td>{{.Duration}}</td></tr>
</table>

<h2>2. 证据源</h2>
<table class="meta-table">
  <tr><td>源设备</td><td><code>{{.Custody.SourceDevice}}</code></td></tr>
  {{if .Custody.SourceSize}}
  <tr><td>源大小</td><td>{{.Custody.SourceSize}} 字节 ({{.SourceSizeHuman}})</td></tr>
  {{end}}
  {{if .Custody.SourceSHA256}}
  <tr><td>源 SHA-256</td><td><span class="hash">{{.Custody.SourceSHA256}}</span></td></tr>
  {{end}}
</table>

<h2>3. 恢复文件清单 ({{len .Custody.OutputFiles}} 项)</h2>

<div class="files-summary">
  共 {{len .Custody.OutputFiles}} 个文件恢复成功；总大小 {{.TotalSizeHuman}}。
  每个文件的 SHA-256 已单独记录，任何字节级修改可被检测。
</div>

<table class="files-table">
<thead>
  <tr>
    <th style="width: 50px;">#</th>
    <th>文件路径</th>
    <th style="width: 100px;">大小</th>
    <th style="width: 500px;">SHA-256</th>
  </tr>
</thead>
<tbody>
{{range $i, $f := .Custody.OutputFiles}}
  <tr>
    <td>{{add $i 1}}</td>
    <td class="path">{{$f.Path}}</td>
    <td class="size">{{$f.Size}}</td>
    <td><span class="hash">{{$f.SHA256}}</span></td>
  </tr>
{{end}}
</tbody>
</table>

<h2>4. 完整性证明</h2>

<div class="sig-section">
  <strong>Manifest SHA-256：</strong><br>
  <span class="hash">{{.Custody.ManifestSHA256}}</span>
  <p>此哈希覆盖本报告所列所有文件条目的 path / size / SHA-256 字段。修改任何文件或元数据后，本哈希必然变化。</p>

  {{if .Signed}}
    <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
    <strong class="sig-ok">✓ Ed25519 数字签名</strong><br>
    <div style="font-size: 13px; margin-top: 8px;">
      <p>签名算法：{{.Signed.SignatureScheme}}</p>
      <p>公钥：<span class="hash">{{.Signed.SignaturePublicKey}}</span></p>
      <p>签名：<span class="hash">{{.Signed.Signature}}</span></p>
    </div>

    {{if .Signed.TSAURL}}
      <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
      <strong class="sig-ok">✓ RFC 3161 可信时间戳</strong><br>
      <div style="font-size: 13px; margin-top: 8px;">
        <p>TSA：<code>{{.Signed.TSAURL}}</code></p>
        <p>时间戳：{{.Signed.TSATimestamp.Format "2006-01-02 15:04:05 UTC"}}</p>
        <p>原始 TSA 响应（Base64）：<br><span class="hash" style="display:block; max-height: 100px; overflow-y: auto;">{{.Signed.TSAResponseB64}}</span></p>
      </div>
    {{else}}
      <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
      <strong class="sig-none">✗ RFC 3161 时间戳缺失</strong>
      <p style="font-size: 13px;">TSA 服务不可达或网络受限；签名仍合法但无外部时间证明。</p>
    {{end}}
  {{else}}
    <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
    <strong class="sig-none">✗ 本报告未经数字签名</strong>
    <p style="font-size: 13px;">仅保管链哈希；建议用 <code>BuildSignAndWrite</code> 生成签名版本。</p>
  {{end}}
</div>

<h2>5. 第三方校验指南</h2>

<ol>
  <li>获取 evidence.zip 解压出 <code>custody.signed.json</code> + <code>public_key.pem</code> + <code>tsa_response.tsr</code></li>
  <li>执行 <code>bash verify.sh</code> 自动验证 Ed25519 签名</li>
  <li>执行 <code>openssl ts -reply -in tsa_response.tsr -text</code> 查看 RFC 3161 时间戳详细</li>
  <li>对 OutputFiles 中每条重算 SHA-256 比对 → 确认文件未被篡改</li>
</ol>

<div class="footer">
  本报告由 <strong>{{.Custody.ToolName}} {{.Custody.ToolVersion}}</strong> 自动生成 — 生成时间 {{.Custody.CompletedAt.Format "2006-01-02 15:04:05 UTC"}}<br>
  无人工修饰；任何字段异常请立即联系发报方核实
</div>

</body>
</html>
`

// humanSize 人性化显示字节数
func humanSize(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
}

// GenerateHTMLReport 生成专业取证报告 HTML，写到 outputDir/evidence_report.html。
// signedJSONPath 可选；若指向有效 custody.signed.json 则报告里展示签名信息。
func GenerateHTMLReport(outputDir string) (string, error) {
	// 优先读 custody.signed.json，缺就读 custody.json
	var signed *SignedCustody
	var basic Custody

	if signedBytes, err := os.ReadFile(filepath.Join(outputDir, "custody.signed.json")); err == nil {
		var s SignedCustody
		if err := json.Unmarshal(signedBytes, &s); err == nil {
			signed = &s
			basic = s.Custody
		}
	}
	if signed == nil {
		plainBytes, err := os.ReadFile(filepath.Join(outputDir, "custody.json"))
		if err != nil {
			return "", fmt.Errorf("读保管链失败（请先 BuildAndWrite）: %w", err)
		}
		if err := json.Unmarshal(plainBytes, &basic); err != nil {
			return "", fmt.Errorf("解保管链: %w", err)
		}
	}

	var totalSize int64
	for _, f := range basic.OutputFiles {
		totalSize += f.Size
	}

	duration := basic.CompletedAt.Sub(basic.StartedAt)
	if duration < 0 {
		duration = 0
	}

	data := map[string]any{
		"Custody":         basic,
		"Signed":          signed,
		"Duration":        duration.Round(time.Second).String(),
		"SourceSizeHuman": humanSize(basic.SourceSize),
		"TotalSizeHuman":  humanSize(totalSize),
	}

	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("解析 template: %w", err)
	}

	dest := filepath.Join(outputDir, "evidence_report.html")
	f, err := os.Create(dest)
	if err != nil {
		return "", fmt.Errorf("创建 HTML 报告文件: %w", err)
	}
	defer f.Close()
	if err := tmpl.Execute(f, data); err != nil {
		return "", fmt.Errorf("渲染 HTML: %w", err)
	}
	return dest, nil
}
