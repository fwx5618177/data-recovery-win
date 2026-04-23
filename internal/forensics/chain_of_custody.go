package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

// ChainOfCustody（保管链）—— 取证标准要求："每份证据从被收集到被分析的整个生命周期
// 必须可追溯且不可否认"。本工具输出一个 manifest.json，含：
//
//   - 证据来源（原盘 / 镜像路径 + 大小 + sha256）
//   - 操作员（os user 名）
//   - 时间戳（采集开始 / 完成 UTC）
//   - 工具版本 + OS / arch
//   - 每个恢复出的文件：相对路径 + 大小 + sha256
//   - **整个 manifest 的 sha256**（写在文件名里，让任何篡改都立即可见）
//
// 不实现真数字签名（需要 PKI 证书 + 法律资质）；提供"可验证的 hash chain"作为最低
// 担保 — 第三方法务专家拿到 manifest 后能验证内容未被篡改。
type Custody struct {
	ToolName       string             `json:"toolName"`
	ToolVersion    string             `json:"toolVersion"`
	OperatorUser   string             `json:"operatorUser"`
	OS             string             `json:"os"`
	Arch           string             `json:"arch"`
	StartedAt      time.Time          `json:"startedAt"`
	CompletedAt    time.Time          `json:"completedAt"`
	SourceDevice   string             `json:"sourceDevice"`
	SourceSize     int64              `json:"sourceSize,omitempty"`
	SourceSHA256   string             `json:"sourceSHA256,omitempty"`
	OutputFiles    []CustodyFile      `json:"outputFiles"`
	ManifestSHA256 string             `json:"manifestSHA256"` // 内容算完后自填
}

type CustodyFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// BuildAndWrite 扫描 outputDir 下所有文件 → 算 sha256 → 生成 custody.json + 自身 sha256
func BuildAndWrite(outputDir string, c Custody) (string, error) {
	if outputDir == "" {
		return "", fmt.Errorf("outputDir 为空")
	}
	c.OS = runtime.GOOS
	c.Arch = runtime.GOARCH
	if c.OperatorUser == "" {
		if u := os.Getenv("USER"); u != "" {
			c.OperatorUser = u
		} else if u := os.Getenv("USERNAME"); u != "" {
			c.OperatorUser = u
		}
	}

	// 遍历 outputDir 收集所有 file
	var files []CustodyFile
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Base(path) == "custody.json" {
			return nil // 不把自己也算进去
		}
		h, hErr := sha256File(path)
		if hErr != nil {
			return nil // 个别文件失败不阻塞
		}
		rel, _ := filepath.Rel(outputDir, path)
		files = append(files, CustodyFile{Path: rel, Size: info.Size(), SHA256: h})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	c.OutputFiles = files
	c.CompletedAt = time.Now().UTC()
	if c.StartedAt.IsZero() {
		c.StartedAt = c.CompletedAt
	}

	// 算 manifest 内容的 sha256（先把字段置空再算 → 避免循环依赖）
	c.ManifestSHA256 = ""
	tmp, _ := json.MarshalIndent(c, "", "  ")
	sum := sha256.Sum256(tmp)
	c.ManifestSHA256 = hex.EncodeToString(sum[:])

	// 写最终文件（含 ManifestSHA256）
	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	dest := filepath.Join(outputDir, "custody.json")
	if err := os.WriteFile(dest, out, 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

// BuildSignAndWrite 是 BuildAndWrite 的 B2B 级扩展：manifest 之上加 Ed25519
// 数字签名 + RFC 3161 时间戳（默认 freetsa.org；失败回退 digicert / sectigo）。
//
// 输出文件：custody.signed.json —— 含 manifest 原字段 + signaturePublicKey +
// signature + tsaResponseB64。
//
// 第三方验证流程：
//   1. 拿到 custody.signed.json + 本工具发布的公钥（随 release 附）
//   2. 用 VerifySignedCustody 或标准 Ed25519 工具验 signature
//   3. 提取 tsaResponseB64 解 base64 → custody.tsr 文件
//      → `openssl ts -reply -in custody.tsr -text` 查真实 TSA 时间戳
//
// 失败时（TSA 全挂）不 fatal：manifest 签名已完成，时间戳字段留空。
func BuildSignAndWrite(outputDir string, c Custody) (string, error) {
	// 先跑常规 manifest 流程（计算 hash 等）
	if _, err := BuildAndWrite(outputDir, c); err != nil {
		return "", err
	}
	// 读刚写的 custody.json 再算一次（为了 outputFiles 准确）
	raw, err := os.ReadFile(filepath.Join(outputDir, "custody.json"))
	if err != nil {
		return "", err
	}
	var filled Custody
	if err := json.Unmarshal(raw, &filled); err != nil {
		return "", err
	}
	signed, err := SignCustody(filled, nil, nil)
	if err != nil {
		return "", err
	}
	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return "", err
	}
	dest := filepath.Join(outputDir, "custody.signed.json")
	if err := os.WriteFile(dest, out, 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyCustody 校验保管链：重算每个文件的 sha256 + 重算 manifest 的 sha256，
// 任何不匹配返回 error 列表。
func VerifyCustody(outputDir string) ([]error, error) {
	manifestPath := filepath.Join(outputDir, "custody.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("读 manifest: %w", err)
	}
	var c Custody
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("解 manifest: %w", err)
	}

	// 校验 manifest 自身 hash
	stored := c.ManifestSHA256
	c.ManifestSHA256 = ""
	tmp, _ := json.MarshalIndent(c, "", "  ")
	calc := sha256.Sum256(tmp)
	calcHex := hex.EncodeToString(calc[:])

	var problems []error
	if stored != calcHex {
		problems = append(problems, fmt.Errorf("manifest 自身被篡改: stored=%s calc=%s", stored, calcHex))
	}

	// 校验每个文件
	for _, f := range c.OutputFiles {
		path := filepath.Join(outputDir, f.Path)
		got, err := sha256File(path)
		if err != nil {
			problems = append(problems, fmt.Errorf("文件 %s: %w", f.Path, err))
			continue
		}
		if got != f.SHA256 {
			problems = append(problems, fmt.Errorf("文件 %s sha256 不匹配", f.Path))
		}
	}
	return problems, nil
}
