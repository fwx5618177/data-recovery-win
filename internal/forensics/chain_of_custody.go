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
//
// 这是给"用户手动跑保管链工具"用的入口 —— 用户显式说"对这个目录里的所有东西算 hash"
// 时是合理的。但**不要**给自动 post-recovery 流程用：用户的 outputDir 可能是 C:\
// 之类的根目录，walk 整个盘会让磁盘 IO 持续几分钟到几小时（v2.8.21 用户报的
// "恢复完成后磁盘还在被读"的真正成因）。
// 自动 post-recovery 应该用 BuildAndWriteFromPaths（v2.8.30 加），只 hash 实际写盘的文件。
func BuildAndWrite(outputDir string, c Custody) (string, error) {
	if outputDir == "" {
		return "", fmt.Errorf("outputDir 为空")
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
	return writeCustodyManifest(outputDir, c, files)
}

// BuildAndWriteFromPaths 用**显式提供的文件列表**算 SHA256 + 生成 custody.json。
//
// v2.8.30 加 —— 修 v2.8.21 用户报的"恢复完成后磁盘还在被读几十秒到几分钟"的真正成因：
// 之前 post-recovery forensics 调 BuildAndWrite，里面 filepath.Walk 整个 outputDir。
// 用户的 outputDir 经常是 C:\ 或者 D:\ 这种盘根目录 —— walk 整个盘 + 每个文件算
// SHA256 是磁盘 IO 灾难。
//
// 现在：直接传当次恢复**真正写盘**的文件列表（recovery.records 里的 OutputPath），
// 只算这些文件的 SHA256。1.2MB 一张图片 = 1 次 sha256，毫秒级完成。
//
// outputDir：仅用作 1) 写 custody.json 落地位置 2) 算 Path 相对路径基准；不再 walk 它。
// absPaths：要算 SHA256 的绝对路径列表（一般来自 recovery.FileRecoveryRecord.OutputPath）。
//   nil / 空切片 → 生成的 manifest 不含 outputFiles，但其它元数据仍写盘。
func BuildAndWriteFromPaths(outputDir string, c Custody, absPaths []string) (string, error) {
	if outputDir == "" {
		return "", fmt.Errorf("outputDir 为空")
	}
	files := make([]CustodyFile, 0, len(absPaths))
	for _, p := range absPaths {
		if p == "" {
			continue
		}
		info, statErr := os.Stat(p)
		if statErr != nil || info.IsDir() {
			continue
		}
		h, hErr := sha256File(p)
		if hErr != nil {
			continue
		}
		rel, _ := filepath.Rel(outputDir, p)
		if rel == "" {
			rel = filepath.Base(p)
		}
		files = append(files, CustodyFile{Path: rel, Size: info.Size(), SHA256: h})
	}
	return writeCustodyManifest(outputDir, c, files)
}

// writeCustodyManifest 把已经算好 SHA256 的文件列表写成 custody.json。
// 这是 BuildAndWrite / BuildAndWriteFromPaths 的公共尾段。
func writeCustodyManifest(outputDir string, c Custody, files []CustodyFile) (string, error) {
	c.OS = runtime.GOOS
	c.Arch = runtime.GOARCH
	if c.OperatorUser == "" {
		if u := os.Getenv("USER"); u != "" {
			c.OperatorUser = u
		} else if u := os.Getenv("USERNAME"); u != "" {
			c.OperatorUser = u
		}
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
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("创建 outputDir 失败: %w", err)
	}
	dest := filepath.Join(outputDir, "custody.json")
	if err := os.WriteFile(dest, out, 0o644); err != nil {
		return "", err
	}

	// 同时写 binary plist 副本（对 macOS 工具链原生兼容）。
	// 失败不阻塞 —— JSON 仍是 source-of-truth；plist 只是便利副本。
	if _, plistErr := WriteCustodyPlist(outputDir, c); plistErr != nil {
		// 静默：plist 是 nice-to-have，不应让 custody 流程失败
		_ = plistErr
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
	return signExistingCustody(outputDir)
}

// BuildSignAndWriteFromPaths 同 BuildSignAndWrite 但只 hash 显式提供的文件，
// 不 walk outputDir。v2.8.30 加 —— 给 post-recovery 自动流程用，防止 walk
// 整个 C:\ / D:\ 引起的"恢复完成后磁盘 IO 持续几分钟"问题。
func BuildSignAndWriteFromPaths(outputDir string, c Custody, absPaths []string) (string, error) {
	if _, err := BuildAndWriteFromPaths(outputDir, c, absPaths); err != nil {
		return "", err
	}
	return signExistingCustody(outputDir)
}

// signExistingCustody 在 outputDir 已经有 custody.json 的前提下，加 Ed25519 + TSA
// 签名层 → 写 custody.signed.json。
func signExistingCustody(outputDir string) (string, error) {
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
