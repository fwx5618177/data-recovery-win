package forensics

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// NSRLDB —— 离线 NSRL (National Software Reference Library) hash 数据库查询。
// NSRL 是 NIST 维护的"已知良性软件 hash 表"，约 30GB CSV/SQLite。
// 取证人员用它"过滤掉系统文件 / 已知工具 / 不感兴趣的文件"，专注于剩下的可疑文件。
//
// **本工具不内嵌 NSRL**（30GB 太大）；提供"载入预制 hash 列表"接口，
// 用户自己从 https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
// 下载 NSRL minimal hash list（仅 sha256 一列）。
type NSRLDB struct {
	hashes map[string]struct{}
}

// LoadNSRLFromFile 读 .txt 文件（每行一个 sha256，大小写无关）
func LoadNSRLFromFile(path string) (*NSRLDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 NSRL 文件: %w", err)
	}
	defer f.Close()
	db := &NSRLDB{hashes: make(map[string]struct{}, 1<<20)}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		s := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if len(s) == 64 { // SHA-256 hex
			db.hashes[s] = struct{}{}
		}
	}
	return db, scanner.Err()
}

// IsKnownBenign 文件 hash 在 NSRL 里 = 已知良性，可过滤
func (db *NSRLDB) IsKnownBenign(sha256Hex string) bool {
	if db == nil || db.hashes == nil {
		return false
	}
	_, ok := db.hashes[strings.ToLower(sha256Hex)]
	return ok
}

// Size 库里 hash 数量
func (db *NSRLDB) Size() int {
	if db == nil {
		return 0
	}
	return len(db.hashes)
}

// =============================================================
// VirusTotal hash 查询（v3 API）
// =============================================================

// VTReport VirusTotal 文件报告的精简返回
type VTReport struct {
	SHA256       string `json:"sha256"`
	Malicious    int    `json:"malicious"` // 多少 AV 报恶意
	Suspicious   int    `json:"suspicious"`
	Undetected   int    `json:"undetected"`
	TotalEngines int    `json:"totalEngines"`
	Permalink    string `json:"permalink"`
}

// VTClient VirusTotal API client（用户自带 API key）
type VTClient struct {
	APIKey string
	HTTP   *http.Client
}

// NewVTClient 默认 30s 超时
func NewVTClient(apiKey string) *VTClient {
	return &VTClient{
		APIKey: apiKey,
		HTTP:   &http.Client{Timeout: 30 * time.Second},
	}
}

// LookupHash 查询 sha256；找不到（404）返回 nil + nil；其它错误返回 error。
//
// 本工具**不上传文件本身**，只查 hash —— 对调查员自己的数据隐私友好。
// API 配额：免费版 4 req/min，500/day。
func (c *VTClient) LookupHash(ctx context.Context, sha256Hex string) (*VTReport, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("VirusTotal API key 为空")
	}
	url := "https://www.virustotal.com/api/v3/files/" + sha256Hex
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("x-apikey", c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VirusTotal HTTP %d", resp.StatusCode)
	}
	var raw struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	stats := raw.Data.Attributes.LastAnalysisStats
	return &VTReport{
		SHA256:       sha256Hex,
		Malicious:    stats.Malicious,
		Suspicious:   stats.Suspicious,
		Undetected:   stats.Undetected,
		TotalEngines: stats.Malicious + stats.Suspicious + stats.Undetected,
		Permalink:    "https://www.virustotal.com/gui/file/" + sha256Hex,
	}, nil
}
