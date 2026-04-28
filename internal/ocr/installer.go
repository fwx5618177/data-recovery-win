package ocr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 用户在 OCR Modal 里点 "+ 添加语言" 时调这里。从官方 tessdata_fast 仓库
// 下载 lang.traineddata 到 cache/tessdata，下次 OCR 直接可用。
//
// 设计：
//   - 仅从 raw.githubusercontent.com（GitHub 官方 CDN）拉，无第三方镜像
//   - 走 HTTPS，下载完做基础 sanity check（不为空 / 非 HTML 错误页）
//   - 不并发下多个语言（避免 GitHub raw 触发限流；用户也基本一次只加一个）

const tessdataFastBaseURL = "https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/main/"

// AvailableLanguages 是 tessdata_fast 仓库里已知可下载的语言代码 + 中文名。
// 列表来自 https://github.com/tesseract-ocr/tessdata_fast 顶层 .traineddata 文件名。
// 这里手维护，避免运行时还要拉 GitHub 目录列表 API（未登录有 60 req/h 限流）。
var AvailableLanguages = []LanguageInfo{
	{Code: "eng", Name: "English", Builtin: true},
	{Code: "chi_sim", Name: "中文（简体）", Builtin: true},
	{Code: "chi_tra", Name: "中文（繁体）"},
	{Code: "jpn", Name: "日本語"},
	{Code: "kor", Name: "한국어"},
	{Code: "rus", Name: "Русский"},
	{Code: "deu", Name: "Deutsch"},
	{Code: "fra", Name: "Français"},
	{Code: "spa", Name: "Español"},
	{Code: "ita", Name: "Italiano"},
	{Code: "por", Name: "Português"},
	{Code: "nld", Name: "Nederlands"},
	{Code: "ara", Name: "العربية"},
	{Code: "heb", Name: "עברית"},
	{Code: "tha", Name: "ไทย"},
	{Code: "vie", Name: "Tiếng Việt"},
	{Code: "tur", Name: "Türkçe"},
	{Code: "pol", Name: "Polski"},
	{Code: "ces", Name: "Čeština"},
	{Code: "ukr", Name: "Українська"},
	{Code: "ell", Name: "Ελληνικά"},
	{Code: "hin", Name: "हिन्दी"},
	{Code: "ben", Name: "বাংলা"},
	{Code: "mar", Name: "मराठी"},
	{Code: "tam", Name: "தமிழ்"},
	{Code: "tel", Name: "తెలుగు"},
	{Code: "ind", Name: "Bahasa Indonesia"},
	{Code: "msa", Name: "Bahasa Melayu"},
	{Code: "swe", Name: "Svenska"},
	{Code: "nor", Name: "Norsk"},
	{Code: "dan", Name: "Dansk"},
	{Code: "fin", Name: "Suomi"},
	{Code: "hun", Name: "Magyar"},
	{Code: "ron", Name: "Română"},
	{Code: "bul", Name: "Български"},
	{Code: "hrv", Name: "Hrvatski"},
	{Code: "srp", Name: "Српски"},
	{Code: "slk", Name: "Slovenčina"},
	{Code: "slv", Name: "Slovenščina"},
	{Code: "lav", Name: "Latviešu"},
	{Code: "lit", Name: "Lietuvių"},
	{Code: "est", Name: "Eesti"},
	{Code: "kat", Name: "ქართული"},
	{Code: "hye", Name: "Հայերեն"},
	{Code: "fas", Name: "فارسی"},
	{Code: "urd", Name: "اردو"},
}

// LanguageInfo 一种可用语言的元数据
type LanguageInfo struct {
	Code      string `json:"code"`              // tesseract lang code（"chi_sim"）
	Name      string `json:"name"`              // 给用户看的人名（"中文（简体）"）
	Builtin   bool   `json:"builtin,omitempty"` // 是否 app 内嵌（不可删）
	Installed bool   `json:"installed"`         // 当前是否已下载到 cache
	SizeBytes int64  `json:"sizeBytes,omitempty"`
}

// ListAvailableLanguages 把"可下载列表" + "已装状态"合并返回给前端。
func ListAvailableLanguages() ([]LanguageInfo, error) {
	installedSet := map[string]int64{}
	if installed, err := ListInstalledLangs(); err == nil {
		tessdir, _ := TessdataDir()
		for _, lang := range installed {
			if st, err := os.Stat(filepath.Join(tessdir, lang+".traineddata")); err == nil {
				installedSet[lang] = st.Size()
			} else {
				installedSet[lang] = 0
			}
		}
	}
	out := make([]LanguageInfo, 0, len(AvailableLanguages))
	for _, l := range AvailableLanguages {
		if size, ok := installedSet[l.Code]; ok {
			l.Installed = true
			l.SizeBytes = size
		}
		out = append(out, l)
	}
	return out, nil
}

// DownloadLanguage 从 tessdata_fast 拉 <code>.traineddata 到 cache/tessdata/。
// 已存在就跳过；下载失败时把临时文件清掉避免下次拿到半截 traineddata 误用。
//
// 不放 ctx 超时是因为 chi_tra ~50MB 在慢网下也得 1+ min；用户取消通过 ctx.Cancel。
func DownloadLanguage(ctx context.Context, code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return fmt.Errorf("语言代码为空")
	}
	if HasEmbeddedLang(code) {
		// 内嵌语言不下载，确保 cache 里是 embed 出来的版本
		return EnsureBuiltinLangs()
	}
	tessdir, err := TessdataDir()
	if err != nil {
		return err
	}
	dst := filepath.Join(tessdir, code+".traineddata")
	if st, err := os.Stat(dst); err == nil && st.Size() > 1024 {
		return nil // 已装
	}
	url := tessdataFastBaseURL + code + ".traineddata"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	cli := &http.Client{Timeout: 5 * time.Minute}
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("下载 %s 失败：%w", code, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载 %s 失败：HTTP %d", code, resp.StatusCode)
	}
	tmp := dst + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("写 %s.traineddata: %w", code, err)
	}
	out.Close()
	// sanity：体积 < 50KB 大概率是 GitHub 404 HTML 页面
	if st, err := os.Stat(tmp); err != nil || st.Size() < 50*1024 {
		os.Remove(tmp)
		return fmt.Errorf("下载到的 %s.traineddata 体积异常（%d 字节）—— 可能 GitHub 404", code, st.Size())
	}
	return os.Rename(tmp, dst)
}

// DeleteLanguage 把已下载的语言从 cache 里删掉。内置语言（eng / chi_sim）不允许删。
func DeleteLanguage(code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return fmt.Errorf("语言代码为空")
	}
	if HasEmbeddedLang(code) {
		return fmt.Errorf("%s 是内置语言，不可删除", code)
	}
	tessdir, err := TessdataDir()
	if err != nil {
		return err
	}
	path := filepath.Join(tessdir, code+".traineddata")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(path)
}

// LanguageSHA256 给运维 / 取证用，确认 cache 里的 traineddata 没被篡改
func LanguageSHA256(code string) (string, error) {
	tessdir, err := TessdataDir()
	if err != nil {
		return "", err
	}
	f, err := os.Open(filepath.Join(tessdir, code+".traineddata"))
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
