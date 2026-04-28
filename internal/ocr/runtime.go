// Package ocr v2.8.4 重构版：
//
// 设计目标：「OCR 开箱即用」—— 用户**不需要**手动装语言包。
//
// 实现策略：
//   1. **traineddata 内嵌**（small）：app 二进制内嵌 eng + chi_sim 的 fast 模型
//      （约 20 MB），首次 OCR 时解压到 user cache 目录。任何系统装的 tesseract
//      跑起来都能直接用 —— 不依赖 OS 自带的 tessdata，也不需要用户去
//      `apt install tesseract-ocr-chi-sim`。
//   2. **额外语言按需下载**：用户在 OCR Modal 里点 "+ 添加语言" 选某个 lang，
//      app 从 `tessdata_fast` 官方仓库下载到 cache，立即可用。见 installer.go。
//   3. **tesseract 二进制**：先找 system PATH，再找各平台常见 install 路径。
//      没找到就在 UI 上用 friendly toast 提示用户装。
//      （v2.9 计划：把 tesseract 本体也内嵌进 app 二进制做到完全 zero-install；
//        v2.8.4 这一步先把"已装但 PATH 没加"的常见情况修了，让现有用户立刻可用。）

package ocr

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

//go:embed assets/tessdata/*.traineddata
var embeddedTessdata embed.FS

// builtinLangs 是 app 一定内嵌的语言。其它语言用户按需下载到 cache dir。
var builtinLangs = []string{"eng", "chi_sim"}

// 缓存目录布局：
//   ~/.cache/data-recovery/ocr/  (Linux)
//   ~/Library/Caches/data-recovery/ocr/  (macOS)
//   %LOCALAPPDATA%\data-recovery\ocr\  (Windows)
//   ├── tessdata/
//   │   ├── eng.traineddata        ← 启动时从 embed.FS 同步
//   │   ├── chi_sim.traineddata    ← 同上
//   │   └── jpn.traineddata        ← 用户后下载的
//   └── version                    ← 标记当前 embed 的版本，升级 app 时重写

const cacheVersionMarker = "v2.8.4-fast"

var (
	cacheDirOnce sync.Once
	cacheDirVal  string
	cacheDirErr  error
)

// CacheDir 返回 app 的 OCR cache dir，必要时创建。
// 目录约定：每平台 OS 标准位置 / data-recovery / ocr / 。
func CacheDir() (string, error) {
	cacheDirOnce.Do(func() {
		base, err := os.UserCacheDir()
		if err != nil {
			cacheDirErr = err
			return
		}
		dir := filepath.Join(base, "data-recovery", "ocr")
		if err := os.MkdirAll(filepath.Join(dir, "tessdata"), 0o755); err != nil {
			cacheDirErr = fmt.Errorf("创建 OCR cache 目录失败: %w", err)
			return
		}
		cacheDirVal = dir
	})
	return cacheDirVal, cacheDirErr
}

// TessdataDir 返回放 *.traineddata 的目录（cache/tessdata）。
func TessdataDir() (string, error) {
	d, err := CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tessdata"), nil
}

// EnsureBuiltinLangs 把内嵌的 eng / chi_sim traineddata 同步到 cache dir。
// 已经存在且大小匹配就跳过；版本变化时整体重刷。
//
// 调用时机：每次 OCR 调用前先 Ensure；启动期不强制（lazy）。
func EnsureBuiltinLangs() error {
	tessdir, err := TessdataDir()
	if err != nil {
		return err
	}
	verPath := filepath.Join(tessdir, ".version")
	curVer, _ := os.ReadFile(verPath)
	versionMatches := strings.TrimSpace(string(curVer)) == cacheVersionMarker

	for _, lang := range builtinLangs {
		dst := filepath.Join(tessdir, lang+".traineddata")
		if versionMatches {
			if st, err := os.Stat(dst); err == nil && st.Size() > 1024 {
				continue // 文件已存在且非占位 → 跳过
			}
		}
		// 从 embed 复制
		src, err := embeddedTessdata.Open("assets/tessdata/" + lang + ".traineddata")
		if err != nil {
			// embed 中没有这个文件（开发环境未跑 bundle 阶段），跳过 —— UI 自然
			// 会引导用户手动下载 / 用 system tessdata。
			continue
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			src.Close()
			return fmt.Errorf("写 %s.traineddata 到 cache: %w", lang, err)
		}
		if _, err := io.Copy(out, src); err != nil {
			out.Close()
			src.Close()
			return fmt.Errorf("复制 %s.traineddata: %w", lang, err)
		}
		out.Close()
		src.Close()
	}
	_ = os.WriteFile(verPath, []byte(cacheVersionMarker), 0o644)
	return nil
}

// HasEmbeddedLang 这个语言代码的 traineddata 是不是 app 内嵌（vs 外部下载）。
// UI 用来标记"内置 / 已下载"区别。
func HasEmbeddedLang(lang string) bool {
	_, err := embeddedTessdata.Open("assets/tessdata/" + lang + ".traineddata")
	return err == nil
}

// ListInstalledLangs 列出 cache/tessdata 下当前可用的语言代码（去 .traineddata 后缀）。
func ListInstalledLangs() ([]string, error) {
	if err := EnsureBuiltinLangs(); err != nil {
		return nil, err
	}
	tessdir, err := TessdataDir()
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(os.DirFS(tessdir), ".")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var langs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".traineddata") {
			continue
		}
		langs = append(langs, strings.TrimSuffix(name, ".traineddata"))
	}
	return langs, nil
}

// FindTesseractBin 找 tesseract 可执行文件。优先级：
//  1. 环境变量 TESSERACT_BIN（用户显式指定）
//  2. system PATH
//  3. 各平台常见安装路径（用户用 "下软件" / 安装包装但没加 PATH 的情况）
//
// 找不到返回 ("", err)。
func FindTesseractBin() (string, error) {
	if env := os.Getenv("TESSERACT_BIN"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
	}
	if p, err := exec.LookPath("tesseract"); err == nil {
		return p, nil
	}
	candidates := commonInstallPaths()
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("tesseract 不在 PATH 也不在常见安装位置")
}

// commonInstallPaths 各平台用户装 tesseract 后常见的可执行路径。
// 这些路径通常**不在系统 PATH 里**（尤其 Windows 装 .exe 没勾"添加到 PATH"），
// 单查 LookPath 会漏报"明明装了"的情况 —— 这里兜底。
func commonInstallPaths() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\Program Files\Tesseract-OCR\tesseract.exe`,
			`C:\Program Files (x86)\Tesseract-OCR\tesseract.exe`,
			// "下软件" / 360 / 各种国内软件管家常见安装位置
			`C:\Tesseract-OCR\tesseract.exe`,
			`D:\Tesseract-OCR\tesseract.exe`,
			os.ExpandEnv(`${LOCALAPPDATA}\Programs\Tesseract-OCR\tesseract.exe`),
			os.ExpandEnv(`${USERPROFILE}\AppData\Local\Programs\Tesseract-OCR\tesseract.exe`),
		}
	case "darwin":
		return []string{
			"/opt/homebrew/bin/tesseract", // Apple Silicon brew
			"/usr/local/bin/tesseract",    // Intel brew / 手装
			"/opt/local/bin/tesseract",    // MacPorts
		}
	case "linux":
		return []string{
			"/usr/bin/tesseract",
			"/usr/local/bin/tesseract",
			"/snap/bin/tesseract",
		}
	}
	return nil
}

// Status 是 UI 拿来显示"OCR 健康度"的快照。
type Status struct {
	BinaryPath       string   `json:"binaryPath"`       // 用的 tesseract 路径
	BinaryFound      bool     `json:"binaryFound"`      // 找到 binary 了吗
	BinaryVersion    string   `json:"binaryVersion"`    // tesseract --version 输出第一行
	TessdataDir      string   `json:"tessdataDir"`      // 我们 manage 的 tessdata 目录
	InstalledLangs   []string `json:"installedLangs"`   // 已安装语言
	BuiltinLangs     []string `json:"builtinLangs"`     // app 内嵌语言（不可删）
	NotFoundHint     string   `json:"notFoundHint"`     // binary 缺失时给用户的指引
}

// QueryStatus 给前端的"OCR 现在能不能用 + 装了哪些语言"摘要
func QueryStatus() *Status {
	st := &Status{
		BuiltinLangs: append([]string(nil), builtinLangs...),
	}
	if dir, err := TessdataDir(); err == nil {
		st.TessdataDir = dir
	}
	if err := EnsureBuiltinLangs(); err != nil {
		st.NotFoundHint = "OCR cache 初始化失败：" + err.Error()
		return st
	}
	if langs, err := ListInstalledLangs(); err == nil {
		st.InstalledLangs = langs
	}
	bin, err := FindTesseractBin()
	if err != nil {
		st.NotFoundHint = notFoundHintForOS()
		return st
	}
	st.BinaryFound = true
	st.BinaryPath = bin
	if v := tesseractVersion(bin); v != "" {
		st.BinaryVersion = v
	}
	return st
}

func tesseractVersion(bin string) string {
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		// 第一行通常是 "tesseract 5.4.0" 之类
		return l
	}
	return ""
}

// notFoundHintForOS 给用户的"怎么装 tesseract"指引（按平台）。
// v2.9 计划：内嵌 tesseract 二进制，本函数届时返回空字符串。
func notFoundHintForOS() string {
	switch runtime.GOOS {
	case "windows":
		return "OCR 引擎 (tesseract) 未找到。\n" +
			"安装：访问 https://github.com/UB-Mannheim/tesseract/releases\n" +
			"下载并运行 tesseract-ocr-w64-setup-*.exe（默认装到 C:\\Program Files\\Tesseract-OCR）。\n" +
			"装完不需要加 PATH —— app 会自动从安装目录找到它。"
	case "darwin":
		return "OCR 引擎 (tesseract) 未找到。\n" +
			"安装：终端运行 `brew install tesseract`（不需要 tesseract-lang，traineddata 已内嵌）。"
	case "linux":
		return "OCR 引擎 (tesseract) 未找到。\n" +
			"安装：`sudo apt install tesseract-ocr` 或 `sudo dnf install tesseract`。"
	}
	return "OCR 引擎 (tesseract) 未找到。"
}
