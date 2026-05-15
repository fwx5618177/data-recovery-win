// drift-check 扫描代码里"注释声明了保护层，但函数体内其实没有对应调用"的漂移。
//
// 背景：CHANGELOG v2.0.1 里两个生产 bug（预览 reader 漏 TimeoutReader、自动
// 更新漏 stall watchdog）同根同源 —— 注释写了"带超时/防卡死/带 watchdog"，
// 实现里却找不到任何 context.WithTimeout / time.AfterFunc / TimeoutReader /
// deadline 的调用。这种"注释承诺但代码没做"的 bug 随项目规模必然反复出现。
//
// 本工具不是完美静态分析，只做最朴素的字符串级 heuristic：
//
//  1. 扫所有 *.go 文件里的 **函数级** doc-comment / body 注释
//  2. 如果 doc 里出现任何 drift-trigger 关键词（timeout / watchdog / cancel /
//     deadline / 取消 / 超时 / 看门狗 等）
//  3. 就在对应的函数体里 grep 对应的 drift-resolver 关键词
//     （context.WithTimeout / time.AfterFunc / NewTimeoutReader /
//     select 分支里的 ctx.Done() / context.WithDeadline / Stop() 等）
//  4. 只有注释有、body 没有时报告
//
// 故意不做完整 AST 分析是 trade-off：90% 的漂移都能抓到；10% 要人判断的就
// human review 来兜底。用 golang.org/x/tools/go/ast 做精确分析会把这工具变成
// "又一个要维护的解析器"。
//
// 退出码：
//   - 0 = 没发现漂移（或只发现了 warnings；报告打印但不报错）
//   - 1 = 发现明确漂移（CI 会 fail）
//
// 用法：
//
//	drift-check              # 扫当前目录起整棵树，报告但不 fail
//	drift-check -strict      # 发现任何漂移就退出 1，适合 CI
//	drift-check -v           # 打印每个匹配位置
//	drift-check -root=./x    # 指定根目录
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DriftRule 描述一类漂移检查：如果注释里命中 trigger，函数体必须命中 resolvers 中至少一个。
type DriftRule struct {
	Name      string
	Trigger   *regexp.Regexp // 函数 doc 里必须匹配
	Resolvers []*regexp.Regexp
}

// 关键规则集：覆盖历史上真出过 bug 的几类 drift
var rules = []DriftRule{
	{
		Name:    "timeout",
		Trigger: regexp.MustCompile(`(?i)(timeout|超时|deadline|卡死)`),
		Resolvers: []*regexp.Regexp{
			regexp.MustCompile(`context\.WithTimeout`),
			regexp.MustCompile(`context\.WithDeadline`),
			regexp.MustCompile(`time\.AfterFunc`),
			regexp.MustCompile(`time\.After\b`),
			regexp.MustCompile(`NewTimeoutReader`),
			regexp.MustCompile(`OpenWithTimeout`),
			regexp.MustCompile(`SetDeadline`),
			regexp.MustCompile(`SetReadDeadline`),
			regexp.MustCompile(`SetWriteDeadline`),
		},
	},
	{
		Name:    "cancel",
		Trigger: regexp.MustCompile(`(?i)(cancellation|cancel|取消|context\.Cancelled)`),
		Resolvers: []*regexp.Regexp{
			regexp.MustCompile(`ctx\.Done\(\)`),
			regexp.MustCompile(`ctx\.Err\(\)`),
			regexp.MustCompile(`context\.WithCancel`),
			regexp.MustCompile(`\bcancel\(\)`),
			regexp.MustCompile(`select\s*{`),
		},
	},
	{
		Name:    "watchdog",
		Trigger: regexp.MustCompile(`(?i)(watchdog|看门狗|stall detect|stall watch|停滞检测)`),
		Resolvers: []*regexp.Regexp{
			regexp.MustCompile(`time\.NewTicker`),
			regexp.MustCompile(`time\.AfterFunc`),
			regexp.MustCompile(`time\.After\b`),
			regexp.MustCompile(`\bcancel\(\)`),
			regexp.MustCompile(`stall|Stall`),
		},
	},
	{
		Name:    "retry",
		Trigger: regexp.MustCompile(`(?i)(retry|重试|retries|backoff|指数退避|exponential)`),
		Resolvers: []*regexp.Regexp{
			regexp.MustCompile(`for\s+.*\b(i|attempt|try)\b`),
			regexp.MustCompile(`time\.Sleep`),
			regexp.MustCompile(`\bbackoff`),
			regexp.MustCompile(`\bretry\b`),
		},
	},
	{
		Name:    "cleanup",
		Trigger: regexp.MustCompile(`(?i)(cleanup|clean up|清理|释放资源|release.+resource)`),
		Resolvers: []*regexp.Regexp{
			regexp.MustCompile(`\bdefer\b`),
			regexp.MustCompile(`\.Close\(\)`),
			regexp.MustCompile(`\.Shutdown\(\)`),
			regexp.MustCompile(`\.Release\(\)`),
		},
	},
}

// Finding 一条漂移报告
type Finding struct {
	File    string
	Line    int
	Func    string
	Rule    string
	Comment string // 触发漂移的原注释（截取前 80 字节）
}

func main() {
	root := flag.String("root", ".", "扫描根目录")
	strict := flag.Bool("strict", false, "发现漂移即退出 1（给 CI 用）")
	verbose := flag.Bool("v", false, "verbose 输出")
	flag.Parse()

	findings, errs := scan(*root)

	// 打印解析错误（但不当 fatal，Go 项目里偶有 cgo/build-tag 导致 parser 失败）
	if *verbose {
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		}
	}

	if len(findings) == 0 {
		fmt.Println("✓ 未发现注释↔实现漂移")
		return
	}

	// 按 file 分组输出，便于 grep 定位
	byFile := map[string][]Finding{}
	for _, f := range findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	fmt.Printf("✗ 发现 %d 条潜在漂移（%d 个文件）：\n\n", len(findings), len(byFile))
	for file, fs := range byFile {
		rel, _ := filepath.Rel(*root, file)
		if rel == "" {
			rel = file
		}
		fmt.Printf("  %s\n", rel)
		for _, f := range fs {
			fmt.Printf("    %s:%d  func %s  [rule=%s]\n",
				rel, f.Line, f.Func, f.Rule)
			fmt.Printf("        注释: %s\n", f.Comment)
		}
		fmt.Println()
	}

	fmt.Printf("规则：注释命中 trigger 关键词时，函数体必须同时出现对应的 resolver 调用。\n")
	fmt.Printf("修法：① 把注释里的承诺删掉；或 ② 在代码里真的加上对应调用。\n")

	if *strict {
		os.Exit(1)
	}
}

// scan 遍历 root 下所有 .go 文件，收集 Finding 和解析错误
func scan(root string) ([]Finding, []error) {
	var findings []Finding
	var errs []error

	fset := token.NewFileSet()
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			// 跳过 vendor、build 产物、测试数据、node_modules
			if name == "vendor" || name == "node_modules" || name == ".gocache" ||
				name == "testdata" || name == "build" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		// 解析 file；带 ParseComments 以保留 doc
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, parseErr))
			return nil
		}

		// 读原文件字节用于 body 正则扫描（ast 里的 body 打印回来会丢注释风味）。
		// path 来自 filepath.WalkDir 内部已校验的 root subtree，非用户外部输入；
		// 是 dev 工具不是 server，TOCTOU 风险无业务影响。
		// #nosec G304 G122 -- drift-check 是仓库内自检工具，path 来自固定 root 内
		body, _ := os.ReadFile(path)

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Doc == nil || fn.Body == nil {
				continue
			}
			docText := fn.Doc.Text()
			bodyStart := fset.Position(fn.Body.Pos()).Offset
			bodyEnd := fset.Position(fn.Body.End()).Offset
			if bodyEnd > len(body) {
				bodyEnd = len(body)
			}
			if bodyStart >= bodyEnd {
				continue
			}
			bodyText := string(body[bodyStart:bodyEnd])

			for _, rule := range rules {
				if !rule.Trigger.MatchString(docText) {
					continue
				}
				resolved := false
				for _, res := range rule.Resolvers {
					if res.MatchString(bodyText) {
						resolved = true
						break
					}
				}
				if !resolved {
					snippet := strings.TrimSpace(docText)
					snippet = strings.ReplaceAll(snippet, "\n", " ")
					if len(snippet) > 120 {
						snippet = snippet[:120] + "…"
					}
					findings = append(findings, Finding{
						File:    path,
						Line:    fset.Position(fn.Pos()).Line,
						Func:    fn.Name.Name,
						Rule:    rule.Name,
						Comment: snippet,
					})
				}
			}
		}
		return nil
	})

	return findings, errs
}
