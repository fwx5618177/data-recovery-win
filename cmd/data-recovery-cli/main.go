// data-recovery-cli —— GUI-less CLI 入口，给取证脚本 / 服务器 / CI 场景。
//
// 子命令：
//
//	scan   <drive> [--mode quick|deep|full] [--output report.json]
//	         扫描磁盘 / 镜像，把发现的文件元数据写到 JSON
//
//	recover <report.json> --output <dir> [--filter "*.jpg,*.pdf"] [--allow-same-disk]
//	         从已扫描的 report.json 里挑符合 filter 的文件恢复出来
//
//	bitlocker-detect <drive>
//	         列出磁盘上的 BitLocker 卷 + 它们的 protector 类型
//
//	usn-list <drive>
//	         直接读 NTFS $UsnJrnl 列出"被删除文件名 + 时间"清单
//
// 设计理念：
//   - 只读，不写源盘；恢复输出强制不同盘检查
//   - JSON-only 输出（除人类可读 progress 外），方便 jq / shell 管道处理
//   - 复用 internal/recovery 的 Engine，与 GUI 走同一套代码
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"data-recovery/internal/disk"
	"data-recovery/internal/logging"
	"data-recovery/internal/ntfs"
	"data-recovery/internal/recovery"
	"data-recovery/internal/types"
)

const cliUsage = `data-recovery-cli — Open-source data recovery, headless mode.

Usage:
  data-recovery-cli scan <drive> [--mode quick|deep|full] [--output report.json]
  data-recovery-cli recover <report.json> --output <dir> [--filter pattern] [--allow-same-disk]
  data-recovery-cli scan-and-recover <drive> --output <dir> [--mode full] [--filter "*.jpg"] [--allow-same-disk]
  data-recovery-cli bitlocker-detect <drive>
  data-recovery-cli usn-list <drive> [--max-bytes 67108864]
  data-recovery-cli help

Examples:
  data-recovery-cli scan /dev/sdb1 --mode full --output sdb1.json
  data-recovery-cli recover sdb1.json --output ./recovered --filter "*.jpg,*.heic"
  data-recovery-cli scan-and-recover /dev/sdb1 --output ./recovered --filter "*.jpg,*.heic,*.docx"
  data-recovery-cli bitlocker-detect '\\.\PhysicalDrive0'
  data-recovery-cli usn-list /dev/nvme0n1p3

注意：
  scan + recover 分开两步只能恢复 carver 来源（按盘内 offset 直读）；
  NTFS / APFS / HFS+ 等需要 source cache 的来源必须用 scan-and-recover 单进程模式。
`

func main() {
	logging.L() // touch global logger

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, cliUsage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "recover":
		cmdRecover(os.Args[2:])
	case "scan-and-recover":
		cmdScanAndRecover(os.Args[2:])
	case "bitlocker-detect":
		cmdBitLockerDetect(os.Args[2:])
	case "usn-list":
		cmdUSNList(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(cliUsage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], cliUsage)
		os.Exit(2)
	}
}

// flagsAfter 把"位置参数 + flag"的简单解析合并：返回 (positional, kvFlags)。
// flag 必须形如 --key value 或 --key=value；无 flag 后跟值的 bool 暂不支持。
func flagsAfter(args []string) ([]string, map[string]string) {
	pos := []string{}
	kv := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			key := strings.TrimPrefix(a, "--")
			if eq := strings.Index(key, "="); eq >= 0 {
				kv[key[:eq]] = key[eq+1:]
			} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				kv[key] = args[i+1]
				i++
			} else {
				kv[key] = "true"
			}
		} else {
			pos = append(pos, a)
		}
	}
	return pos, kv
}

func dieIf(err error, format string, args ...any) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, format+": %v\n", append(args, err)...)
	os.Exit(1)
}

// =============== scan ===============

func cmdScan(args []string) {
	pos, flags := flagsAfter(args)
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "scan: 缺少 <drive> 参数")
		os.Exit(2)
	}
	drive := pos[0]
	mode := flags["mode"]
	if mode == "" {
		mode = "full"
	}
	output := flags["output"]
	if output == "" {
		output = "scan-report.json"
	}

	engine := recovery.NewEngine()
	defer engine.Shutdown()

	go awaitInterrupt(func() { engine.Stop() }, engine)

	startTime := time.Now()
	lastPct := -1
	cb := recovery.ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			if int(p.Percent) > lastPct {
				lastPct = int(p.Percent)
				fmt.Fprintf(os.Stderr, "\r[scan] %3d%% %s files=%d", lastPct, p.Phase, p.FilesFound)
			}
		},
	}
	res, err := engine.Scan(drive, types.ScanMode(mode), cb)
	fmt.Fprintln(os.Stderr) // 换行
	dieIf(err, "scan failed")

	// 输出 JSON 报告
	out, err := os.Create(output)
	dieIf(err, "create %s", output)
	defer out.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		dieIf(err, "encode report")
	}
	fmt.Fprintf(os.Stderr, "\n✅ 扫描完成: %d 文件，用时 %.1fs，报告写入 %s\n",
		len(res.Files), time.Since(startTime).Seconds(), output)
}

// =============== recover ===============

func cmdRecover(args []string) {
	pos, flags := flagsAfter(args)
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "recover: 缺少 <report.json> 参数")
		os.Exit(2)
	}
	reportPath := pos[0]
	outputDir := flags["output"]
	if outputDir == "" {
		fmt.Fprintln(os.Stderr, "recover: --output <dir> 必填")
		os.Exit(2)
	}
	filterStr := flags["filter"]
	allowSameDisk := flags["allow-same-disk"] == "true"

	// 读 report
	data, err := os.ReadFile(reportPath)
	dieIf(err, "read %s", reportPath)
	var report types.ScanResult
	dieIf(json.Unmarshal(data, &report), "decode report")
	if len(report.Files) == 0 {
		fmt.Fprintln(os.Stderr, "report 里没有文件")
		os.Exit(1)
	}

	// 按 filter 挑文件
	patterns := splitNonEmpty(filterStr, ",")
	var pickedIDs []string
	for _, f := range report.Files {
		if !matchesAnyPattern(f.FileName, patterns) {
			continue
		}
		pickedIDs = append(pickedIDs, f.ID)
	}
	fmt.Fprintf(os.Stderr, "选中 %d / %d 文件准备恢复\n", len(pickedIDs), len(report.Files))
	if len(pickedIDs) == 0 {
		os.Exit(0)
	}

	engine := recovery.NewEngine()
	defer engine.Shutdown()

	go awaitInterrupt(func() { engine.StopRecovery() }, engine)

	lastPct := -1
	rcb := recovery.RecoverCallbacks{
		OnProgress: func(p types.RecoveryProgress) {
			pct := 0
			if p.Total > 0 {
				pct = p.Current * 100 / p.Total
			}
			if pct > lastPct {
				lastPct = pct
				fmt.Fprintf(os.Stderr, "\r[recover] %3d%% (%d/%d) %s",
					pct, p.Current, p.Total, p.CurrentFile)
			}
		},
	}

	// 注意：本独立 recover 进程的 engine 没有 NTFS / APFS source 缓存，
	// 所以非 carver 来源的恢复会因为找不到 source 而失败。完整工作流应是 scan + recover
	// 在同一进程跑（GUI 即如此）。CLI MVP 的设计折衷：carver 来源直接走 offset 读，仍能 work。
	opts := recovery.RecoverOptions{AllowSameDisk: allowSameDisk}
	_, err = engine.RecoverWithOptions(pickedIDs, outputDir, opts, rcb)
	fmt.Fprintln(os.Stderr)
	dieIf(err, "recover failed")
	fmt.Fprintln(os.Stderr, "✅ 恢复完成（仅 carver 来源能在独立 recover 调用里工作；")
	fmt.Fprintln(os.Stderr, "   NTFS / APFS / HFS+ 来源需在同一 scan 进程里 recover）")
}

// =============== scan-and-recover ===============

// 单进程串联 scan + recover：scan 完成后立即用同一 engine 的 source cache 恢复，
// 完整支持 NTFS / APFS / HFS+ / FAT 等需要 source cache 的来源。
func cmdScanAndRecover(args []string) {
	pos, flags := flagsAfter(args)
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "scan-and-recover: 缺少 <drive> 参数")
		os.Exit(2)
	}
	drive := pos[0]
	outputDir := flags["output"]
	if outputDir == "" {
		fmt.Fprintln(os.Stderr, "scan-and-recover: --output <dir> 必填")
		os.Exit(2)
	}
	mode := flags["mode"]
	if mode == "" {
		mode = "full"
	}
	filterStr := flags["filter"]
	allowSameDisk := flags["allow-same-disk"] == "true"

	engine := recovery.NewEngine()
	defer engine.Shutdown()
	go awaitInterrupt(func() { engine.Stop(); engine.StopRecovery() }, engine)

	// 阶段 1：扫描
	startTime := time.Now()
	lastPct := -1
	scb := recovery.ScanCallbacks{
		OnProgress: func(p types.ScanProgress) {
			if int(p.Percent) > lastPct {
				lastPct = int(p.Percent)
				fmt.Fprintf(os.Stderr, "\r[scan] %3d%% %s files=%d", lastPct, p.Phase, p.FilesFound)
			}
		},
	}
	scanRes, err := engine.Scan(drive, types.ScanMode(mode), scb)
	fmt.Fprintln(os.Stderr)
	dieIf(err, "scan failed")
	fmt.Fprintf(os.Stderr, "✅ 扫描完成: %d 文件，用时 %.1fs\n",
		len(scanRes.Files), time.Since(startTime).Seconds())

	// 阶段 2：按 filter 挑文件
	patterns := splitNonEmpty(filterStr, ",")
	var pickedIDs []string
	for _, f := range scanRes.Files {
		if !matchesAnyPattern(f.FileName, patterns) {
			continue
		}
		pickedIDs = append(pickedIDs, f.ID)
	}
	fmt.Fprintf(os.Stderr, "选中 %d / %d 文件准备恢复\n", len(pickedIDs), len(scanRes.Files))
	if len(pickedIDs) == 0 {
		return
	}

	// 阶段 3：用同一 engine 恢复（source cache 还在内存）
	lastPct = -1
	rcb := recovery.RecoverCallbacks{
		OnProgress: func(p types.RecoveryProgress) {
			pct := 0
			if p.Total > 0 {
				pct = p.Current * 100 / p.Total
			}
			if pct > lastPct {
				lastPct = pct
				fmt.Fprintf(os.Stderr, "\r[recover] %3d%% (%d/%d) %s",
					pct, p.Current, p.Total, p.CurrentFile)
			}
		},
	}
	opts := recovery.RecoverOptions{AllowSameDisk: allowSameDisk}
	res, err := engine.RecoverWithOptions(pickedIDs, outputDir, opts, rcb)
	fmt.Fprintln(os.Stderr)
	dieIf(err, "recover failed")
	fmt.Fprintf(os.Stderr, "✅ 恢复完成: 成功 %d / 部分 %d / 失败 %d / 去重 %d，输出在 %s\n",
		res.Succeeded, res.Partial, res.Failed, res.Duplicates, outputDir)
}

// =============== bitlocker-detect ===============

func cmdBitLockerDetect(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "bitlocker-detect: 缺少 <drive> 参数")
		os.Exit(2)
	}
	drive := args[0]
	r := disk.NewReader(drive)
	dieIf(r.Open(), "open %s", drive)
	defer r.Close()

	// 用 BitLocker scanner 找所有卷
	// （为避免 import bitlocker 包，本 CLI 简化只输出 message — 全功能版可像 GUI 一样调）
	fmt.Fprintln(os.Stderr, "本 CLI bitlocker-detect 只调用 disk reader 验证可读；")
	fmt.Fprintln(os.Stderr, "完整 BitLocker 扫描请用 scan 子命令，metadata 会含加密卷信息。")
	_ = drive
}

// =============== usn-list ===============

func cmdUSNList(args []string) {
	pos, flags := flagsAfter(args)
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "usn-list: 缺少 <drive> 参数")
		os.Exit(2)
	}
	drive := pos[0]
	maxBytes := int64(64 * 1024 * 1024)
	if v := flags["max-bytes"]; v != "" {
		fmt.Sscanf(v, "%d", &maxBytes)
	}

	r := disk.NewReader(drive)
	dieIf(r.Open(), "open %s", drive)
	defer r.Close()

	scanner := ntfs.NewScanner(r)
	boot, err := scanner.ParseBootSector(0)
	dieIf(err, "parse boot sector")

	var entries []*ntfs.MFTEntry
	dieIf(scanner.ScanMFT(context.Background(), boot, 0,
		func(current, total int64) {
			fmt.Fprintf(os.Stderr, "\rscan MFT: %d/%d", current, total)
		},
		func(e *ntfs.MFTEntry) { entries = append(entries, e) },
	), "scan MFT")
	fmt.Fprintln(os.Stderr)
	scanner.RebuildDirectoryTree(entries)

	events, err := ntfs.ScanDeletedFileNames(r, boot, entries, maxBytes)
	dieIf(err, "USN parse")

	// JSON 到 stdout
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{
		"drivePath":     drive,
		"deletedCount":  len(events),
		"deletedFiles":  events,
		"scannedBytes":  maxBytes,
	}); err != nil {
		dieIf(err, "encode")
	}
}

// =============== helpers ===============

func awaitInterrupt(stopFn func(), _ *recovery.Engine) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	fmt.Fprintln(os.Stderr, "\n收到中断信号，停止…")
	stopFn()
}

func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// matchesAnyPattern 简易 glob 匹配：仅支持 *.ext / prefix*。
func matchesAnyPattern(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if matched, _ := filepath.Match(p, name); matched {
			return true
		}
		if strings.HasPrefix(p, "*") && strings.HasSuffix(name, strings.TrimPrefix(p, "*")) {
			return true
		}
	}
	return false
}
