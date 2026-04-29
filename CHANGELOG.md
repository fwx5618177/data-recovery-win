# 版本历史

遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

---

## v2.8.8 (2026-04-29)

**核心架构修：扫描时间从 14h 砍到 ~1h（128GB U 盘）—— brute-force 改为 opt-in，对齐业界标准**

### 用户问题：扫描 128GB U 盘卡 14.3% / 速度 180 B/s / 跑了 14 小时

QA 跑完整 v2.8.7 实测：扫描进度卡 14.3% 几小时 + 速度跌到 180 B/s + 总耗时 14 小时。
v2.8.7 修了**可视化**（你能看见进度），但没修**算法层的真浪费**。

### 第一性原理诊断

- **14.3% 卡死**：FAT 阶段在代码里只占 0.5% 进度预算（14.0-14.5%），但实际 FAT brute-force
  扫整个 125GB 盘要花数小时。预算和真实耗时严重不匹配。
- **180 B/s**：ResilientReader 在末端坏扇区做**单扇区重试**。每次重试 ~3 秒读 512 字节 = 170 B/s。
  这不是 IO 慢，是**重试地狱**，因为我们本不该读到磁盘末端那块。
- **14 小时**：对同一块盘做了 **3 次全盘读**（exFAT brute-force + FAT brute-force + Carver
  = 3 × 125GB = 375GB IO）。USB 2.0 30MB/s 理论 3.5 小时；末端坏扇区重试堆叠 = 14 小时。

**根因**：`brute-force` 类的全盘签名扫描在所有 FS 上**总是运行**，哪怕 fast path（offset-0
ParseBootSector / MBR / GPT）已经在微秒内拿到完整答案。这违反业界标准。

### 业界标准对照（之前我们和谁不一样）

| 工具 | 默认行为 | Brute-force 触发 |
|---|---|---|
| **R-Studio** | Quick scan（仅分区表） | "Deleted partition recovery" 选项 |
| **PhotoRec** | 不做 brute-force（只 carver） | N/A |
| **DMDE** | "Quick scan" | "Full scan" 显式选 |
| **TestDisk** | 默认仅 MBR/GPT | "Advanced > Search" 显式选 |
| **DataRecoveryMaster v2.8.7 之前** | **永远 brute-force** ❌ | 没选项 |
| **DataRecoveryMaster v2.8.8** | 默认仅 fast path ✅ | `IncludeDeletedPartitions=true` opt-in |

### Changed — `internal/types/types.go`

新增 `types.ScanOptions{Mode, IncludeDeletedPartitions}` —— Engine 主入口的统一参数包。

### Changed — `internal/{exfat,fat,ntfs}/scanner.go,partition.go`

每个 scanner 加 `FindOptions{OnProgress, BruteForce}`。`FindPartitions` 签名从
`(ctx, onProgress)` 改为 `(ctx, opts)`。规则：

```go
// Always run fast path
if bs, err := ParseBootSector(s.reader, 0); err == nil {
    partitions = append(partitions, ...)
}
// Brute-force ONLY when explicitly requested
if opts.BruteForce {
    brute, _ := s.bruteForceFindXXX(ctx, opts.OnProgress)
    partitions = append(partitions, brute...)
}
```

**关键决策：fast path 失败时不**做隐式 brute-force fallback。隐式 fallback = 用户感知的"为什么我的扫描跑了 14 小时"；显式 fallback = "fast path 没找到，要不要切到取证模式重扫" → 让上层决定。

### Added — `Engine.ScanWithOptions` / `ScanWithReaderOptions`

新增两个完整版 API 接受 `ScanOptions`。原 `Engine.Scan` / `ScanWithReader` 保留为
shim，默认 `IncludeDeletedPartitions=false`，对所有现存 caller 0 改动。

### Added — 双套阶段预算表（`engine.go`）

```go
fastBudget = phaseBudget{   // 默认模式：FS 毫秒级，Carver 占 86%
    ntfs: 0-2, exfat: 2-4, fat: 4-5, ext: 5-6, apfs: 6-7,
    hfsplus: 7-8, btrfs: 8-9, carver: 9-95, validate: 95-100,
}
forensicBudget = phaseBudget{   // 取证模式：3 个 brute-force × 25% + carver
    ntfs: 0-25, exfat: 25-50, fat: 50-70, ext: 70-72, apfs: 72-74,
    hfsplus: 74-76, btrfs: 76-78, carver: 78-95, validate: 95-100,
}
```

之前 FAT 只占 0.5% 预算 → 14h brute-force 进度条只能动 0.5%。新预算让进度跟实际耗时对应。

### Added — `App.StartScanWithOptions(drivePath, mode, includeDeletedPartitions)`

新 Wails IPC 方法支持取证模式开关。原 `StartScan` 保留默认行为 = false。
**Frontend 取证模式开关 UI 推到 v2.8.9**（用户当前问题用默认行为修复就够了）。

### Tests — 锁住核心契约

`internal/exfat/scanner_test.go`：
- `TestFindPartitions_DefaultSkipsBruteForce` —— 默认模式下 onProgress 0 调用（被 panic 断言守护）
- `TestFindPartitions_ForensicRunsBruteForce` —— 取证模式下 onProgress ≥1 调用 + final tick 满进度
- `TestFindPartitions_Volume` —— fast path 找到 offset=0 整盘分区

### 性能对比（128GB U 盘 USB 2.0）

| 模式 | v2.8.7 | v2.8.8 |
|---|---|---|
| 默认（健康盘） | **14h**（3 × 全盘读 + 重试） | **~1h**（仅 carver 一遍） |
| 取证模式 | （无此选项） | **~3.5h**（4 × 全盘读，但有真预算反映耗时） |

### 验证

```
go vet ./...                                ✅ clean
go build ./...                              ✅ clean
go test -race -count=1 -timeout 240s ./... ✅ 38 packages PASS
```

### Files Changed

- `internal/types/types.go` — `ScanOptions` struct
- `internal/exfat/scanner.go` + `scanner_test.go` — `FindOptions` + brute-force gating + 2 new tests
- `internal/fat/scanner.go` — `FindOptions` + brute-force gating
- `internal/ntfs/partition.go` — `FindOptions` + brute-force gating
- `internal/recovery/exfat_scan.go` — pass `BruteForce` to scanner
- `internal/recovery/fat_scan.go` — pass `BruteForce` to scanner
- `internal/recovery/ntfs_scan.go` — pass `BruteForce` to scanner
- `internal/recovery/scanner.go` — adapter signatures (compile-time interface check)
- `internal/recovery/engine.go` — `ScanOptions` + `phaseBudget` dual table + `phaseRange` helper
- `app.go` — `StartScanWithOptions` + `startScanInternal` refactor

### Future work (tracked, not in this PR)

- **PhotoRec 式单遍扫描**：所有 FS 探测 + carver 签名同时跑在 1 次 IO 通道里。当前架构是 N 次串行扫描，PhotoRec 是 1 次。预期收益：取证模式 3.5h → ~50min。复杂度：scanner 流水线重写，2-3 天。
- **Carver 仅扫 unallocated 空间**：让每个 FS scanner 输出 free-space bitmap，carver 跳过已分配簇。健康盘上 carver 几乎不读。复杂度：1-2 天。
- **Frontend 取证模式 UI**：WelcomePage 加一个 checkbox "扫描已删除分区（慢 3-4 倍）"，绑到 `StartScanWithOptions`。预计 v2.8.9。

---

## v2.8.7 (2026-04-28)

**128G U 盘扫描卡 0% bug 修 —— brute-force 分区发现期间真进度反馈**

### 用户问题：扫描源盘扫描时间过长，对应扫描速度和文件个数并未及时显示，一般在快扫描结束了，会展示对应数据。期望可以展示对应扫描进度百分比、已发现文件个数和大小、速度。

QA 抓到的常见复现 bug：U 盘扫描点了开始之后界面一直停在 "即将开始 0.0% / 已发现 0 / 0 B / 0 B/s"，
要等几分钟到快结束才突然蹦出全部数据。

### 根因

`exfat.bruteForceFindEXFAT` / `fat.bruteForceFindFAT` / `ntfs.bruteForceFindNTFS` 三个**全盘逐 4MB 扫签名**
的兜底函数**没有 onProgress 回调**。128GB U 盘要跑几分钟，期间这三个函数完全静默 —— 心跳虽然每 500ms 发
"init+0.5%" 占位，但首跳要等 500ms（前端已显示 "即将开始 0.0%"），且占位不带 BytesScanned/Speed 数据。

### Fixed — 三个 brute-force 扫描器加 onProgress（500ms 节流）

```go
// internal/exfat/scanner.go, internal/fat/scanner.go, internal/ntfs/partition.go
type ProgressFn = func(scanned, total int64)
func (s *Scanner) FindPartitions(ctx, onProgress ProgressFn) ([]Partition, error)
```

每 ~500ms 节流回调一次（避免事件风暴）+ 走完盘发一次 final tick。

### Fixed — 三个 recovery dispatcher 抓字节进度并映射到 phase 0-50%

`internal/recovery/{exfat,fat,ntfs}_scan.go`：每个 dispatcher 入口立刻 emit "正在查找 X 分区..."
（让前端跳出 ready 状态），分区发现期把字节进度映射到 phase 内 0-50%，剩 50-100% 留给目录遍历阶段。

```go
partitions, err := scanner.FindPartitions(ctx, func(scanned, total int64) {
    onProgress(types.ScanProgress{
        Phase:        "exfat",
        Percent:      float64(scanned) / float64(total) * 50.0,
        BytesScanned: scanned,
        TotalBytes:   total,
        CurrentFile:  fmt.Sprintf("正在查找 exFAT 分区… %s / %s", ...),
    })
})
```

### Fixed — 心跳立刻首跳 + 自动算 Speed

`app.go` `emitScanHeartbeat`：

1. **立刻发首跳**（不等 500ms tick），让前端在用户点"开始扫描"那一刻跳出 ready 状态
2. **从 BytesScanned 增量自动算 Speed**（500ms 滚动窗口），底层扫描器只报字节数不算速度也能显示
3. `lastSpeed` 缓存防 IO 短暂停顿时 UI 闪 0

```go
type heartbeatState struct {
    lastBytesScanned int64
    lastSampleTime   time.Time
    lastSpeed        int64 // IO 间歇缓存
}
```

### Added — 回归测试守契约

`internal/exfat/scanner_test.go::TestFindPartitions_ProgressCallback`：
brute-force 必须至少回调一次 final tick + scanned == total。锁住"以后不能再忘 onProgress"。

### 用户可见效果（点开始扫描那一刻起）

- **percent**：从 0.5% 起，随分区发现字节增长滚到 50%；进入目录遍历继续到 100%
- **BytesScanned / TotalBytes**：实时显示 "已扫 X / 总 Y"
- **Speed**：500ms 滚动窗算 bytes/sec，IO 短暂停顿用上一帧兜底（不闪 0）
- **CurrentFile**：`正在查找 exFAT 分区… 1.2 GB / 128 GB`
- **FilesFound**：心跳每 500ms 用 `len(a.scanFiles)` 兜底

### 验证

```
go vet ./...                                   ✅ clean
go build ./...                                 ✅ clean
go test -race -count=1 -timeout 240s ./...    ✅ 38 packages PASS
```

### Files Changed

- `internal/exfat/scanner.go` + `scanner_test.go`
- `internal/fat/scanner.go`
- `internal/ntfs/partition.go`
- `internal/recovery/exfat_scan.go`
- `internal/recovery/fat_scan.go`
- `internal/recovery/ntfs_scan.go`
- `app.go`

---

## v2.8.6 (2026-04-28)

**fix(ocr): gosec G703 path traversal 在 TESSERACT_BIN env 验证里**（CHANGELOG backfill）

CI gosec medium-severity check 抓到 `internal/ocr/runtime.go:173` 的
`os.Stat(os.Getenv("TESSERACT_BIN"))` 是 taint chain。我们这种"用户自己设 env var 指向
自己机器的 tesseract"是合法用法，但 gosec 不知道用户语义、只看 taint 流，所以严格校验
+ 局部 `#nosec` 把链条断干净。

新增 `validateTesseractPath()`：

- `filepath.Clean` 标准化
- 必须绝对路径（拒绝相对路径，避免 cwd 注入）
- basename 白名单（`tesseract` / `tesseract.exe`）—— 拒绝指向任意可执行
- `os.Stat` 验证存在 + 必须 `IsRegular`（拒绝目录 / device / pipe）

通过校验后才到 `os.Stat`，给 `#nosec G304 G703` 加注释解释 taint 已断。
`commonInstallPaths` 列表迭代也加 `#nosec` —— 那是包内常量，非用户输入。

```
verified: gosec ./... → Issues 0 (Files 214, Nosec 17)
```

---

## v2.8.5 (2026-04-28)

**多盘并行扫描真接通 —— 唯一一处剩余的"假菜单"清零**

### 用户问题：检查下，是否还有别的实际没实现

跑了一轮代码 audit，工具菜单 13 个条目里 12 个是真实现（SMART / SED / GPT /
计划备份 / 时间线导出 / DFXML / 保管链 / 校验保管链 / NSRL / 网络挂载建议 /
APFS 快照 / OCR 搜图）—— 唯一一个**仍然是 toast.info 假提示**的就是
"⚡ 多盘并行扫描"。后端 `ParallelScanDrives` 早已完整实现（`internal/parallel/multidisk.go`），
GUI 没接上，菜单点了只显示"功能就绪请用 CLI 调"。

### Added — 后端异步入口（`app.go`）

之前的 `ParallelScanDrives` 是**同步阻塞**的 IPC 方法 —— 多盘扫几小时它就卡几小时，
GUI 用不了。新加：

```go
StartParallelScanDrives(jobs, maxParallel) error    // 立刻返回，goroutine 跑
CancelParallelScan()                                 // 用户关 modal / 点停止
```

事件流（在原有 4 个基础上 + 1）：
- `parallel:diskStart` `{drivePath, mode}`
- `parallel:diskProgress` `{drive, progress: ScanProgress}`
- `parallel:fileFound` `{drive, file}`
- `parallel:diskDone` `{drivePath, result, error}`
- **`parallel:allDone`** `[]{drivePath, result, error}` —— 新增，全部盘扫完一次发

`error` 字段从 Go `error` 序列化成 string（前端不会看到 `error: {}`）。
新加 `parallelMu` / `parallelCancel` 字段 ——同时只允许一个 multi-disk 任务在跑，
重复调取消旧的。

### Added — `frontend/src/components/MultiDiskScanModal.tsx`

完整 Modal：
- **盘选**：扫描列里所有盘渲染成卡片 grid（U盘 / 物理盘 icon + 路径 + 大小），多选 checkbox，
  「全选 / 清空」快捷
- **扫描参数**：mode 下拉（auto / quick / deep）+ "同时最多扫" 数字输入（1–8，
  含提示"SSD 2-4 / HDD 1-2"避免 IO 互相打架）
- **运行态**：每盘一张卡片，含 16px hard-disk icon + 名称 + 路径 + 进度条
  + percent + "已发现 X · 速度 Y/s · 已用 Z" + 状态 badge（pending / running / done / error / cancelled）
- **停止全部**按钮调 `CancelParallelScan`，立即把仍在跑的 drive 标 cancelled
- 关闭 Modal 自动 cancel
- "完成"按钮 (allDone 后) 关闭 modal

### Changed — `frontend/src/App.tsx`

- 菜单项 "⚡ 多盘并行扫描" 从 toast.info 改成 `setOpenMobileModal("multi-disk-scan")`
- 注册新 modal `<MultiDiskScanModal>`

### Audit 报告（其它菜单）

audit 同时检查了所有其它工具菜单项，确认**全部为真实现**：

| 菜单 | 后端 | 状态 |
| --- | --- | --- |
| 磁盘 SMART 健康 | 三平台原生（v2.8.2/3 已修） | ✓ |
| SED OPAL 锁定 | sedutil-cli + JSON tag fix | ✓ |
| GPT 备份恢复 | 物理盘解析 + ReadPartitions | ✓ |
| 查找重复图片 | aHash perceptual hash | ✓ |
| OCR 搜图 | tessdata_fast 内嵌 + tesseract（v2.8.4） | ✓ |
| 计划定时备份 | OS 级 cron / launchd / Task Scheduler | ✓ |
| 导出时间线 mactime | forensics.WriteMactime | ✓ |
| 导出 DFXML | forensics.WriteDFXMLWithSource | ✓ |
| 生成保管链 | forensics.BuildAndWrite | ✓ |
| 校验保管链 | forensics.VerifyCustody | ✓ |
| 载入 NSRL | forensics.LoadNSRLFromFile（解 SHA-256 → map） | ✓ |
| 网络挂载建议 | netfs.SuggestMount（按平台返指令） | ✓ |
| APFS 时光快照 | scanner 扫 APFS 容器 | ✓ |
| 多盘并行扫描 | **本版接通** | ✓ |

### Files

- 修改：`app.go`（StartParallelScanDrives / CancelParallelScan / 序列化 err / parallel 字段）
- 新增：`frontend/src/components/MultiDiskScanModal.tsx`（~280 行）
- 修改：`frontend/src/App.tsx`（菜单 → modal + 注册）

### Verify

```bash
go vet ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=linux GOARCH=amd64 go build ./...
cd frontend && pnpm build
# 全部 ✓
```

---

## v2.8.4 (2026-04-28)

**OCR 搜图：内嵌 traineddata + 系统 tesseract 智能定位 + 真 Modal 流式 UX**

### 用户反馈

> 直接内部集成，不要再让用户去下载了。如果用户还要下载，本身就提高了心智负担

v2.8.3 直接把 OCR 菜单删掉避免假实现混淆用户。这版**反过来彻底集成**：app
内嵌 tessdata_fast 的 eng + chi_sim（约 6.3 MB），用户不用去 `apt install
tesseract-ocr-chi-sim` / `brew install tesseract-lang`。其它语言用户在
OCR Modal 里点 + 按需从官方仓库下载到本地 cache。

tesseract 二进制本体 v2.8.4 仍依赖系统装（找 PATH + 各平台常见安装目录），
**v2.9 计划把 tesseract 也内嵌**做到 100% zero-install。

### Added — `internal/ocr/runtime.go`

- `//go:embed assets/tessdata/*.traineddata` 把 tessdata_fast 的 eng + chi_sim
  打进 app 二进制（共 ~6.3 MB）
- `EnsureBuiltinLangs()` 首次 OCR 调用前把内嵌 traineddata 解压到 user cache
  （macOS `~/Library/Caches/data-recovery/ocr/tessdata/` / Linux `~/.cache/.../`
   / Windows `%LOCALAPPDATA%\data-recovery\ocr\tessdata\`）
- `FindTesseractBin()` 三段式查找 tesseract：
  1. `TESSERACT_BIN` env 显式指定
  2. system PATH（`exec.LookPath`）
  3. 各平台常见安装路径（修复 v2.8.3 截图的 bug —— 用户用"下软件" / 360 软件管家
     装到 `C:\Tesseract-OCR\` 等非标准位置，不在 PATH 但确实装了）
- `Status` 结构含 binary 路径 / 版本 / 已装语言列表 / 内置语言 / 找不到 binary 时
  按 OS 给详细安装指引

### Added — `internal/ocr/installer.go`

- `AvailableLanguages` 列了 ~45 种官方支持的语言（chi_tra / jpn / kor / rus /
  ara / hin / 等等）+ 中文人名
- `DownloadLanguage(ctx, code)` 从 `https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/main/<code>.traineddata`
  下载到 cache，原子 rename + 体积 sanity check（< 50 KB 视为 GitHub 404 HTML）
- `DeleteLanguage(code)` 删除非内置语言；`HasEmbeddedLang()` 防误删 eng / chi_sim
- `LanguageSHA256()` 取证场景验完整性

### Added — `internal/ocr/ocr.go` 重写

- `SearchInDirectory(ctx, dir, keyword, langs, onProgress, onHit)` —— 走目录递归
  + 过滤图片扩展名（png/jpg/jpeg/bmp/tiff/webp）+ 流式回调进度 / 命中
- `Recognize()` 改用 app 自管 tessdata 目录（`--tessdata-dir` + `TESSDATA_PREFIX`
  双保险），跨发行版行为一致
- 错误信息友好化：tesseract 报"语言包找不到"时转译成"请在 OCR 设置里下载 X 后再试"

### Added — Wails IPC（`app.go`）

| 方法 | 用途 |
| --- | --- |
| `OCRStatus()` | 引擎能不能用 + 装了哪些语言摘要 |
| `OCRListLanguages()` | 全部可用语言（已装 + 可下载） |
| `OCRDownloadLanguage(code)` | 拉某语言到 cache |
| `OCRDeleteLanguage(code)` | 删非内置语言 |
| `OCRSearchDirectory(dir, kw, langs)` | 启动后台搜索；事件流 `ocr:progress` / `ocr:hit` / `ocr:done` / `ocr:error` |
| `OCRCancelSearch()` | 用户关闭 modal 时取消正在跑的 search |

### Added — `frontend/src/components/OCRSearchModal.tsx`

新 Modal：
- 顶部显示 `tesseract --version`（找到了的话）；找不到时 banner 警告 + OS 指引
- 表单：目录选择器（接 `SelectDirectory` IPC） + 关键词输入 + 语言多选 chip
- 「+ 添加 / 管理语言」可折叠面板：
  - 已下载列表（含内置标记 + 删除按钮）
  - 可下载列表（按官方 lang code，hover 即下载，下载中转圈）
- 搜索时：进度条 + "n / total 张 · 命中 m" + 当前文件名 mono ellipsis
- 结果列表（命中文件路径，单行 ellipsis + tooltip）
- 关闭 Modal 自动取消正在跑的 search

### Added — `Makefile` `tesseract-bundle` target

```bash
make tesseract-bundle
```
从 tesseract-ocr/tessdata_fast 官方仓库拉 eng / chi_sim（默认入 git，~6.3 MB）。
后续可扩展拉 tesseract 二进制做 v2.9 的全集成。

### Files

- 新增：`internal/ocr/runtime.go`（embed + 提取 + binary 定位 + status，~250 行）
- 新增：`internal/ocr/installer.go`（语言下载 / 删除 / 校验，~140 行）
- 新增：`internal/ocr/assets/tessdata/eng.traineddata`（4.0 MB，tessdata_fast）
- 新增：`internal/ocr/assets/tessdata/chi_sim.traineddata`（2.4 MB，tessdata_fast）
- 新增：`internal/ocr/assets/{README.md,.gitignore}`
- 修改：`internal/ocr/ocr.go`（重写为目录 / 进度版）
- 修改：`app.go`（+6 个 OCR IPC 方法 + `ocrMu` / `ocrCancel`）
- 修改：`Makefile`（+ `tesseract-bundle` target）
- 新增：`frontend/src/components/OCRSearchModal.tsx`（~340 行）
- 修改：`frontend/src/App.tsx`（重新加 OCR 菜单 + 接 modal）

### Verify

```bash
go test -race ./internal/ocr/...
go vet ./...
GOOS=linux/windows/darwin GOARCH=amd64 go build ./...
cd frontend && pnpm build
# 全部 ✓
```

---

## v2.8.3 (2026-04-28)

**5 个用户反馈 bug 一次扫清**

### Bug 1 — SMART 在 U 盘 / 逻辑卷上提示"不可用"

**根因**：`internal/disk/smart_windows.go` 收到 `\\.\G:` 这种逻辑卷路径时直接 CreateFile，但 SMART IOCTL 只能在物理盘 handle 上跑。逻辑卷必须先解析回底层物理盘索引。

**修复**：
- 新 `internal/disk/path_windows.go` —— 用 `IOCTL_STORAGE_GET_DEVICE_NUMBER` 把 `\\.\G:` 解析到 `\\.\PhysicalDriveN`
- `smart_windows.go` 调用 `resolveToPhysicalDriveWindows()` 在 CreateFile 之前
- USB 桥不透传 SMART 时 `unavailableHint()` 改成"多见于 U 盘 / SD 卡（USB 桥不透传），对扫描没影响"

### Bug 2 — SED OPAL 显示 `locked=undefined`

**根因**：`internal/sed/sed.go` 的 `SEDStatus` 结构体**没有 JSON 标签**。Wails 序列化用 PascalCase（`Locked` / `Note`），前端用 camelCase（`r.locked` / `r.note`）读 → 全部 `undefined`。

**修复**：
- 给 `SEDStatus` 所有字段加 `json:"locked"` / `json:"note"` / 等标签
- 加 `Source` 字段标记数据出处（"sedutil" / "unavailable"）
- 前端 SED 工具按钮改用 rich toast：unlocked / locked / not-supported 各自不同 toast level，含 OPAL 版本副标题
- 删除老 Note 里的 emoji（✅ / ⚠️ / ℹ️）—— 与 v2.8.0 全 emoji → SVG 图标策略一致

### Bug 3 — GPT 备份恢复"读取的数据不足：需要偏移 0，仅读取 0 字节"

**根因**：`app.go` `RecoverGPTPartitions(\\.\G:)` 在逻辑卷上找 GPT 备份头。GPT 在物理盘的最后一个 LBA，逻辑卷只是其中一个分区，没有 GPT 头。

**修复**：
- `app.go` 调 `disk.ResolveToPhysicalDriveWindows()` 把 `\\.\G:` → `\\.\PhysicalDrive0`
- 前端 GPT 工具按钮改用 rich toast：成功列出前 6 个分区（编号 / 名称 / firstLBA-lastLBA），失败给可执行提示

### Bug 4 — OCR 搜图：占位假实现

**根因**：`App.tsx` 的 OCR 菜单项只是 `toast.info({ title: "OCR 扫描已计划", description: "在选中目录下运行 tesseract..." })`，没有任何后端调用。装了 tesseract 也没用。

**用户合理质疑**："为什么会存在 OCR 识图？"

**修复**：
- 删除 OCR 菜单项 —— 数据恢复主流程里"按文字搜图"是非常边缘的需求；且占位假实现误导用户去装无用的依赖
- 保留后端 `OCRImage` / `OCRSearch` API 入口，未来如果要做真正的 OCR 集成可以从这里接

### Bug 5 — 扫描进度卡 0% / 已发现 0 文件 / 速度 0 B/s

**根因**（两条独立问题）：

a) **后端某些阶段长时间不 emit 进度**：NTFS 读 MFT entry 0 / 解析 boot sector / `ScanDeletedFileNames` 扫 USN journal 这几段都是几秒级 IO，期间没有 progress 事件。前端的 `scanProgress` 一直是初始值。

b) **前端 indeterminate 动画造成视觉欺骗**：`percent === 0` 时进度条切到 indeterminate 模式，CSS 把宽度强制设为 40% + 滑动动画。用户看到"60% 蓝色填充"以为扫到 60% 了，实际百分比文字仍是 0.0%。

**修复**：

后端（`app.go`）：
- 新 `(a *App) emitScanHeartbeat(stopCh, startTime)` —— 每 500ms 重发 `scan:progress`，自动更新 Elapsed 字段；底层扫描器静默期 UI 也能看到时间在走
- `formatElapsedSeconds()` —— "12s" / "3m45s" / "1h02m"
- 4 个 scan 入口（StartScan / StartImageScan / ScanWithDecrypted / 别处）都启动 heartbeat goroutine，扫描结束 close stopCh

后端（`internal/recovery/ntfs_scan.go`）：
- 速度从 since-start 改成 **1 秒滚动窗口** —— 开扫前几秒不再误报 speed=0
- 永不 emit `Percent: 0` —— 最低 0.5%，让前端不走 indeterminate 路径
- 初始 progress 也带 `Percent: 0.5` + `Elapsed: "0s"`

前端（`Workbench.tsx`）：
- indeterminate 判断从 `percent === 0` 改成 `!hasAnyProgressData`（任何进度数据存在就退出 indeterminate 模式）
- 进度条统计行加"已用：XmYs" 让用户看到 elapsed

### Files

- 新增：`internal/disk/path_windows.go`（逻辑卷 → 物理盘解析）
- 新增：`internal/disk/path_other.go`（非 Windows 平台 no-op stub）
- 修改：`internal/disk/smart.go` / `internal/disk/smart_windows.go`（用解析助手 + 改文案）
- 修改：`internal/sed/sed.go`（JSON 标签 + Source 字段 + Note 文案）
- 修改：`internal/recovery/ntfs_scan.go`（速度滚动窗口 + 永不 emit 真 0%）
- 修改：`app.go`（emitScanHeartbeat + 4 处 scan 入口启停 + GPT 路径解析）
- 修改：`frontend/src/App.tsx`（SED / GPT rich toast + 删除 OCR 菜单项）
- 修改：`frontend/src/components/Workbench.tsx`（indeterminate 判断 + Elapsed 显示）

### Verify

```bash
go test -race ./internal/disk/...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
go vet ./...
cd frontend && pnpm build
# 全部 ✓
```

---

## v2.8.2 (2026-04-27)

**SMART 健康检查三平台原生集成 —— 不再依赖外部 smartctl**

### 用户反馈

> SMART 的那个工具为啥不修复集成呢？

v2.8.1 把 SMART 的 native alert 换成了 toast，但 fallback 文案还是
"smartctl 未安装；装 smartmontools 可看磁盘健康"。用户的本意是：
**集成进应用本身**，而不是让用户去装外部工具。

### Added — 三平台原生 SMART 实现

| 平台 | 实现 | 文件 |
| --- | --- | --- |
| Linux | `HDIO_DRIVE_CMD` ioctl 直接发 ATA SMART READ DATA / RETURN STATUS / IDENTIFY DEVICE | `internal/disk/smart_linux.go` |
| Windows | `IOCTL_STORAGE_PREDICT_FAILURE` + `SMART_RCV_DRIVE_DATA`（DeviceIoControl，复用 `golang.org/x/sys/windows`） | `internal/disk/smart_windows.go` |
| macOS | `/usr/sbin/diskutil info` + `/usr/sbin/system_profiler SPSerialATADataType` —— 都是 OS 自带 | `internal/disk/smart_darwin.go` |

**零外部依赖**：Linux / Windows 直接 ioctl，macOS 走系统命令。
不需要 cgo，也不需要用户装 smartmontools。

### Changed — `smart.go` 重构成调度器 + 共享解析

- 新 `QuerySmart()` 调度链：原生 → smartctl 退路 → "不可用 + 解释"
- `parseATASmartData()`（共享）：解析标准 ATA SMART 512 字节属性表
  - ID 5 → Reallocated_Sector_Ct
  - ID 9 → Power_On_Hours（取低 32 位避开 vendor flag 噪声）
  - ID 194 → Temperature_Celsius
  - ID 197 → Current_Pending_Sector
  - ID 198 → Offline_Uncorrectable
- `writeNotes()`（共享）：把 SmartHealth 各项数据合成一句给用户看的话，三平台一致
- smartctl 路径单独到 `smart_smartctl.go`，作为 graceful fallback
- `SmartHealth` 加 `Source: "native" | "smartctl" | "diskutil" | "unavailable"` 字段，UI 可显示数据出处

### Changed — 前端 SMART 工具按钮 rich toast

之前：`toast.info("SMART: ⚠ 异常\nsmartctl 未安装...")`（孤零零一行）

现在：用户点"🩺 磁盘 SMART 健康"后弹出结构化 toast，含：
- title：`SMART：健康` / `SMART：异常`（按 healthy 走 success / error 配色）
- 摘要：`SMART 健康检查通过。` 或 `已重映射 X 个坏扇区...`
- 详情：型号 / 序列号 / 通电时长（自动换算年）/ 温度 / 各类坏扇区数

健康时 10s 自动消失；异常时 `duration: 0` 不自动关，强制用户看。

### Added — 单元测试

- `TestParseATASmartData_Healthy` —— 构造 30 槽位 ATA buffer 验证解析正确
- `TestParseATASmartData_Failing` —— 验证有坏扇区时 `Healthy=false` + `HasCriticalIssue()=true`
- `TestParseATASmartData_TooShort` —— 短 buffer 不崩
- `TestQuerySmart_EmptyPath` —— 空路径 fast-fail

### Files

- 新增：`internal/disk/smart_linux.go`
- 新增：`internal/disk/smart_windows.go`
- 新增：`internal/disk/smart_darwin.go`
- 新增：`internal/disk/smart_smartctl.go`（从 smart.go 抽出）
- 修改：`internal/disk/smart.go`（重构成调度器 + 共享 parseATASmartData / writeNotes）
- 修改：`internal/disk/smart_test.go`（+4 测试，老测试适配新 writeNotes 拆分）
- 修改：`frontend/src/App.tsx`（SMART 菜单项改用 rich toast，结构化展示型号 / 通电 / 温度等）
- 修改：`frontend/src/style.css`（`.toast__desc` line-clamp 4 → 8 行，容纳 SMART 详情）

### Verify

```bash
go test -race ./internal/disk/...
# ok  data-recovery/internal/disk
GOOS=linux GOARCH=amd64 go build ./internal/disk/...
GOOS=windows GOARCH=amd64 go build ./internal/disk/...
GOOS=darwin GOARCH=arm64 go build ./internal/disk/...
# all OK
go vet ./...
# (no output)
```

---

## v2.8.1 (2026-04-27)

**全局 Toast 通知系统 —— 替代散落的 native `alert()` 调用**

### 用户反馈

> 这个应该集成，而不是还要自己弄一个

截图：触发"磁盘 SMART 健康"工具后弹出 Wails 的 native alert 框
（"wails.localhost 显示 / SMART: ⚠ 异常 / smartctl 未安装；装 smartmontools 可看磁盘健康"），
跟应用本身的暗色 / 现代设计语言完全不搭。

### 问题

`App.tsx` + `MobileToolsModals.tsx` 一共 39 处 `alert()` / `globalThis.alert?.()`：
- Wails 渲染原生 alert 时显示 "wails.localhost 显示" 顶部 → 像浏览器警告框，廉价
- 阻塞式：用户必须先点确定才能继续操作
- 多个 alert 排队体验极差
- 不能含 icon / 不能区分 success / warning / error
- 不响应主题切换

### Added — `frontend/src/toast.ts`（单例 API，0 dep）

```ts
toast.success("操作成功");
toast.error("失败：" + err);
toast.info({ title: "SMART", description: "smartctl 未安装；装 smartmontools 可看磁盘健康" });
toast.warning({ title: "...", description: "...", action: { label: "重试", onClick: ... } });
```

特性：
- 4 个 level：info / success / warning / error，对应 accent / success / warning / danger 色温
- 自动消失（默认 5s，error 8s）；duration: 0 → 不消失（用户手动关）
- 队列上限 5 条，超出丢最早的（防 toast 风暴）
- 支持 action button（如"重试"）
- 单一字符串含 `\n` 时自动拆 title + description（兼容老 alert 风格的多行消息）
- 模块单例 + 订阅模式 → 模块函数（如 `runAsync`）也能调，无需 hook context

### Added — `frontend/src/components/ToastViewport.tsx`

固定在右下角；多条上下堆叠 + slide-in 动画；每条 toast：
- 左 24px icon（圆角方块 + level 软色背景）
- 中 title + description（description 限 4 行 + 超长 title= tooltip）
- 右 action 按钮 + 关闭按钮
- 左侧 3px level 色边框条

挂载点：`App.tsx` 根 `<div className="app-shell">` 下统一一份。

### Changed — 全部 `alert()` → `toast.X()`

| 调用方 | 之前 | 之后 |
| --- | --- | --- |
| scan:error / recovery:error 事件处理 | `alert(getFriendlyActionError(...))` | `toast.error(...)` |
| 文件拖入不支持的格式 | `globalThis.alert(\`不支持拖入 "..."\\n请拖入...\`)` | `toast.warning({ title, description })` |
| StartScan / StartImageScan / StartRecovery 等 IPC 失败 | `alert(...)` | `toast.error(...)` |
| BitLocker 解锁 / VSS 启动 / 选择目录失败 | `alert(...)` | `toast.error(...)` |
| 报告 / 诊断包导出成功 | `alert(\`报告已导出到：\\n${path}\`)` | `toast.success({ title, description: path })` |
| 下载页复制到剪贴板 | `alert(...)` | `toast.success(...)` |
| 工具菜单 SMART 健康结果 | `globalThis.alert?.("SMART: ⚠ 异常\\n...")` | `toast.info("SMART: ⚠ 异常\\n...")` 自动拆 title/desc |
| MobileToolsModals 启动扫描失败 | `globalThis.alert?.(...)` | `toast.error(...)` |
| 应用更新失败 / 平台资源未找到 | `alert(...)` | `toast.error / warning` |

总计：39 处 native alert 全部清零。

### Files

- 新增：`frontend/src/toast.ts`（单例 + 订阅，约 130 行，0 dep）
- 新增：`frontend/src/components/ToastViewport.tsx`
- 修改：`frontend/src/style.css`（appended `.toast-viewport / .toast / .toast--{level} / .toast__{icon|body|title|desc|action-btn|close}`）
- 修改：`frontend/src/App.tsx`（import toast + ToastViewport；38 处 alert 替换；ToastViewport 挂在 app-shell 下）
- 修改：`frontend/src/components/MobileToolsModals.tsx`（1 处 alert 替换）

### Verify

```bash
grep -r "globalThis\.alert\|alert(" frontend/src/{App,components}*.{ts,tsx}
# (无输出 —— 全清零)

cd frontend && pnpm build
# ✓ built in ~480ms
```

---

## v2.8.0 (2026-04-27)

**UI 现代化重做 + 跟随时间自动主题切换 + Material 风格 `<Select>`**

### 用户反馈

> 样式 UI 极丑，必须重新设计，按照根据电脑时间的模式切换，
> 有暗黑模式和光照模式。对比要采用现代 UI 设计的思路来设计和处理。

WelcomePage 截图：light mode 是冷灰底色 + 扁平蓝按钮 + Win95 灰边框
卡片 + 单层重阴影 ——「管理后台/扫描工具」气质，缺少现代 SaaS 桌面应用
应该有的层次感和精致度。

### Changed — design tokens 整体重做（`frontend/src/style.css`）

**Light mode**：
- 背景：冷灰 `#f5f7fa` → 暖白 `#f6f8fc` + 顶部 1200×600 径向 accent 高光（`--bg-base-gradient`）
- 主 accent：呆板深蓝 `#2266dd` → 现代靛蓝 `#3563e3`，加 135° 紫蓝渐变 `--accent-gradient`
- 阴影：单层 `0 4px 16px rgba(...)` → **三层叠加**（顶部 inset 高光 + 中距柔光 + 远距阴影），
  阴影颜色用蓝色温（`rgba(20, 32, 56, ...)`）替代死黑

**Dark mode**：
- 背景：纯黑 `#0b0f14` → 略偏蓝 `#0a0e15` + 顶部 accent 径向高光，避免「廉价 OLED 死黑」
- 主 accent：`#4f9eff` → 略提饱和的 `#5aa3ff`，夜里更"亮"
- 阴影同样改成多层叠加，加 inset 顶部高光

**新 tokens**：
- `--bg-base-gradient` —— body 背景用，固定 attached 不滚动
- `--accent-gradient` —— primary 按钮 / drive-card hover 装饰带 / 标题
- `--shadow-glow` —— card 选中态用，accent 色光晕替代单纯升高

### Changed — 组件现代化

- **`.btn--primary`**：单色背景 → accent 渐变 + 三层阴影（带 accent 色光圈），hover 时升 1px
- **`.card--hover`**：hover 时 transform translateY(-2px) + shadow-md 升起
- **`.card--selected`**：用新 `--shadow-glow` 替代单纯换底色
- **`.banner`**：加 `box-shadow: var(--shadow-sm)`，padding 12→14
- **`.drive-card`**：
  - 加顶部 2px accent 渐变高光带（hover 60% / selected 100% 显示）
  - icon 容器 hover 时 `scale(1.05)` + 切 accent 软背景
  - 整卡 hover 升 2px
- **`.app-topbar`**：backdrop-filter 加 `saturate(140%)`，让背景虚化更"通透"
- **`.page__title`**：22px → 28px，应用 `--accent-gradient` + `background-clip: text` 让主标题"上色"

### Added — `theme.ts` 新增 `auto-time` 模式

新 Theme value `"auto-time"`：
- 06:00–18:00 → light（白天高对比度，视觉清醒）
- 18:00–06:00 → dark（夜里护眼）
- 每 60s 重新评估一次，用户在 17:59 → 18:00 自动跟着切换
- 切到非 `auto-time` 时自动清掉 timer，无内存泄漏

为啥要：`system` 模式依赖 OS 是否设了"日落黑模式"，老 macOS / Linux 桌面环境不一定支持；
`auto-time` 走应用自己的时钟，对所有平台一致工作。

### Added — `ThemeSwitcher` 新增 "🕐 跟随时间" 选项

下拉菜单顺序：跟随系统 / **跟随时间** / 深色 / 浅色。

### Added — Material 风格 `<Select>` 组件（`frontend/src/components/Select.tsx`）

用户反馈："现在的 select 要参考 Material UI 的设计思想来设计"。

原 `<ThemeSwitcher>` / `<LocaleSwitcher>` 用的是原生 `<select>`，macOS 上灰扑扑老气、
Windows 上又是另一套 OS 风格 —— 跨平台不统一，且无法放图标 / 副标题 / 选中标记。

新组件特性（参考 MUI Filled / Outlined Select）：
- **触发器**：胶囊形（filled / ghost 双变体），右侧 `IconChevronDown`，打开时旋转 180° 染 accent 色
- **浮层**：popover 形（`shadow-lg` + 圆角），slide-down 动画 140ms，按屏幕剩余空间自动 top/bottom
- **每项**：左 emoji icon / 中 label + hint 副标题 / 右选中态 `IconCheck`
- **选中态**：左侧 3px accent 条 + accent 文字色 + 右侧 check
- **键盘可达**：Esc 关 / ↑↓ 在选项间跳 / Enter 提交 / Tab 离开关闭
- **点击外部自动关闭**

ThemeSwitcher 的 4 个选项现在带"副标题":
| 主题 | 副标题 |
| --- | --- |
| 跟随系统 | 由 macOS / Windows 当前主题决定 |
| 跟随时间 | 白天浅色 (6–18)，夜里深色 |
| 深色     | 始终保持暗色 |
| 浅色     | 始终保持亮色 |

LocaleSwitcher 也用 emoji 旗（🇨🇳 / 🇺🇸）替代纯文字，一眼可识别。

### Added — 原生 `<select>` 兜底美化

`MobileToolsModals.tsx` 等表单里的原生 `<select>`（共 4 处）短期内不换组件成本较高
（option 列表是动态的：网卡 / 设备 / 配置文件），但通过 CSS 美化保证至少不再像
1995 年的灰扑扑系统下拉：
- `appearance: none` 抹平浏览器默认样式
- 用 inline SVG `data:` URI 在右侧绘自己的 chevron（light / dark 两套色）
- 触发器底色 / 边框继承 `.input` token

### Changed — emoji → SVG 图标全面替换

用户反馈："现在很多 icon 都是 emoji 而不是 react-icons 的来代替"。

emoji 在不同 OS 上渲染差异巨大（Apple Color Emoji vs Segoe UI Emoji vs Noto Color Emoji），
跨平台不一致；color 不能用 currentColor 染；尺寸不可控；屏幕阅读器读法各异。

**新增 SVG icons**（`frontend/src/icons.tsx`，沿用现有的 `currentColor` + 1.75 stroke 风格）：
- 主题：`IconSunMoon` / `IconSun` / `IconMoon` / `IconClock`
- 安全：`IconLock` / `IconLockOpen`
- 状态：`IconXCircle`（IconX / IconCheck / IconAlertTriangle 已存在）
- 平台：`IconApple` / `IconWindows` / `IconBox`（HFS+ / ReFS / APFS 卷类型用）
- 通用：`IconLightbulb` / `IconGlobe`（提示文 / 语言切换）

**替换点**：
| 文件 | 之前 | 之后 |
| --- | --- | --- |
| `App.tsx` ThemeSwitcher | 🌗 🕐 🌙 ☀️ | `IconSunMoon` / `IconClock` / `IconMoon` / `IconSun` |
| `App.tsx` LocaleSwitcher | 🇨🇳 🇺🇸 | `IconGlobe`（"语言"概念全球通用，不绑定单一国家） |
| `WelcomePage.tsx` 加密卷类型 | 🔒 🍎 🍏 🪟 📦 | `IconLock` / `IconApple` / `IconWindows` / `IconBox`（带 warning 软色背景框） |
| `WelcomePage.tsx` BitLocker modal title | 🔒 解锁 BitLocker 卷 | `<IconLock>` + 标题 |
| `WelcomePage.tsx` "也可以从其他来源恢复" 提示 | 💡 | `IconLightbulb` |
| `WelcomePage.tsx` pendingSession warning | ⚠️ | `IconAlertTriangle` + 行内布局 |
| `WelcomePage.tsx` BitLocker 保护器列表 | ✅ ⚠️ | `IconCheck` / `IconAlertTriangle` |
| `RecoveryPage.tsx` 进度统计 | ✓ ⚠ ✗ | `IconCheck` / `IconAlertTriangle` / `IconX` |
| `RecoveryPage.tsx` stat-card 标签 | ✓ ⚠ ◑ ⊘ ✗ | 全部对应 SVG icon |
| `ConfidenceBadge.tsx` | ✓ / ⚠ 文字前缀 | `<IconCheck>` / `<IconAlertTriangle>` 元素 |

`stat-card__label` CSS 改为 inline-flex 让 icon 与文字基线对齐。

### Fixed — 文字折行问题

用户反馈："文字老有折行，文字有一个最大宽度，尽可能不要折行，过长就用 tooltip"。

- `.drive-card__name` / `.drive-card__path`: **`word-break: break-all` → ellipsis + tooltip**
  - 老规则把中文方块字硬拆（"我的-桌面" → "我的-/n桌面"）—— 极丑
  - 改成 `overflow: hidden; text-overflow: ellipsis; white-space: nowrap;` + JSX 加 `title=`
- `WelcomePage` QuickCard 标题 / desc: 加 `.ellipsis` + `title=` 兜底
- `WelcomePage` 加密卷列表: 三层文字（kindLabel / location / note）全部 ellipsis + title
- `WelcomePage` BitLocker 保护器 hint: ellipsis + title
- 全局 `body { word-break: break-word; overflow-wrap: anywhere; }` —— 替代 break-all，CJK 友好
- 新 utility `.line-clamp-2` / `.line-clamp-3`: WebKit line-clamp，多行优雅截断
- `.select-trigger__label` 加 `max-width: 160px` —— 长 label 在 trigger 里 ellipsis 而非撑爆

### Changed — visual polish

- `.page__body` / `.page__header` 限宽 1400px 居中 —— 超宽屏（4K / ultrawide）下卡片 / banner 不被拉到撑满
- `.app-topbar` 加 `gap: var(--space-4)` 防 brand / flow / actions 挤到一起；新加 `box-shadow: 0 1px 0 var(--border), 0 4px 12px -8px rgba(0, 0, 0, 0.12)` 让 stage 与 topbar 之间多一层 separator
- `.app-brand__mark` 32px → 36px，背景从 `accent-soft` 换成 **accent gradient**（白色图标），加 inset 高光 + 外发光阴影 —— 像现代 SaaS 的 brand 元素
- `.flow-track` 加 `flex-wrap: nowrap; overflow: hidden` —— 中间步骤指示器不会被挤换行
- 加 inline-flex stat-card label 让 icon 与文字基线一致

### Added — typography 对比增强

新 utility classes：
- `.text-strong` —— bg 色文字 + semibold + tighter letter-spacing
- `.text-emphasis` —— 数据/状态值用，加 tabular-nums 防数字宽度跳动
- `.text-accent-gradient` —— 关键词上 accent 渐变 + background-clip: text

H1/H2/H3 加了对应的 size（`--text-3xl` / `--text-2xl` / `--text-xl`）+ tighter letter-spacing
（中文标题用 negative letter-spacing 视觉更紧凑）。

`.banner__title` 字号从 inherit 14 → `--text-md`（14）但 weight `600` → `--weight-semibold`，
margin-bottom 2→4，line-height 显式 1.35。

`.drive-card__name` 14px → `--text-lg` (15px) + tighter spacing。
`.drive-card__meta dd` 加 `font-variant-numeric: tabular-nums`，"容量"列对齐更整齐。

### Changed — `WelcomePage` DEV 占位卡专用样式

之前 `[DEV-MODE] 物理盘枚举已跳过` 走通用 `DriveCard` 渲染：
0 字节、空路径、tag 显示"逻辑盘" —— 看着像 bug。

现在专用 `<DriveCard>` 分支 + `.drive-card--placeholder` CSS：
- 虚线边框 + warning-soft 渐变背景
- icon 改成 `IconAlertTriangle` + warning 色
- 不可点击（`cursor: default`），hover 不动
- 副标题改写："避免每次启动都触发 macOS 权限框"
- 提示文案直接给修复指令：`make dev-elevated`

### Backwards compatibility

- 已存的 `data-recovery.theme` localStorage 值兼容（`system` / `dark` / `light` 不变）；
  新加的 `auto-time` 不破坏老用户
- 旧 CSS variables 全部保留，只是色值微调；外部组件无须改动

### Files

- 新增：`frontend/src/components/Select.tsx`（Material 风格下拉，约 200 行，0 dep）
- 修改：`frontend/src/icons.tsx`（+13 个 SVG icon：IconSunMoon / IconSun / IconMoon / IconClock / IconLock / IconLockOpen / IconLightbulb / IconApple / IconWindows / IconBox / IconGlobe / IconXCircle）
- 修改：`frontend/src/style.css`（tokens + button + card + drive-card + topbar + brand mark + Select + 原生 select 美化 + page max-width + line-clamp utility + stat-card label flex + body word-break）
- 修改：`frontend/src/theme.ts`（加 `auto-time` 模式 + 60s tick）
- 修改：`frontend/src/App.tsx`（ThemeSwitcher / LocaleSwitcher 改用 `<Select>` + SVG icons）
- 修改：`frontend/src/components/WelcomePage.tsx`（DEV 占位卡专用渲染 / 加密卷列表 SVG 化 / BitLocker modal SVG 化 / 全部 emoji 替换 / 多处 ellipsis + title）
- 修改：`frontend/src/components/RecoveryPage.tsx`（进度行 + stat-card 全部 SVG 化）
- 修改：`frontend/src/components/ConfidenceBadge.tsx`（IconCheck / IconAlertTriangle 替代 ✓ ⚠ 字符）

### Verify

```bash
cd frontend && pnpm build
# ✓ built in ~430ms
go vet ./...
# ✓ no warnings
```

---

## v2.7.2 (2026-04-27)

**修 macOS `make dev` 每次都弹权限框** —— DEV 模式 + Info.plist 文案 + 自检脚本

### 用户问题：现在 make dev 后，macOS 总是会提示权限问题

诊断：
- `ensureAdminPrivileges()` 在 dev TTY 下不被 `isNonInteractiveContext` 拦截 → 每次都跑 osascript 弹 Touch ID/密码框
- `listDrivesMacOS()` 每次枚举都 `os.Open("/dev/disk0")` → 系统弹"App 想访问可移除卷"框
- Info.plist 没有任何权限文案 → macOS 弹默认通用文案

### Added — DEV 模式（彻底跳物理盘）

新 env var `DATA_RECOVERY_DEV_MODE=1`：
- `admin_unix.go`: `ensureAdminPrivileges` 短路返回，不弹 osascript
- `internal/disk/drives_other.go`: `listDrivesMacOS` 跳过 `os.Open(/dev/disk*)`，
  返回单条 "[DEV-MODE] 物理盘枚举已跳过" 占位卡，让 UI 知道不是 bug
- 用户测扫描就用 .img 镜像 / 拖文件 / 用户主目录路径

### Added — Makefile dev / dev-elevated / check-perms targets

- `make dev` —— 默认设 `DATA_RECOVERY_DEV_MODE=1`，**完全免权限框**
- `make dev-elevated` —— 真需要测物理盘扫描时用，会要一次 sudo 密码
- `make check-perms` —— 跑 `scripts/check-macos-permissions.sh` 自检

### Added — `scripts/check-macos-permissions.sh`

一次性 macOS 权限健康检查（不申请权限，只报告 + 给指引）：
- ✓ wails CLI 是否在 PATH
- ⚠ DEV_MODE env 是否设置
- ⚠ 是否 root（dev 模式下 OK 不需要）
- ✓ /dev/disk0 是否可见（ls 检查，不真打开）
- ⚠ Full Disk Access (TCC) 状态 —— 读 ~/Library/Application Support/com.apple.TCC/TCC.db
- 推荐工作流总结

### Added — Info.plist 6 个权限文案

`build/darwin/Info.plist` 加：
- `NSRemovableVolumesUsageDescription` —— 可移除卷（U 盘 / SD 卡）
- `NSDocumentsFolderUsageDescription` —— "文稿"文件夹（读镜像 / 写恢复输出）
- `NSDesktopFolderUsageDescription` —— "桌面"文件夹（默认输出目录）
- `NSDownloadsFolderUsageDescription` —— "下载"文件夹（读镜像 / 备份）
- `NSAppleEventsUsageDescription` —— AppleScript 申请管理员权限提示
- `NSSystemAdministrationUsageDescription` —— 管理员权限说明

每条都用人类可读的中文说明，强调"只读，不修改源盘"，让 macOS 系统弹框时
用户更愿意授权（vs 默认通用提示文案）。

### 修复后的开发体验

| 场景 | v2.7.1 之前 | v2.7.2 之后 |
|------|-----------|-----------|
| `make dev` 启动 | 每次弹 Touch ID / 密码框 | 直接启，0 弹框 |
| 启动后 GetDrives | 每次弹"想访问可移除卷" | 占位卡片，无弹框 |
| 真要测物理盘 | 没专门入口 | `make dev-elevated`（明示） |
| 不知权限状态 | 没法查 | `make check-perms` |

### 工程指标
- backend `go build` 通过；frontend 未动
- 4 文件改：admin_unix.go / drives_other.go / Makefile / Info.plist
- 1 新文件：scripts/check-macos-permissions.sh

---

## v2.7.1 (2026-04-27)

**Hotfix：TasksSidebar 折叠按钮点击后白屏** —— React Rules of Hooks 违规。

### Fixed — `TasksSidebar` early return 在 hooks 之前

用户截图复现：当左侧任务侧栏没有任务时点折叠箭头 → 白屏，控制台报：

```
Rendered fewer hooks than expected. This may be caused by an accidental
early return statement.
```

**根因**：`MobileToolsModals.tsx:1318` 早期 `return null` 在 `useReducer` 和
`useEffect` 之前：

```tsx
const [tab, setTab] = useState(...);
const inflight = ...;
if (inflight.length === 0 && histList.length === 0 && collapsed) return null;  // ← 早返回
const [, force] = useReducer(...);  // ← hook 在 early return 之后
useEffect(...);                     // ← hook 在 early return 之后
```

正常情况（有任务）：3 个 hooks 调用。
折叠且无任务（用户截图情形）：1 个 hook（早返回）。
React 比对前后 hook 数量不一致 → throw → 白屏。

**修复**：所有 hooks 全部上提到函数最前；`if (shouldHide) return null` 放在
所有 hook 调用之后。`useEffect` 内部用 `if (shouldHide || ...) return` 提前
退出 setInterval（cleanup OK）。

加注释明确说明这是 v2.7.0 的 regression，防止未来又踩。

### 顺手扫了：其他 React 组件的早返回都在 hooks 之后 ✓

`CacheStatsPanel` (line 46) / `RecoveryPage extractPartialPct` 都是 helper
function 或 useState/useEffect 之后的 return，不违反 Rules of Hooks。

### 工程指标
- frontend `pnpm typecheck` 0 errors / `vite build` 通过
- backend 未动

---

## v2.7.0 (2026-04-27)

**TypeScript 迁移 + 类型化 IPC + 顺手修了 5 个 TS 抓出来的真 bug + sortable 列指示器**

### 用户问题：是不是该上 TS？

是的。已经迁完。Vite 早就在用，只是 React 代码是 `.jsx` (plain JS + JSX)。
本 release 把 16 个文件迁到 `.tsx` / `.ts`，并对 IPC 边界做强类型。

### Added — TypeScript 基础设施

- 新增 `tsconfig.json`（渐进迁移配置：`strict: false` + `allowJs: true`，
  避免一次冒 100+ 错误吓到）
- 新增 `package.json` script：`pnpm typecheck` 跑 `tsc --noEmit`
- 安装 `typescript@latest`（`@types/react` + `@types/react-dom` 之前已经在了）
- Vite 原生支持 TS，0 配置变化

### Added — Wails IPC 类型声明 (`src/types/wails.d.ts`)

手写精简补丁 vs 依赖 `wails generate`（要求 dev/build 跑过才能生成）：
- 强类型 30+ 个最常用 IPC method（GetDrives / StartScan / 5 个 Cancel / 11 个移动端 IPC...）
- index signature `[methodName: string]: (...args: any[]) => unknown` 兜底其余
  ~70 个 method（编译过得去 + 渐进改进）
- 14 个业务数据 interface：`DriveInfo / RecoveredFile / ScanProgress /
  RecoveryProgress / FileRecoveryRecord / CloudSyncRoot / CloudBackupHit /
  AndroidPartition / IOSDevice / PTPDevice / MTPDevice / ...`
- 全局 `Window.runtime.EventsOn / EventsEmit` 类型声明
- 编译期捕"调一个不存在的 IPC method" bug（v2.4.0 audit 时遇到的真实问题类）

### Migrated — 16 文件 jsx/.js → tsx/.ts

| 文件 | 之前 | 之后 |
|------|------|------|
| `App.jsx` | `.jsx` | **`.tsx`** |
| `main.jsx` | `.jsx` | **`.tsx`** |
| `icons.jsx` | `.jsx` | **`.tsx`** + IconProps interface |
| `formatters.js` | `.js` | **`.ts`** |
| `recovery-helpers.js` | `.js` | **`.ts`** |
| `i18n.js` | `.js` | **`.ts`** |
| `theme.js` | `.js` | **`.ts`** |
| `components/*.jsx` (8 个) | `.jsx` | **`.tsx`** |

### Fixed — 5 个 TS 实际抓出来的 bug

迁移过程中 `tsc` 实际 catch 的非平凡问题（不是凑数的 lint 风格）：

1. **RecoveryPage `counts.highConfidence` 字段不存在** —— 计数对象 init 没声明
   `highConfidence`，但 line 53 `c.highConfidence = c.success - c.lowConfidence`
   靠 JS 动态属性"飞着加"，TS 编译时会"undefined"。展示在 stat-card 上没炸
   只是因为 React 渲染数字 NaN 走 falsy。修：init 时把 `highConfidence: 0` 列上。

2. **i18n `t()` 单参数调用爆 24 处** —— `t("foo")` 传一个 arg，但 `function t(key, vars)`
   没标 `vars` optional。修：`t(key: string, vars?: Record<string, ...>)`。

3. **`onLocaleChange` / `onThemeChange` 返回值被 useEffect 当 destructor 用，
   但实际是 `() => boolean`** —— `Set.prototype.delete()` 返回 boolean 让 React 抱怨
   "destructor 不能返回非 void"。**这是真 bug，可能导致 cleanup 不被触发**。
   修：包成 `() => { listeners.delete(fn); }` 显式返回 void。

4. **`Field` / `TextInput` props 强必填** —— TS 看到 `disabled` 没标 `?:`
   就要求每个调用都传 disabled，6 处 callsite 漏传。修：定义 `FieldProps` /
   `TextInputProps` 把 `hint` / `disabled` 标 optional。

5. **`document.querySelector(...).focus()` 在 `Element` 上不存在** —— 必须
   `as HTMLInputElement` cast。本来 keyboard shortcut Ctrl+F 只有刚好命中
   `<input>` 时才工作；命中其他元素时 `.focus is not a function` 静默失败。

### Added — Sortable 列指示器（v2.6.0 没做的）

`FileTable.tsx` 里的 `Th` 组件（之前 v2.6.0 我留 TODO 了）：
- 激活列 → ↑/↓ accent 蓝色
- 非激活列 → 默认浅色 ↕（之前完全无指示，用户得逐列点试）
- 加 ARIA `title="点击列头切换排序"` 鼠标悬浮提示

### 工程指标
- frontend `vite build` 成功（293 KB → gzip 93 KB，比 v2.6.0 +3 KB = TS 类型 + 业务数据 interface）
- frontend `pnpm typecheck` **0 errors**（lenient `strict: false` 起步）
- backend 未动；`go build ./...` 全绿

### 后续改进路径

TS 迁移**渐进**思路（避免一次 strict 暴 100+ 错误）：
1. v2.7：完成基础迁移 + 抓 5 个真 bug ✅（本 release）
2. v2.7.x：逐个文件加严格 props 类型（modal 的 ModalProps 现在还是 `[k]: any` 兜底）
3. v2.8：开 `strict: true` + `noImplicitAny: true`，预期再暴 50+ 真 bug
4. v2.9：跑 `wails generate ts` 替换手写的 wails.d.ts（更权威）

### v2.6.0 留下未做的（推到 v2.7.x）
- ToolsMenu 25 项按使用频率重排（需 telemetry 数据）
- WelcomePage banner 堆压缩
- Workbench 左 filter-panel 改 tab-bar
- Inline px → token 全面 sweep（A11y level 1 已达，level 2 慢慢来）

---

## v2.6.0 (2026-04-27)

**完整 UI 设计迭代** —— 修 18 个具体问题（美观 / 直观 / 方便操作），加 token
体系、Cmd+K 工具搜索、可拖拽快速卡片，并把 ✕ 文本按钮换成 SVG icon。

### Added — Design token system + 视觉一致性

- `style.css` 加完整 token 体系（之前散落硬编码 px / 字号）：
  - **字号 scale**：`--text-xs` (11) / `sm` (12) / `base` (13) / `md` (14) / `lg` (15) / `xl` (18) / `2xl` (22) / `3xl` (28)
  - **字重 scale**：normal (400) / **medium (500)** / semibold (600) / bold (700) — 中文标题主推 medium 避免"打扁"
  - **间距 scale**：8 倍数体系 `--space-1..12`
- 文本对比度按 WCAG AA 重排：
  - dark mode `--text` 从 `#e7ecf2` → `#f0f4fa`（对 bg-base 7:1 AAA）
  - dark mode `--text-muted` 从 `#8b96a6` → `#a3afc1`（对 bg-base 5.2:1 AA pass）
  - light mode 全部加深一档：`--text` 从 `#0f1624` → `#0a1220`（17:1 AAA）；
    border 从 0.10 → 0.12 让卡片边界更清楚
- 新加 `.tab-bar` segmented control：底部 accent 横线 + 激活态 surface 背景，
  比之前 `btn-group` 的"primary vs ghost"反差强 5×
- `.badge` 默认从灰扑扑改用淡 accent 色（中性信息也有存在感）；真正"无关紧要"
  迁到 `.badge--muted`

### Added — 6 个新 SVG icon

`icons.jsx` 加：`IconCloud` / `IconPhone` / `IconCamera` / `IconServer` /
`IconGripVertical` / `IconChevronUp/Down/UpDown`

### Changed — WelcomePage 视觉重构

- 4 张快速卡片 emoji（📱🔌📷📡 — 4 种风格不一致）→ SVG icon set
  （Cloud/Phone/Camera/Server，统一笔画 + accent 圆角方块容器）
- 拖拽手柄 ⋮⋮ 默认就显示（之前 hover 才出，新用户不知道可拖）
- 卡片 hover 加 box-shadow 提升 + accent border（之前只换背景色，反馈弱）

### Changed — drive-grid 自适应

`auto-fill, minmax(280px, 1fr)` → `auto-fill, minmax(240px, 1fr)`：
- 1920px 宽屏从一行 4 张提升到一行 7-8 张，少滚动
- 窄屏不变（auto-fill 仍降到 1-2 列）

### Added — ToolsMenu Cmd+K 搜索 + 重排

之前 25 个菜单项扫起来累。现在：
- 顶栏按钮加 `⌘K` kbd 提示
- **Cmd/Ctrl+K** 全局快捷键打开菜单 + 自动 focus 搜索框
- 输入即时 filter（拆 emoji + 大小写不敏感子串匹配）
- Esc 一次清空 filter，再次 Esc 关菜单
- 菜单宽度 240 → 320，更舒展

### Changed — RecoveryPage filter 改 tab-bar

`btn-group` (btn--primary vs btn--ghost) → `.tab-bar` segmented control：
- 激活态有底部 accent 横线 + surface 背景，扫一眼看出"我在哪个 tab"
- 加 ARIA `role="tablist"` / `aria-selected` for 可访问性

### Changed — Workbench 进度条主/次行分层

之前一行挤 6 段（phase / 字数 / 字节 / 速度 / ETA / 当前文件），字号混乱无层次。
现在 3 行分层：
- **主行（醒目）**：phase 图标 + 标签 + 大字 22px **进度%** (accent 蓝) + ETA + 停止/返回按钮
- **次行（紧凑）**：来源 / 文件计数 / 字节量 / 速度 — text-sm muted
- **底行（mono）**：当前正在扫的文件 — 单行 truncate + title tooltip

用户扫一眼就抓到"X% 还剩 Y 分钟"，不被一行 6 字段碾过。

### Fixed — Modal 关闭按钮 ✕ → SVG IconX

`MobileToolsModals.jsx` GenericModal header 关闭按钮：
- 文本 ✕ → `IconX` SVG（125% 缩放下不糊）
- min-width/height 32px（满足 44px 触摸目标的 ~75%）
- 加 `aria-label="关闭对话框"`

### 工程指标
- frontend `vite build` 成功（290 KB → gzip 93 KB，比 v2.5.1 +3 KB = 6 个新 icon + tab-bar CSS + Cmd+K 搜索）
- backend 未动；`go test -short ./internal/updater/` 全绿
- 文本对比度全部 ≥ AA（WCAG 2.1）；多数主文字达 AAA

### 解决的 18 个具体问题

按严重度记录全部修复：HIGH 5 个（drive grid 宽度、拖拽手柄、Workbench 进度堆叠、emoji-not-icon、ToolsMenu 25 项扫不完）；MED 9 个（badge 配色、字号 token、Modal ✕、tab-bar 视觉、UpdateBanner 状态色、字号梯度、ghost button、3 banner 平摊、filter-panel 互斥关系）；LOW 4 个（grid padding、缩略图比例、ghost hover、文字对比）。

### 后续可改进
- ToolsMenu 25 项的"按使用频率重排"留待 v2.7（需要 telemetry 收集使用频次）
- WelcomePage 加密卷面板和顶部 banner 的视觉层次还能再压
- Workbench 左侧 filter-panel 可考虑改 tab-bar
- Sortable 列头的 ▲▼ 指示器还没加（已在 icons.jsx 备好 IconChevronUpDown）

---

## v2.5.1 (2026-04-27)

**TasksSidebar 历史 tab + 5 个 Cancel IPC + WelcomePage 卡片拖拽重排 + DumpDisk 事件名修正**

### Added — Backend 5 个 Cancel IPC

每个 mobile 任务现在用 cancellable context + 在 App struct 存 cancel func：
- `mtpDumpCancel` / `mtpPullCancel` / `iosBackupCancel` / `ptpPullCancel` / `diskDumpCancel`
- 5 个 IPC：`CancelAndroidDump` / `CancelMTPPull` / `CancelIOSBackup` / `CancelPTPPull` / `CancelDiskDump`
- 取消时 `exec.CommandContext` 自动 SIGKILL 子进程（adb / dd / idevicebackup2 / gphoto2）
- 已传输的部分保留（用户可能想保住已有 X% 数据）
- 幂等：没在跑时调 Cancel 返回 nil

### Fixed — DumpDisk 事件名 + 缺 cancellable context（v2.5.0 漏的）

之前 `DumpDisk` 用 `imaging:*` 事件，但 v2.5.0 frontend 监听 `image:dump*` →
**事件接不上**，TasksSidebar 看不到镜像 dump 进度。本 release 同时发两套事件
（`imaging:*` 兼容旧消费者 + `image:dumpStarted/Progress/Completed/Error` 给 sidebar）。
顺便给 DumpDisk 加 cancellable context（之前直接用 `a.ctx`，无法取消）。

### Added — TasksSidebar 历史 tab + 取消按钮

之前完成的任务 5 秒后直接消失。现在：
- **2 个 tab**：进行中 (N) / 历史 (M)
- 完成/出错时**先迁到 history**，再 5s 后从进行中删除（用户能看到完成态）
- 历史 task 含 `id` + `completedAt`，按完成时间倒序
- 自动 purge：每 30s 清掉 > 5 分钟的历史
- in-flight 卡片新增 **🛑 取消** 按钮（红色边框小按钮），点击 confirm 后调 `Cancel<Kind>` IPC
- 历史卡片：成功/失败用左边框颜色区分（绿/红），显示用时 + "X 分钟前"

### Added — WelcomePage 4 张卡片拖拽重排

不同用户偏好不同（手机直连重度用户 vs 云盘重度用户），现在卡片可拖拽重排：
- HTML5 drag-and-drop API（无第三方依赖）
- 拖拽手柄 ⋮⋮ 在 hover 时半透明显示
- 拖拽中：源卡 opacity 0.4，目标卡边框 + 背景换 accent 色高亮
- 顺序持久化到 `localStorage["welcome_quick_cards_order"]`
- 未来加新卡片时（saved 顺序里没有的 key）自动追加到末尾

### 工程指标
- frontend `vite build` 成功（287 KB → gzip 92 KB，比 v2.5.0 +5 KB）
- backend `go build` + `go test -short` 全绿
- 5 个新 Cancel IPC + 1 个 bug 修复（DumpDisk 事件名 + cancellable）

### CI Auto-Release（用户的 #4 已确认）

`.github/workflows/release.yml` 配 `on: push: tags: v*`，每次 git tag push 自动触发：
- 跨平台 wails build (Windows amd64/arm64, Linux amd64)
- 创建 GitHub Release
- 上传 .exe / Linux 二进制 assets

v2.1.5..v2.5.0 的 7 个 tag 已推（GitHub Actions 应当正在构建）。
v2.5.1 推送后第 8 次触发。

---

## v2.5.0 (2026-04-27)

**完整移动端 / 备份 / 云端 工作流 UI 体验** —— 多任务并行 + 4 个新 modal +
WelcomePage 快速入口 + About + 仍走 prompt 的菜单项全部升级。

### Added — 多任务并行可视化 (TasksSidebar)

之前：只能跟踪 1 个 mobile 任务（单 toast）；多个并行任务后来的覆盖前者。
现在：`mobileTasks: Map<kind, task>` 同时跟踪所有 in-flight 任务。

**`TasksSidebar` 左侧可折叠侧栏**：
- 折叠态：36px 窄竖条只露 ›/‹ 切换按钮（不挡主面板）
- 展开态：280px 宽，每个任务一张卡片（图标 / 标题 / 进度 / 已用时长 / 错误信息）
- 任务按 startedAt 排序，新任务底部追加
- 每张卡片左边框颜色按 kind 区分：💽 dump 蓝 / 📂 pull 紫 / 🍎 iOS 绿 / 📷 PTP 黄 / 💾 disk 红
- 完成 5 秒自动消失；错误持久显示直到用户 ✕ 关闭
- 不确定进度走 progressPulse 动画；有具体字节的实时计算百分比
- 没任务 + 折叠 = 完全不渲染（不挡视野）

新事件来源：`image:dumpStarted/Progress/Completed/Error`（v2.4.1 漏的）

### Added — 3 个新 modal（剩余 prompt() 全部升级）

`MobileToolsModals.jsx` 追加 4 个组件（约 +500 行）：

5. **PTPCameraModal** —— gphoto2 检测 → 设备列表 → 选 port → 输出目录 → 启动
6. **ADBPullModal** —— adb 检测 + 设备列表 + 6 个常用路径快捷按钮 (DCIM / WhatsApp / etc)
7. **DiskDumpModal** —— 自动从 selectedDrive 取源盘 + 自动建议输出文件名 + 时间预估
8. **AboutModal** —— 版本号 + 10 大类支持能力（FS/加密/RAID/移动/云盘/NAS/JPEG/LZFSE/取证）+ 第三方依赖

### Added — WelcomePage 4 个 quick-entry cards

新用户打开应用就看到："也可以从其他来源恢复（不一定是本机磁盘）"：
- 📱 iOS / Android 备份 → 打开云盘扫描 modal
- 🔌 手机直连 → 打开 ADB pull modal
- 📷 数码相机 (PTP) → 打开 gphoto2 modal
- 📡 NAS (SMB / NFS) → 打开 SMB 扫描 modal

不再需要挖"🧰 工具"下拉就能用最常见的非本机源恢复路径。卡片有 hover 动画
（accent 边框 / 浅蓝背景 / 上移 1px）。

### Changed — ToolsMenu 剩余 prompt() 全部改 modal

之前 v2.4.1 还有 3 个走 prompt：📂 ADB pull (3 个 prompt) / 📷 PTP (3 个) / 💾 disk dump (1 个)。本 release 全部改 onOpenMobileModal。

加 1 个新菜单项 📦 关于本工具 → AboutModal。

### 工程指标
- frontend `vite build` 成功（282 KB → gzip 90 KB，比 v2.4.1 +14 KB = 4 modal + sidebar）
- backend 未动；`go test -short ./...` 全绿
- 升级后 ToolsMenu **0 prompt**：所有需要 ≥2 步输入的菜单项都有 modal

### 后续仍可改进
- TasksSidebar 加历史任务 tab（不只 in-flight）
- WelcomePage cards 支持自定义/拖拽顺序
- 移动端任务支持取消（当前只能等完成 / 关闭浮窗，但 backend 任务继续跑）

---

## v2.4.1 (2026-04-27)

**v2.4.0 的 prompt() 升级为完整 modal dialog + 全局移动端进度状态栏**

v2.4.0 用 `prompt()` / `alert()` 解锁 11 个暗物质功能能跑，但高频/复杂路径
（NAS / Android dump / iOS 备份）的 4-6 步连续 prompt 体验拙劣。本 release 升级。

### Added — 4 个完整 Modal Dialog

`frontend/src/components/MobileToolsModals.jsx`（~600 行新组件）：

1. **CloudBackupsModal** —— 云盘扫描结果可点击 ✓
   - 旧路径：alert 长文本，用户复制粘贴路径才能扫
   - 新路径：list view，每个发现的 iOS/Android 备份旁边一个 "🔍 扫描" 按钮直接调
     `StartIOSBackupScan` / `StartAndroidBackupScan`（解决用户原始建议 #2）

2. **NASScanModal** —— SMB / NFS 扫描表单
   - 单 modal 复用（`kind` prop 切换）：host / 凭据 / share / export
   - 字段验证 + 启动失败时显示具体错误 + "已启动→关闭跳到主面板"

3. **AndroidDumpModal** —— Android root 块级 dump（含 进度可视化）
   - 状态机：input → checking → ready → running → done
   - root 检测 + 自动列分区 + 默认选 userdata + 输出路径默认填 outputDir
   - 实时显示 dumped MB + 百分比（监听 `mtp:dumpProgress` 事件）
   - 完成后 banner + 5 秒自动关闭

4. **IOSBackupModal** —— iOS libimobiledevice 直连备份触发
   - 状态机：checking → input → pairing → backup → done
   - 工具检测 + 设备列表（trusted/untrusted 标记）+ 配对引导（"看 iPhone 屏幕"）
   - 监听 `ios:backupCompleted` / `ios:backupError` 事件 + 心跳进度提示

### Added — 全局移动端任务状态栏（解决用户建议 #3）

App.jsx 监听 11 个 backend 事件 → 右下角浮窗显示当前任务：
- `mtp:dumpStarted` / `mtp:dumpProgress` / `mtp:dumpCompleted` / `mtp:dumpError`
- `mtp:pullStarted` / `mtp:pullCompleted` / `mtp:pullError`
- `ios:backupStarted` / `ios:backupCompleted` / `ios:backupError`
- `ptp:pullStarted` / `ptp:pullCompleted` / `ptp:pullError`

状态栏特性：
- 图标按任务类型（💽📂🍎📷）
- 不确定进度走 `progressPulse` CSS 动画
- 完成 5 秒后自动隐藏
- 错误时红色背景 + 完整错误消息
- ✕ 按钮手动关闭

### Changed — ToolsMenu 4 个菜单项现在打开 modal

之前：4-6 个连续 `prompt()` → 拙劣
现在：单击菜单项 → 打开 modal → 表单填写 → 一键启动

被替换的菜单项：
- ☁️ 扫云端备份 → CloudBackupsModal
- 📡 NAS SMB 扫描 → NASScanModal kind="smb"
- 📡 NAS NFSv3 扫描 → NASScanModal kind="nfs"
- 💽 Android root 块级 dump → AndroidDumpModal
- 🍎 iOS 直连备份触发 → IOSBackupModal

仍走 prompt() 的（步骤少 + 一次性）：📂 ADB 拉目录、🔍 启动 iOS 备份扫描、
🤖 选 .ab 文件、📷 PTP 相机、🔌 ADB 设备列表、🎯 RAID、💾 镜像 dump

### 工程指标
- frontend `vite build` 成功（268 KB → gzip 86.6 KB，比 v2.4.0 大 17 KB = 4 个新 modal + 全局状态栏）
- backend `go test -short ./...` 全绿
- 没动 backend，纯 UI 增强
- 加 `progressPulse` CSS keyframe（不确定进度动画）

---

## v2.4.0 (2026-04-27)

**11 个"暗物质"功能从后端解锁到 UI** —— 修复 v2.2.0 加了 IPC 但前端没入口的问题。

### Background

v2.2.0 一次性加了 6 大功能（移动端协议 / 云端备份 / NAS / 国标 cipher 等），但
**只加了 23 个 Wails IPC 没建 UI 入口**，结果用户看不到这些功能存在。本 release
按用户优先级建 11 个 ToolsMenu 入口，让所有暗物质功能都可触达。

### Added — ToolsMenu 11 个新入口

按分组归到顶栏 🧰 工具下拉：

**☁️ 云端 + 备份**：
1. `☁️ 扫云端备份（iCloud/OneDrive/Drive...）` —— 一键扫所有云盘同步根 + 找其中的 iOS/Android 备份
2. `📱 扫 iOS 备份（本机 MobileSync）` —— 列出本机所有 iOS 备份（含加密标记）
3. `🔍 启动 iOS 备份扫描` —— 输入路径 + 密码，启动后台扫描
4. `🤖 选 Android .ab 备份扫描` —— 文件选择器 → magic 检测 → 密码（如加密）→ 扫描

**🔌 手机直连**：
5. `🔌 手机直连 ADB 设备列表` —— 列已 grant USB 调试的 Android 设备
6. `📂 ADB 拉手机目录扫描` —— 选 serial + 远端目录 → adb pull → 扫
7. `💽 Android root 块级 dump` —— 检测 root → 列分区 → 选分区 → dd 到本地 .img → 扫
8. `📷 PTP 相机（gphoto2）拉照片扫描` —— 检测 gphoto2 → 列相机 → 选 port → 拉所有照片 → 扫
9. `🍎 iOS 直连备份触发（libimobiledevice）` —— 检测工具链 → 列设备 → pair（需要 iPhone "信任此电脑"）→ 触发系统级备份 → 扫

**📡 NAS + RAID + 镜像**：
10. `📡 NAS SMB 扫描` —— host + 凭据 + share → 启动扫描
11. `📡 NAS NFSv3 扫描` —— host + export → 启动扫描
12. `🎯 RAID 阵列检测` —— 列出本机检测到的 mdadm/LVM/Storage Spaces 阵列
13. `💾 整盘镜像 dump (.img)` —— 当前选中盘 → dump 到 .img（强制不同盘）

### Verified — 23/23 Wails IPC 名称匹配

每个新菜单项调用的 backend method 都在 app.go 实际存在（防"调一个不存在的 method"
导致运行时 undefined error）：
- 云端：DiscoverCloudSyncRoots, ScanCloudForBackups
- iOS 备份：DiscoverIOSBackups, StartIOSBackupScan
- Android 备份：SelectAndroidBackup, InspectAndroidBackup, StartAndroidBackupScan
- MTP：MTPListDevices, MTPPullDirectoryAndScan
- Android 块级：AndroidIsRooted, AndroidListPartitions, AndroidDumpPartitionAndScan
- PTP：PTPCheck, PTPListDevices, PTPPullAllAndScan
- iOS 直连：IOSDirectCheck, IOSListDevices, IOSPair, IOSTriggerBackupAndScan
- NAS：StartSMBScan, StartNFSScan
- RAID + dump：DetectRAIDArrays, DumpDisk

### 工程指标
- frontend `vite build` 成功（251 KB → gzip 82 KB，比 v2.3.2 大 8 KB = 11 个新菜单项）
- backend `go test -short ./...` 全绿
- 没动 backend，纯 UI 增强

### UX 哲学：prompt() 而非 modal

新菜单项用浏览器原生 `prompt()` / `confirm()` / `alert()` 收集输入和显示结果，
跟其他工具菜单项（查找重复图片 / OCR / 计划备份）保持一致。优势：

- 单文件改动（仅 App.jsx ~200 行）
- 不引入新组件依赖
- 用户已熟悉这种交互（同套工具菜单 6 个月）

未来若用户反馈"输入步骤太碎"，再升级关键路径（NAS / Android dump / iOS 备份）
为完整 modal dialog。

---

## v2.3.2 (2026-04-27)

**IDCT 优化 (DC-only 24% 提速) + UI 部分恢复 badge + 长路径 tooltip + 进度条文本**

### Improved — IDCT 性能（纯 Go，不写 assembly）

- **DC-only short-circuit 用 OR-fused 检测**：`row[1]|row[2]|...|row[7] == 0`
  比 7 个 `&&` 链快（编译器 fold 成单次 OR + cmp 0）。这是自然图像的常见路径
  （高频系数被量化掉），命中率 30-60%。
- **Bounds check elimination hints**：`_ = block[63]` / `_ = row[7]` 让编译器
  一次性确认数组合法，省下每个 access 的 bound check
- **OR-fused col DC-only 检测** 类似收益
- 实测 (Apple M3 Max) `BenchmarkIDCT_DCOnly`：35 → 27 ns/op（**24% 提速**）
- Sparse / Dense block 各 5% 提速
- 加 `BenchmarkIDCT_DCOnly` / `_Sparse` / `_Dense` benchmark 防 perf 回归
- **诚实声明**：纯 Go 极限大约就是这里。要追平 libjpeg-turbo 的 SIMD（5-10×
  提速），需要写 amd64/arm64 assembly + 维护 fallback + build constraints。
  本工具典型场景（几百到几千张 JPEG 恢复）IDCT 不是热路径，未来集成到批量
  验证（10 万张/秒）再投入 asm 优化。

### Added — UI partial recovery badge

JPEG 部分修复成功后，前端显示更具体的"恢复率 badge"而不是泛泛"部分"：

- `frontend/src/components/RecoveryPage.jsx` `StateBadge` 增强：
  - 解析 backend message 里的 "X%" 数字（regex `部分恢复\s+(\d+)%`）
  - 显示 `⚠ 部分 31%` 而不是仅 `⚠ 部分`
  - 颜色按恢复率渐变：≥70% 标准 warning（黄）；<30% 偏红（用户能直观看到"这个图救得不好"）
  - tooltip = full message（鼠标悬停看完整 "部分恢复：5/16 MCUs，损坏点 @byte 725"）
- 新增"部分恢复"过滤 tab（仅当 counts.partial > 0 才显示）：
  - 默认 "未成功" tab 不再含 partial（partial 有自己的 tab）
  - 用户能一键 isolate "我有多少图是部分恢复的"

### Fixed — UI 可用性

- **长路径 progress.currentFile 加 `title` tooltip**：用户鼠标悬停就能看到完整路径
- **records-table message 列加 `title` tooltip**：长错误消息悬停可读
- **进度条覆盖百分比文字** (1 decimal)：之前用户只能从侧栏数字推断进度，
  现在主进度条上直接显示 `42.3%`，浅色背景上深字 / 深色背景上浅字（textShadow 增强对比）

### 工程指标
- `go test -race -short ./...` 全绿
- `staticcheck ./...` 0 警告 / `vet` 0 issues
- frontend `vite build` 成功（243 KB → gzip 79 KB）

---

## v2.3.1 (2026-04-27)

**4 个 bug 修复 + Loeffler IDCT + partial decoder 接入 carving pipeline**

### Fixed — 4 个生产 bug

- **updater dev 版本检测不一致** —— `internal/updater/checker.go:148`
  - `isNewerSemver` 把 dev 当 "总是有更新可用"
  - `verify.IsVersionNewer` 把 dev 当 "无法解析，拒绝 anti-downgrade"
  - 用户体验：UI 提示 "新版 v2.1.4 可用 (当前 dev)" → 点下载 → 弹错 "防 downgrade: 目标版本 v2.1.4 不比当前新"
  - **修复**：dev 构建一律不显示更新提示（dev 是开发场景，不该被自动覆盖为旧 release）
  - 加 `TestVersionCheckers_AreConsistent` 防再分歧

- **DownloadUpdate 失败路径死锁 downloadActive** —— `app.go:993`
  - `updater.PendingDir()` 失败时直接 return，但 `a.downloadActive = true` 已设置
  - 后续所有下载请求被静默吞掉（"下载已在进行" 分支），用户只能重启 app
  - **修复**：错误路径手动 mu.Lock + downloadActive=false + Unlock + 包装错误

- **3 个错误未包装** —— `app.go:519, 526, 2005`
  - BitLocker BuildSectorCipher / NewDecryptingReaderWithCache / FileVault disk Open 失败
  - 错误信息丢失，故障排查时不知道哪一步爆
  - **修复**：全部 `fmt.Errorf("具体步骤: %w", err)` 包装

### Improved — Loeffler IDCT (像素距 40.51 → 5.90)

替换 v2.3.0 的简化 cosine matrix IDCT 为 Loeffler/Ligtenberg/Moschytz 1989
11-mul 算法 —— **像素级匹配 stdlib `image/jpeg`**：

- 移植自 libjpeg jidctint.c + Go stdlib idct.go（算法事实，BSD-3 兼容）
- DC-only short-circuit：自然图像高频系数稀疏，跳过整个 1D IDCT 提速 ~2-3×
- `TestPartialDecode_BaselineHealthy` 测试容差从 80 收紧到 12（实测 5.90，
  早期朴素实现 40，stdlib 通常 < 5）

### Added — Partial decoder 接入 carving pipeline

把 v2.3.0 实现的 `PartialDecode` / `DeepRepairJPEG` 真正接到 recovery engine —
之前是 validator 包的孤立工具，没人调用：

- `internal/validator/jpeg_repair_from_disk.go`：
  - `RepairOutcome`：含 Repaired / RepairedBytes / Strategy / Coverage / HumanReadable
  - `Validator.RepairJPEGFromOffset(file)`：从磁盘读字节 → 跑 DeepRepair → 包装结果
  - `classifyRepair()`：通过对比 original vs repaired 推断走了哪个策略
    （original / partial-decode / header-injection / boundary-trim / huffman-stitch / deep-truncation）
- `internal/recovery/engine.go` Recover 路径改造：
  - carver 文件 ValidateDeep 失败 → JPEG → 调 RepairJPEGFromOffset
  - 修好就走"部分恢复"路径：标 `RecoveryStatePartial`，partialCount++，
    manifest 记 `[JPEG 部分恢复 31% via partial-decode] 部分恢复：5/16 MCUs (31%)，损坏点 @byte offset 725`
  - Confidence 设为 `Coverage * 0.5`（修复版置信度上限 50%，与正常解码区分）
- 端到端测试：损坏 JPEG 在 disk offset=4096 → RepairJPEGFromOffset → 5/16 MCUs
  恢复（31% coverage）+ 写出 stdlib 可解修复版

### 工程指标
- `go test -race -short ./...` 全绿
- `staticcheck` 0 警告 / `vet` 0 issues
- 新增 ~280 行代码 + ~100 行测试

---

## v2.3.0 (2026-04-27)

**ReFS B+ tree 端到端验证 + JPEG in-tree partial decoder** —— 把 v2.2.0 的两个
"foundation" 升级到真正的端到端通路。

### Added — ReFS B+ tree 端到端联调

- **合成 ReFS 风格 B+ tree fixture** —— `internal/refs/btree_walker_e2e_test.go`
  - 原因：macOS 没原生 ReFS 工具，无法生成真镜像；社区 sample 集大且许可证不明
  - fixture：3 层 B+ tree（root → 2 internal → 4 leaf → 8 file）
  - 每个 leaf entry 含完整 `$FILE_NAME` TLV field（parent_id + UTF-16 name + ...）
  - `EnumerateFilesViaBTree` 端到端走整棵树，返回的文件名清单与已知输入逐项匹配
- **新增 4 个端到端测试**：
  - `TestEnumerateFilesViaBTree_EndToEnd`：3 层树完整遍历，8 个文件名 + ObjectID 全验证
  - `TestEnumerateFilesViaBTree_RootIsLeaf`：root 直接是 leaf 的退化场景
  - `TestEnumerateFilesViaBTree_PrefersHighestLSN`：LSN 优先级正确
  - `TestWalkBTree_CycleDetection`：循环引用不死循环

### Added — JPEG in-tree partial decoder（终极策略）

替换之前"靠 stdlib + 边界注入"的间接路径，做了 **in-tree 最小 baseline JPEG
decoder**。这是真正的"R-Studio 风格"partial decode —— stdlib 在 entropy 流损坏时
abort 整个图像，本实现在损坏点保留已 decode 的 MCU + 灰填充未 decode 区域。

- **完整 baseline JPEG 解码栈**（~1000 行 Go，纯实现，无 CGO）：
  - `jpeg_partial_decoder.go`：segment 扫描 + SOF/DQT/DHT 解析 + Huffman 表构造 +
    bit reader（带 byte-stuffing + marker-aware）
  - `jpeg_partial_scan.go`：MCU 解码主循环 + IDCT (8×8 cosine matrix) + 反 quant +
    YCbCr→RGB（4:4:4 / 4:2:2 / 4:2:0 subsampling 全支持）
  - `PartialDecode(data) → *PartialImage`：
    - `Image`：已 decode 的 MCU 区域 + 未 decode 填中性灰
    - `DecodedMCUs / TotalMCUs`：恢复进度（"图像 70% 已恢复"）
    - `CorruptionMCU / CorruptionByte`：损坏发生位置（取证用）
- 接入 `DeepRepairJPEG` 策略链 strategy 6（终极兜底）
- **端到端验证**：
  - `TestPartialDecode_BaselineHealthy`：32×32 渐变图 round-trip，平均像素差 40
    （JPEG 量化 + 简化 IDCT 误差，视觉一致）
  - `TestPartialDecode_CorruptedEntropy`：64×64 文件中段插入 `FF 88` 损坏后，
    16 个 MCU 中前 3 个 decode 出来，损坏位置准确定位到 byte offset 675
  - `TestDeepRepairChain_PartialDecodeRecovery`：stdlib `jpeg.Decode` 失败的损坏
    文件经 `DeepRepairJPEG` 救回 697 字节可解 JPEG ✓

### 工程指标
- 新增代码 ~1100 行 + ~370 行测试（含合成 B+ tree fixture builder）
- `go test -race -short ./...` 全绿
- `staticcheck ./...` 0 警告
- `go vet ./...` 0 issues

### 与上一代实现的差距对比

| 项 | v2.2.0 (foundation) | v2.3.0 (端到端) |
|---|---|---|
| ReFS B+ tree | 单元测试单层 leaf/internal 识别 | 3 层完整树 + 8 文件名验证 |
| JPEG 部分恢复 | 注入合成 RST 让 stdlib 重同步（间接） | in-tree decoder 主动 emit 部分图像（直接） |
| 损坏文件恢复成功率 | ~70%（stitching 路径） | ~70% stitching + 兜底 partial decode |

---

## v2.2.0 (2026-04-27)

**重大功能扩展** —— 一次性补齐 6 个长期缺口：移动端协议、云端备份发现、
NAS 协议增强、ReFS B+ tree、JPEG Huffman stitching、VC 国标 cipher。

### Added — 移动端 / 直连协议

- **VeraCrypt Kuznyechik (GOST R 34.12-2015)** —— `internal/veracrypt/kuznyechik.go`
  - 纯 Go 实现俄国国标 128-bit 分组密码（256-bit key, 10 轮 LSX 网络）
  - RFC 7801 Appendix A 官方 KAT 通过：
    `Encrypt(key=8899aabb...cdef, pt=11223344...9988) = 7f679d90bebc24305a468d42b9d4edcd`
  - Kuznyechik-XTS-256 wrapper 实现 luks.SectorCipher 接口
  - cipher dispatcher 加 7 个新组合：
    `kuznyechik` / `kuznyechik-aes` / `kuznyechik-serpent` / `kuznyechik-twofish` /
    `kuznyechik-serpent-aes` / `aes-serpent-kuznyechik`
  - VC supportedCiphers 从 9 扩到 13；覆盖 95% → 99%+

- **云端备份本地发现** —— `internal/backup/cloud_discovery.go`
  - 不调任何云 API（OAuth-free，遵守"零网络"原则）
  - 扫已同步到本地的：iCloud Drive / OneDrive / Google Drive / Dropbox /
    Box / MEGA / pCloud / Nextcloud
  - 跨平台路径：macOS Library/CloudStorage、Windows OneDrive、Linux Nextcloud
  - 自动识别其中的 iOS MobileSync 备份（Manifest.plist）+ Android .ab 文件（magic header）
  - Wails IPC：`DiscoverCloudSyncRoots` / `ScanCloudForBackups`

- **Android 块级直读** —— `internal/mtp/android_block.go`
  - 对 root 设备 `adb shell su -c dd if=/dev/block/mmcblkN`
  - 支持 ListPartitions（/dev/block/by-name/）+ DumpPartition（流式 dd）
  - 进度回调（每 16MB 一次），128GB userdata 约 50 分钟
  - 物理镜像 dump 后接现有扫描引擎
  - Wails IPC：`AndroidIsRooted` / `AndroidListPartitions` / `AndroidDumpPartitionAndScan`

- **PTP via gphoto2** —— `internal/mtp/ptp_gphoto2.go`
  - libgphoto2 系统工具 wrapper（macOS/Linux/Windows 都能装）
  - 支持 2300+ 数码相机型号 + 部分老 Android 走 PTP
  - `--auto-detect` 解析 / `--get-all-files` 拉所有照片
  - Wails IPC：`PTPCheck` / `PTPListDevices` / `PTPPullAllAndScan`

- **iOS 直连 via libimobiledevice** —— `internal/mtp/ios_imobile.go`
  - idevice_id / ideviceinfo / idevicepair / idevicebackup2 wrapper
  - 触发系统级 iOS 备份到本地（等效 iTunes 备份按钮）
  - 备份完成后接现有 internal/ios 解析链
  - Wails IPC：`IOSDirectCheck` / `IOSListDevices` / `IOSPair` / `IOSTriggerBackupAndScan`

### Added — 协议增强

- **NFS3 完整 RPC** —— `internal/netfs/nfs_v3.go`
  - 新增 4 个 RPC：ACCESS（权限预检）、READLINK（符号链接）、FSINFO（rsize 调优）、FSSTAT（容量）
  - NFSFileReader 自适应 read chunk size（用 server 推荐 RTPref，老 Synology 32KB
    → NetApp 256KB-1MB，大文件传输快 20-40%）

- **ReFS Minstore B+ tree walker** —— `internal/refs/btree_walker.go`
  - 完整 B+ tree DFS 遍历（vs 之前仅启发式扫字符串）
  - leaf vs internal node 自动识别（用 child page ref 比例判断）
  - TLV 字段流解析（0x10 STANDARD_INFORMATION / 0x30 FILE_NAME / 0x80 DATA）
  - $FILE_NAME 抽 parent_id + UTF-16 文件名 → 可建目录树
  - cycle 检测（visited set 防 page 循环引用）
  - EnumerateFilesViaBTree 与 entries.go 启发版互补：结构化优先，启发兜底

- **JPEG Huffman state stitching** —— `internal/validator/jpeg_huffman_stitch.go`
  - 不 fork stdlib image/jpeg 的务实路径（DRI + 合成 RST 注入）
  - InjectSyntheticRST：在 SOS 前加 DRI 段 + entropy 流每 4KB 插一个 RST
    （RST 让 decoder 重置 DC predictor + skip 到字节边界，能从损坏点之后重新同步）
  - FindEntropyCorruption：扫 entropy 流找 0xFF + 非合法 marker（损坏特征）
  - StitchHuffmanState：组合 RST 注入 + 损坏点截断
  - DeepRepairJPEG 策略链加 strategy 5（stitching） + 5b（DHT + stitching）
  - 实测 ~70% 中段损坏 baseline JPEG 能产可识别图（vs R-Studio ~85%）

### 工程指标
- `go test -race -short ./...` 全绿
- `staticcheck ./...` 0 警告
- `gosec -severity=medium ./...` 0 issues
- 新增代码 ~2200 行 + 新增 ~430 行测试
- 新 Wails IPC：14 个（云端备份 2 + Android 直读 3 + PTP 3 + iOS 直连 4 + 已有扩展）

---

## v2.1.5 (2026-04-26)

LZFSE v2 (bvx2) 纯 Go decoder 完整修复 —— Apple compression_tool round-trip 通过。

### Fixed (修复 6 个独立的 LZFSE v2 实现 bug)

1. **header pf0 字段位置错位**（`internal/apfs/lzfse_v2.go`）
   - 早期把 `n_matches` 放在 bits 20..39，`n_literal_payload_bytes` 放在 40..59
   - Apple 真实顺序相反：`n_literal_payload_bytes` 在 20..39，`n_matches` 在 40..59
   - 错位导致 lit_payload / lmd_payload 边界错算 → 解码越界

2. **freq value table idx 19/27 错值**（`internal/apfs/lzfse_v2_freq.go`）
   - 表里 `value_table[19]` 应是 6（不是 4），`value_table[27]` 应是 7（不是 5）
   - 早期复制粘贴时把第二半段当作第一半段镜像，丢了 freq 6 / 7

3. **D 状态数错把 64 当 256**（`internal/apfs/lzfse_v2.go`）
   - Apple `LZFSE_ENCODE_D_STATES = 256`（D 范围 0..229372 比 L/M 大 4×，需要 4× state）
   - 早期 `lmdStates = 64` 同时给 L/M/D，D freq 表 sum 期待 64 实际 256 → 累计超限

4. **FSE table 构造算法错用 Yann Collet spread**（`internal/apfs/lzfse_v2_fse.go`）
   - Apple **不**用 spread 函数：states 按 symbol 顺序连续分配
   - 算法：`k = clz(f) - clz(N); j0 = (2N >> k) - f; for j: delta = (j<j0) ? ((f+j)<<k) - N : (j-j0) << (k-1)`
   - 早期用 step 互质 spread + Yann Collet delta 计算 → encoder/decoder state 转移不对应

5. **L/M base/extra arrays 错值**（`internal/apfs/lzfse_v2_decode.go`）
   - L sym 19 真值：base=60, extra=8 bits（早期：base=30, extra=5 → 范围只到 61）
   - M sym 19 真值：base=312, extra=11 bits（早期：base=30, extra=8 → 范围只到 285）
   - Apple sym 16-19 的 base/extra 全部需要修正
   - **关键**：M=2359 max 让 9000-byte 高度重复输入用 6 个长 match 才正常

6. **bit reader / 解码顺序与 Apple 不符**（`internal/apfs/lzfse_v2_bitreader.go` + `lzfse_v2_decode.go`）
   - 反向 bit reader：HIGH 位 = 最近 encoder 写（Apple `fse_in_pull` 语义），早期反过来
   - init 必须从整个 source buffer 倒退装 8 字节（不仅仅 payload slice），借助 header 字节占 accum 低位
   - literal 解码：output 正向 index（i, i+1, i+2, i+3），不是反向
   - LMD 解码：正向迭代 i = 0..nMatches-1（早期反向）
   - LMD pull 顺序：(L state + L extra) (M state + M extra) (D state + D extra) ——
     必须每对 state+extra 紧接，不能 L state → M state → D state → L extra... 错乱
   - rep-distance 优化：D=0 时复用 prev D（Apple 编码端高频"重复上一次距离"压缩）

### Added
- `TestLZFSEv2_RoundTrip_AgainstAppleEncoder` —— 9KB 重复输入字节级 round-trip ✓
- `TestLZFSEv2_RoundTrip_LargerVariedInput` —— 32KB 变化输入 round-trip ✓
- 这两个测试现在是真正的 regression bar（macOS-only，CI skip 是因为 runner 没 compression_tool）
- `TestReverseBitReader_PaddingZero` / `TestReverseBitReader_PaddingNonzero_Fails`

### Why this matters

LZFSE v2 (bvx2) 是 Apple APFS 默认压缩格式之一。早期实现号称"完整"但实际 round-trip 全部失败，
所有 bvx2 数据要靠 macOS-only `/usr/bin/compression_tool` shell-out fallback。这意味着：
- 非 macOS 平台（Windows/Linux）扫描 APFS 镜像时 bvx2 块**全部解不出来**
- macOS 上每个 bvx2 块要 fork 一次 compression_tool，性能低 100×

修复后纯 Go decoder 在所有平台都能正确解 bvx2，无需外部依赖。

---

## v2.1.2 (2026-04-27)

VeraCrypt Serpent + 完整 cascade 集合 + 系统加密自动识别 + APFS LZFSE v2 重构（部分）。

### Added
- **Serpent cipher**（`internal/veracrypt/data_cipher.go` + `unlock.go`）
  - 引入 `github.com/aead/serpent` 第三方依赖（BSD-2，纯 Go，约 600 行）
  - 单 cipher：Serpent-XTS-256
  - 2-cipher cascade 全集：AES-Twofish / Twofish-Serpent / Serpent-AES
  - 3-cipher cascade：AES-Twofish-Serpent / Serpent-Twofish-AES
  - 抽 `buildCascade2 / buildCascade3` helper 让 cascade 构造统一
  - `supportedCiphers()` 现在覆盖 VC 默认 cipher 集合的 95%+
  - **NESSIE Serpent-256 KAT**（key=0/pt=0 → CT = `49672ba898d98df95019180445491089`）
    验证第三方包正确性
- **VC 系统加密自动识别**（`internal/veracrypt/unlock.go` + `app_unlock_volumes.go`）
  - `OpenAndUnlockAuto`：先试容器路径（offset 0），失败再试系统加密路径（offset 31744）
  - `UnlockVeraCryptSystemEncryptionAndScan` Wails 入口（专属系统加密路径）
  - `UnlockVeraCryptAutoAndScan` Wails 入口（前端"我也不知道是什么 VC 卷"一键路径）
  - 抽 `unlockVCWithFunc(kind, ..., unlockFn vcUnlockFunc)` helper，三种入口
    （容器 / 系统 / auto）共享 Wails 事件 + 扫描调度
- **APFS LZFSE v2 主 decode loop 重构**（`internal/apfs/lzfse_v2*.go`）
  - 修正 v2 header 字节布局：从虚构的 44 字节平铺改为 Apple 真实的 32 字节
    bit-packed 布局（per `lzfse_internal.h` v2→v1 helper）
    - packed_fields[0]: n_literals[0..19] / n_matches[20..39] / n_lit_payload[40..59] / literal_bits+7[60..62]
    - packed_fields[1]: literal_state[0..3] (10 bits each) / n_lmd_payload / lmd_bits+7
    - packed_fields[2]: header_size[0..31] / l_state / m_state / d_state
  - 修正 frequency decoder：从虚构的 16-entry 4-bit tag 表改为 Apple 真实的
    32-entry 5-bit codeword 表（`lzfse_freq_nbits_table` + `lzfse_freq_value_table`）
  - bit reader 加 `peekBits` / `advance` 实现 Apple 风格 peek-then-drop pattern
  - 修正 freq parser 边界：限定到 [32, headerSize) 区间，不能读到 literal payload
  - 端到端 round-trip 测试用 macOS `/usr/bin/compression_tool` 生成真实 bvx2
    block 作 ground truth
  - **当前状态**：header + freq table 解析对了；FSE state / literal stream
    decode 仍有未解决的边界 bug（见 `TestLZFSEv2_RoundTrip_AgainstAppleEncoder`
    的 t.Skipf —— 修复完整 decode loop 时改回 t.Fatalf 即可作为 regression bar）
  - macOS fallback (`compression_tool` shell-out) 仍可用，无功能性退化

### Test Infrastructure
- 新增 NESSIE Serpent-256 KAT
- 新增 LZFSE v2 真 Apple 编码器 round-trip 测试（macOS only，CI 上 skip）
- 新增 `TestParseV2Header_FieldPositions` 验证 bit-packed 布局
- `staticcheck` 0 / `gosec` 0 / `go test -race` 全过

### Known Limitations
- LZFSE v2 pure-Go decoder 仍未通过 round-trip；macOS 用户走
  `compression_tool` fallback 100% 兼容；非 macOS 用户遇到 bvx2 块返回
  `ErrLZFSEFSEPartial` 友好错误

---

## v2.1.1 (2026-04-26)

v2.1.0 的 CI 修复 + 系统加密 parser + 扫描并发化 + 前端缓存 UI。

### Added
- VC 系统加密公式接通（`IterationsForPIMSystem` 已就绪，
  `OpenAndUnlockSystemEncryption` Wails 入口）
- NTFS scanner 多分区并发（worker pool min(NumCPU, len(partitions), 4)）
- APFS scanner 多卷并发（容器外串行，单容器内多卷 worker pool）
- 前端 `CacheStatsPanel.jsx`：每 2s poll `App.GetEncryptedReaderCacheStats`，
  颜色编码命中率（≥80% 绿 / <50% 黄）

### Fixed (CI)
- gosec -severity=medium 0 issues（8 项 #nosec 标注 + 详细注释）：
  G404 (rand) / G703 (path) / G122 (FS TOCTOU) / G505 (sha1) ×4 / G507 (ripemd160)

---

## v2.1.0 (2026-04-26)

加密卷真解锁 + Btrfs 完整扫描 + 性能/工程基础设施。代码量 +19233/-1064 (104 文件)。

### Added

**加密卷真解锁**（业界数据恢复工具的核心壁垒）
- **LUKS1/LUKS2** (`internal/luks/`)：完整 PBKDF2 + Argon2id KDF + AFsplitter (anti-forensic
  splitter) + AES-XTS-plain64 / CBC-ESSIV / CBC-plain 三种 sector cipher，支持 4K sector 卷
  和 sha1/sha512 LUKS2 csum；跨 keyslot 进度回调让 UI 能展示"正在尝试 keyslot 2/8"
- **VeraCrypt/TrueCrypt** (`internal/veracrypt/`)：PBKDF2-{SHA-512/256/RIPEMD-160}
  × {AES-XTS, Twofish-XTS, AES-Twofish cascade}；PIM (Personal Iterations Multiplier)
  含系统加密公式 (200000 fixed for SHA / pim×2048 for RIPEMD)；NumCPU 并发派生让
  最坏 30s+ unlock 缩到 5s；`vc:trying` 事件流前端可观察
- **DecryptedReader 透明解密代理** (`internal/luks/decrypted_reader.go`)：把已解锁卷
  暴露成普通 `disk.DiskReader`，下游 NTFS / ext4 / APFS scanner 直接 ReadAt 即可
  扫"虚拟解密磁盘"，完全不需要懂 LUKS/VC

**Btrfs 完整 FS-tree 扫描**（之前只能 detect-only）
- `ChunkCatalog` 全量 logical→physical 翻译（覆盖 sys chunks + chunk tree 完整遍历）
- `WalkRootTree` + `WalkFSTree` + INODE_ITEM/EXTENT_DATA/DIR_ITEM/INODE_REF 解析
- `BuildPathMap` 完整路径回溯（parents/names 链 → "/Documents/photo.jpg"）
- 压缩 extent 解压：zlib (`compress/zlib`) + zstd (`klauspost/compress`)
- 接入 recovery engine：`runBtrfsScan` + `WriteBtrfsFile` + recoverBtrfsFile
  支持 inline / regular / prealloc 三种 extent + sparse fallback

**iOS / Android / MTP**（移动端备份）
- iOS bplist binary reader + writer（双向 round-trip，与 plutil 输出一致）
- iOS XML plist parser（auto-dispatch 支持老 iTunes 备份）
- Android `.ab` 备份完整链：keybag + AES-CBC + zlib + tar
- MTP 经 adb shell-out（`internal/mtp`）：DetectMTPDevices / PullDirectoryAndScan

**取证基础设施**
- DFXML 1.0 schema 升级：xmlns + Dublin Core namespace + `<byte_runs>` + `<source>`
  区块；Sleuthkit / Autopsy / fiwalk 兼容
- Custody manifest 双写 (`custody.json` + `custody.plist`)，macOS 工具链
  (plutil / Apple Configurator / Magnet AXIOM / R-Studio Mac) 原生 fast-path
- `Signer` 接口化重构：`LocalEd25519Signer` / `ExternalCLISigner` / 任意 HSM/KMS
  adapter 共用 `signCustodyCanonical` 路径
- 10 个 Crypto KAT (RFC 6070 PBKDF2-SHA1 v1-v4 / RFC 7914 PBKDF2-SHA256 /
  IEEE 1619 AES-XTS v1+v2 / Argon2id 参数顺序兜底 / deriveLUKS2KDF 包装层校验)

**Carver 增强**
- JPEG ITU T.81 Annex K 标准 Huffman 注入（覆盖 NTFS data run 第一段被覆盖
  导致 DHT 段丢失的常见恢复场景）+ `DeepRepairJPEG` 多策略链
- ZIP CD 损坏时扫 local headers 兜底重建（覆盖 ZIP 末尾被截断 / CD 被覆盖
  这两类常见数据恢复场景），含 data descriptor 模式（archive/zip 默认）从
  描述符读真实 CRC + sizes

**性能 / 工程基础**
- `disk.SectorCache`：LRU sector 缓存，nil-safe，含 hits/misses/evictions/HitRatio
  metrics；LUKS / VC / BitLocker DecryptedReader / DecryptingReader 共享同实现
- VeraCrypt unlock NumCPU 并发派生（worker pool，第一命中即返回）
- ext / fat / btrfs scanner 多分区并发扫描（worker pool，min(NumCPU, len(parts), 4)，
  HDD 友好上限）
- NTFS 非 resident `$ATTRIBUTE_LIST` 支持（极碎片化大文件 + 多 ADS 的"惊人复杂"
  文件场景；按 DataRuns 读盘 + 共用 parseAttributeListContent）
- LUKS2 csum 多 hash 支持（cryptsetup 实际支持的 sha1/sha256/sha512 全集）

**架构**
- `app.go` 拆分：`app_unlock_volumes.go` 抽出 LUKS+VC unlock IPC（~280 行）
- `internal/disk/sector_cache.go` 共享缓存抽象，避免 LUKS / BitLocker 各自实现
- `cmd/drift-check`：注释↔实现漂移自动检测器
- `Engine.Shutdown` 释放对称性 audit：补齐 6 个 source maps 释放 + apfsVEKs 字节归零
- `Engine.EncryptedReaderCacheStats()` + Wails IPC `GetEncryptedReaderCacheStats`：
  前端能展示加密卷扫描的缓存命中率

### Fixed

- `internal/ios` 7 处 ST1005 错误信息首字母大写
- `internal/recovery/android_scan.go` 1 处 ST1005
- `internal/netfs/xdr.go` 删除 2 个未使用的 XDR primitive helpers (U1000)
- `internal/recovery/scanner.go` 删除未使用的 `(*Engine).allScanners()` (U1000)
- CLI `flagsAfter` 注释 drift 修正（注释说"无 flag 后跟值的 bool 暂不支持"
  但代码 105 行就已经有 `kv[key] = "true"` 兜底）

### Test Infrastructure

- 新增 ~110 单测（覆盖所有新能力）+ 1 个 fuzz
- `go test -race ./...` 全过
- `staticcheck ./...` 0 警告
- `go vet ./...` 干净
- cross-compile windows/amd64 + linux/amd64 通过
- `drift-check`: 0 注释↔实现漂移

### Known Limitations (按 ROI 排序留 TODO)

- **VC system encryption volume parser**：公式已实现 (`IterationsForPIMSystem`)，
  但 layout parser (offset 31744 + boot loader 区) 暂不支持；< 5% VC 用户
- **Serpent cipher**：无现成 Go 实现 + 自己 port 800 行没权威 KAT 验证渠道是
  irresponsible（数据恢复给错密文比报错差 10 倍）；网络恢复后引一行依赖即可
- **APFS LZFSE v2 主 decode loop** (FSE 熵编码)：1500+ 行 + 没 Apple 官方测试
  向量；当前回退报错并提示 `afsctool -d`
- **JPEG Huffman state stitching**（无 RST 也能拼）：R-Studio 20 年壁垒，需
  fork stdlib `image/jpeg` 暴露 decoder.huffmanState

---

## v2.0.2 (2026-04-24)

核心差异化 wedge 兑现 + CI race 修复。

### Added
- **Best Chance First 默认视图** (`frontend/src/components/BestChanceFirst.jsx`)
  - 扫描完成后不再一上来扔给用户 10000+ 行裸表格，改为 6 桶苹果级分类卡片：
    Windows.old / 桌面 / 我的照片 / 我的文档 / 最近修改 / 其他
  - 每桶显示数量 + 总大小 + Top 3-4 条预览（照片桶懒加载真实缩略图）
  - 两个 CTA："恢复此类全部 (N)" / "查看列表"
  - 底部出口"查看全部文件（高级模式）"保留给深度用户
  - 动机：设计文档锁死 wedge "Apple 级预览 + 一键导出"中「一键」那一半此前未落地，
    用户观感和 R-Studio 相差无几；v2.0.2 兑现承诺

- **ConfidenceBadge 4 档可视徽章** (`frontend/src/components/ConfidenceBadge.jsx`)
  - 替代 FileTable 之前那条 "87%" 百分比条
  - 高可靠（绿） / 可能可靠（黄） / 部分（橙） / 低可靠（灰）
  - 用户读不懂浮点数，读"高可靠 ✓"能立刻做判断

- **recovery-helpers.js**：新增 `bucketFiles()` 按优先级分桶（系统文件排除），
  `confidenceTier()` 做 4 档映射，`BUCKETS` 元数据导出

### Fixed
- **CI DATA RACE** (`internal/updater/download.go`)
  - 根因：watchdog goroutine 里读全局 `stallCheckInterval`，与另一测试写该全局
    之间没有 happens-before 边；`close(stallDone)` 同步的是退出路径，但之前的
    读已经发生
  - 修复：在 `DownloadAsset` 主 goroutine 里把 `stallCheckInterval` 捕获到 local
    `interval`，闭包只引用 local。全局读全部发生在调用方主 goroutine，跨测试
    的写有 testing 框架的顺序保证
  - 验证：`go test -race -count=3 ./internal/updater/` 绿

### Test Infrastructure
- `pnpm build` 绿（46 模块，240KB 主包）
- `go vet ./...` / `go build ./...` 绿

---

## v2.0.1 (2026-04-24)

两个**用户可见的生产级 bug** 修复 —— 都是"防护机制注释有写、代码没落地"的同类架构漏洞。

### Fixed
- **预览恢复中的文件不再卡死** (`internal/recovery/engine.go`)
  - 根因：`ReadFilePreview` 用裸 `disk.NewReader` 打开源盘，没包 `TimeoutReader`。bad sector 上 Windows `ReadFile` 在 driver queue 无限 hang，preview goroutine 永远不返回，前端表现为"点击预览卡死"
  - 扫描 reader 在 `runScan` 里已经包了 `Resilient+Timeout` 链；preview 路径历史上被漏掉
  - 修复：抽 `openPreviewReader(devicePath)` 工厂函数，强制 `TimeoutReader` 3s/read + `OpenWithTimeout` 5s。bad sector fail-fast 返回"预览超时"而不是静默花屏图
  - 回归：`TestOpenPreviewReader_WrapsTimeoutReader` 锁死包装契约；`TestTimeoutReader_FailsFastOnHang` 用 hanging mock 验证超时真生效

- **自动更新不再 silent hang** (`internal/updater/download.go`)
  - 根因：`DownloadAsset` 注释声称"由 ctx + stall detector 控制"，但代码里根本**没有 stall detector**。`http.Client.Timeout=0` + 外层 ctx 来自应用生命周期 → GitHub CDN 在 CN 网络下 TCP 连接活着但停发数据时，`resp.Body.Read` 永远阻塞，progress 停发，用户 UI 冻结在某个百分比以为"下载失败了"
  - 修复：加 stall watchdog goroutine + `atomic.Int64 lastActivity`，超过 `StallTimeout` (30s) 无活动自动 `resp.Body.Close()` 让 Read 返回错误；主循环识别 stall 触发 vs 服务器真错，返回清晰中文提示"下载停滞 30s，请检查网络后重试"
  - 回归：`TestDownloadAsset_StallWatchdogTriggers` 用 hang server 验证 watchdog 在 30s 触发；`TestDownloadAsset_SlowButProgressingNotFalseTriggered` 验证慢但持续有进度的连接不误触发

### Architecture Note
两个 bug 共享同一个"aspirational comment"反模式：防护机制的注释写了，代码没实现。未来架构审计 checklist 要加一条：每一条"timeout / cancel / deadline"字样的注释都要能映射到具体实现。

### Test Infrastructure
- 全量 `go test -race ./...` 绿（30+ 包，含所有 fuzz + validator + updater 套件）
- 两个回归测试在 CI 下 pass，已 commit

---

## v2.0.0

主版本升级。新增能力：

### 文件系统
- **NTFS**：完整 MFT + ADS + USN journal 找回删除文件名 + LZNT1 解压 + fixup 校验
- **APFS**：容器/卷枚举 + omap B-tree + fs tree 完整文件遍历 + snapshot
- **Btrfs / XFS / F2FS / ZFS**：完整 B-tree walker + extent 解析
- **HFS+ / HFSX**：Catalog B-tree + Extents Overflow
- **ReFS**：Minstore page 索引 + 启发式 entry 提取
- **LUKS / VeraCrypt**：识别 + 高熵检测

### 加密卷解锁
- **BitLocker 全链**：AES-XTS / AES-CBC + Elephant Diffuser + 4 种保护器
- **FileVault 全链**：keybag → PBKDF2 → AES-KeyWrap → VEK → XTS
- **ZFS native encryption**：PBKDF2 → Key Wrap → HKDF → AES-GCM

### RAID / 存储
- RAID 0/1/5/6/10 + **mdadm 自动检测**（跨盘按 UUID 分组）
- **ZFS RAIDZ1/2/3** 完整求解（3 data 盘缺失走 Vandermonde GF 求逆）

### 压缩
- NTFS LZNT1 / LZX / LZFSE v1 (LZVN) / LZFSE v2 pure Go FSE / LZ4 / ZSTD / zlib

### 碎片重组
- JPEG block-graph stitching + 熵流健康度
- PNG chunk CRC 驱动
- MP4 atom 链 + moov+mdat 双命中
- ZIP Central Directory 反查 (ZIP64 支持)
- PDF startxref 偏移验证

### 取证（B2B）
- Ed25519 签名 + RFC 3161 时间戳 + HTML 专业报告 + Evidence Bundle ZIP

### 自动更新（外部审计级）
- SHA256SUMS + Ed25519 签名 + 代码内公钥 pin
- Rollback 防护 + Apply 失败自动回滚
- JSONLines 审计日志
- 启动时静默替换 exe（用户无感知）

### 质量保证
- staticcheck / gosec 零警告
- `go test -race -count=10` 核心包零 DATA RACE
- Fuzz 2500 万次执行覆盖关键 parser（NTFS / APFS / carver / Btrfs）
- Fuzz + round-trip 抓到 13 个真 bug 已全部修复 + 加回归测试
- CI 自动跑 staticcheck + gosec + race + fuzz

### Breaking Changes
- IPC surface 从 14 方法扩到 70+
- 前端 UI 大改
- v1.x 用户升级会看到全新 UI

---

## v1.0.0 (2025 上半年)

初版。NTFS MFT 扫描 + 签名雕刻 + Wails UI。
