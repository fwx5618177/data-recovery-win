# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [v2.0.0] - 重大版本

**Major bump** 原因：新增 25+ Go 包 + 完整文件系统解锁 / 取证 / 扩展能力，对外 IPC 表从
14 个方法扩到 70+，前端 UI 重构。老版本 v1.x 的用户升级后第一次启动会看到新 UI。

### Added — 加密卷完整解锁
- **BitLocker 完整解密链** —— 覆盖 Win10+ 默认（AES-XTS-128/256）+ Vista/Win 7 老格式（AES-CBC + Elephant Diffuser）
  - 4 种保护器：recovery key (48 位数字) / 用户密码 / startup key (.BEK 文件) / **TPM 卷的内存镜像 VMK brute-force**
  - 内存镜像路径支持 `hiberfil.sys` / winpmem / DumpIt / VMware `.vmem`，让 TPM-only 卷也能解（Passware / Elcomsoft 同款方法）
  - VolumeHeaderBlock datum 自动推算明文卷头区，避免二次"解密"明文
  - 完整 `SectorCipher` 抽象，`DecryptingReader` 透明解密喂给 NTFS scanner
- **FileVault 完整链** —— APFS 加密卷的 keybag → PBKDF2 → AES-KeyWrap (RFC 3394) → VEK → AES-XTS 扇区解密
  - `UnlockFileVaultVolume` 用户密码 IPC 入口
  - `EncryptedReader` 接入 APFS 扫描路径 → FileVault 卷的 fs tree 能枚举文件
  - RFC 3394 KeyWrap 两个权威测试向量（4.1 / 4.6）通过

### Added — 文件系统支持
- **APFS 完整** —— 容器识别 + omap B-tree + fs tree crawler + 文件枚举 + extent 恢复 + Snapshot 枚举（Time Machine）
  - `LoadOmapAtXID` 时光穿越读：按 snapshot.xid 重做 omap walk 看历史时间点文件树
  - LZFSE 容器解压（bvxn LZVN / bvx- uncompressed / bvx$ EOS）
  - LZFSE v2 (bvx2) header parser + FSE table 骨架；未完整解的场景退化到"用 afsctool -d"友好引导
- **HFS+ / HFSX 完整** —— Catalog B-tree 遍历 + 文件枚举 + Extents Overflow Tree（>8 extent 的大文件）
- **ReFS** —— 卷识别 + Minstore page 索引 + 尝试性 B-tree entry parser（社区逆向）
- **Btrfs / XFS / F2FS / ZFS** —— 卷头识别 + 基本元数据（Linux / Android / TrueNAS）
- **LUKS1 / LUKS2** —— header + cipher + UUID / label 识别
- **VeraCrypt / TrueCrypt** —— 高熵启发检测
- **GPT 分区表备份恢复** —— 主表损坏时从盘尾 LBA -33..-1 备份恢复分区列表

### Added — RAID
- **RAID 0 / 1 / 5 / 6 / 10 虚拟重组** —— 作为 `disk.DiskReader` 实现，对上层透明
  - RAID 5 left-symmetric 单盘缺 XOR 重建
  - **RAID 6 双盘缺 Reed-Solomon 重建** —— 自己实现 GF(2^8)（生成多项式 0x1D + exp/log 查表），测试覆盖 6 盘阵列所有 15 种双缺组合
  - RAID 10 mirror pair × stripe
- **卷管理器成员盘识别** —— mdadm (magic 0xA92B4EFC) / LVM2 (`LABELONE`) / Storage Spaces；扫盘时自动预警

### Added — 碎片重组
- **JPEG block-graph stitching** —— 基于 RST marker 序号约束 + 中段 SOI 检测的简化版
- **JPEG health score** —— 合法 RST/EOI vs 非法 marker 比例打完整性评分
- **paranoid level 2 碎片检测** —— 多点采样 + 字节熵突变检测 + PNG/MP4 格式专项
- **NTFS $UsnJrnl 删除文件名复原** —— 找回"这文件曾叫 IMG_3492.HEIC，3 月 15 日被删"线索

### Added — 压缩
- **NTFS LZX 完整 decoder**（WIM / Compact OS）—— 新子包 `internal/compress/lzx/` 780 行
  - 16-bit LE word + MSB-first bit reader（Microsoft 独特格式）
  - canonical Huffman + pretree delta code length
  - 3 种 block（verbatim / aligned offset / uncompressed）+ 32KB 滑动窗口 + LZ77 match + LRU r0/r1/r2
  - E8 x86 call-preprocessing 反向
- **HFS+ decmpfs**（zlib inline）
- **LZVN 扩展 op**（0x00-5F small / 0x70-7F medium），从 2 种 op 扩到 4 种

### Added — 取证 / 法务
- **Timeline**（Sleuthkit mactime / NDJSON 格式）
- **DFXML**（Digital Forensics XML 标准报告）
- **Chain of Custody** —— 每文件 sha256 + manifest 自身 sha256 自证
- **NSRL hash 数据库比对** —— 装入 NIST 良性 hash 列表识别系统文件
- **VirusTotal v3 API hash 查询**（不上传文件，仅查 hash）

### Added — 现代格式 / 增值
- **HEIC / HEIF / AVIF carve** —— iPhone iOS 11+ 默认图像格式
- **HEIC EXIF 解析** + **Live Photo (.HEIC + .MOV) 配对**
- **EXIF 拍摄日期归档**（YYYY/MM 子目录）—— 用户找回 5 万张照片后按月分类
- **Perceptual hash 查重**（aHash + Hamming + SimilarityGroup）
- **OCR 搜图**（调本机 Tesseract；带 SearchInImages helper）
- **定时备份监控** —— 跨 OS 生成 cron / schtasks 任务，"找回后帮你自动定期备份"

### Added — 系统集成
- **SMB 协议级 reader** —— 引 `go-smb2` 依赖；远程共享里的镜像文件可直接扫
- **SMART 磁盘健康探测** —— 调 `smartctl` 解 PASSED/重映射/坏扇区/温度，扫描前提示盘状态
- **SED OPAL / Pyrite 检测** —— 调 `sedutil-cli` 查 TCG 自加密硬盘锁定状态
- **多盘并行扫描** —— `ParallelScanDrives` IPC + 4 种事件流（NAS / 取证场景）
- **ResilientReader 坏扇区跳过** —— 遇 IO 错切扇区重试 + 0 填充 + 记录坏扇区列表
- **诊断包一键导出** —— 日志 + session snapshot + pending update 打包 zip（给 issue 用）
- **macOS 自动 sudo relaunch** —— osascript 弹 Touch ID/密码原生框；Linux 退化到 pkexec
- **非交互环境检测** —— CI / Wails build / pipe 自动跳过 auto-sudo，修复 GitHub Actions "dead parents" 构建失败

### Added — 前端 UX
- **暗黑 / 浅色 / 跟随系统 三态主题切换**
- **中英 i18n 框架**（无第三方依赖）
- **虚拟滚动** —— 文件列表 >1000 时自动切换，10 万+ 文件不卡
- **多类型预览**（PDF / 视频 / 音频 / 文本 / 图像）
- **顶栏 ToolsMenu** —— 15 个工具统一入口（SMART / SED / GPT 恢复 / 查重 / OCR / 备份 / 时间线 / DFXML / 保管链 / NSRL / 网络镜像 / 多盘并行 / Snapshot）
- **BitLocker 解锁预览 protectors** —— 对话框打开时调 `SummarizeBitLockerProtectors`，告诉用户"该卷能用哪种方式解"
- **FileVault 用户密码解锁 UI**
- **拖拽镜像到窗口任意位置自动扫描**（Wails OnFileDrop）
- **键盘快捷键**：Esc 停扫 / Ctrl-F 聚焦搜索 / Ctrl-A 全选可见
- **高级搜索语法**：`size:>100MB type:image deleted:yes ext:jpg path:/Users`
- **按 EXIF 日期归档恢复** UI 开关

### Added — CLI / 命令行
- **`cmd/data-recovery-cli/`** —— 独立二进制，四个子命令：
  - `scan` / `recover` / **`scan-and-recover`**（单进程完整流程，含 NTFS/APFS/HFS+ source cache）
  - `usn-list` 直接列 NTFS 删除文件名
  - `bitlocker-detect`
- 带 JSON 报告输出 + stderr 进度条 + Ctrl-C 优雅停止

### Added — 发布 / CI
- **SHA256SUMS 供应链校验** —— 发版 CI 附 SHA256SUMS.txt，updater 下载后比对
- **Linux .deb / .rpm 自动打包**（nfpm）
- **代码签名 CI 脚手架**（Windows signtool / macOS codesign + notarytool）—— 项目方配 secrets 后自动生效
- **集成测试 CI 脚手架** —— 月度从 Sleuthkit / dislocker 公开镜像下载跑 E2E
- **Homebrew / winget / Chocolatey 发布模板**
- **docs/UNIMPLEMENTED.md** —— 明确标注"外部资源 blocker"的 10 项

### Added — 从上一版继承的（已在 v1.x 实现但未正式 tag release 的）
- **NTFS LZNT1 压缩解压** + **$ATTRIBUTE_LIST** + **已删除分区扫描** + **ADS 枚举**
- **Volume Shadow Copy 枚举 + VSS 扫描入口**
- **自动更新**（后台下载 pending / helper 重启应用）
- **镜像扫描** + **整盘 dump**（带坏道跳过）
- **FAT12/16/32 支持**
- **exFAT 完整 FAT 链**（碎片化文件也能恢复）
- **签名库**：HEIC / HEIF / AVIF / CR2 / CR3 / DjVu / MIDI / XZ 等
- **图片预览** + **Windows.old 高优先级识别**

### Changed
- **IPC 边界层重构**：`app.go` 只做参数校验 + 事件推送 + 调用 internal 包；所有真逻辑在 internal，让 CLI 能复用不依赖 Wails
- `recovery.Engine` 加 `ScanWithReader(reader, mode, callbacks)` — 让 BitLocker / FileVault 解锁后的 `DecryptingReader` 能喂回同一扫描流水线
- `updateRepoOwner` / `updateRepoName` 从源码占位改用 `-ldflags` 注入，fork 开发者零改动
- `vss.Shadow` 加 JSON tag 统一前端字段命名（camelCase）
- `ScanEncryptedVolumes` 改用 `FindVolumesFast` 只扫 offset 0 + GPT/MBR 分区起点，启动主页不再卡几分钟
- 所有 36 个 Go 包通过 `go vet -race -count=1 -short`

### Fixed
- **Windows 启动白屏** —— 两处修复
  - `vite.config.js`：`base: "./"` 改相对路径（WebView2 对 `/assets/` 绝对路径解析不稳），`inlineDynamicImports: true` 把 dynamic import 内联到单 bundle，避免 chunk fetch 失败
  - `App.jsx` 键盘快捷键 `useEffect` 依赖数组里引用了在下方才声明的 `stopScan`（const TDZ）→ render 阶段 `ReferenceError` → React 挂载失败 → 白屏；把这段 `useEffect` 移到 `stopScan` 声明之后
- **扫描卡死 / 停不下来 / 插盘卡死**（一组关联根因）
  - `disk.OpenWithTimeout` 5s 超时包装 `Open()`，避免 dirty U 盘 / 系统级 chkdsk 中的设备让 `CreateFile` hang，连带阻塞整个 wails IPC 队列
  - `ScanEncryptedVolumes` 启动时不再对每块盘并发触发 —— 改为用户在 WelcomePage 选中具体盘后才单盘扫描；启动只列盘，不做真实块读
  - `Engine.Stop` 除了 cancel ctx，还调用新增的 `disk.Canceller.Cancel()` —— Windows 用 `CancelIoEx` 中断 pending IO，Unix 用 close handle —— 让卡在内核 `ReadAt` syscall 上的扫描 goroutine 立即返回，"停止扫描"按钮真的能停
  - WelcomePage 未完成会话 banner：把"丢弃"改为主操作按钮 + 加引导文案，让被卡循环困住的用户能一键逃出
  - 前端 30s 轻量轮询 `GetDrives` 检测 U 盘插拔（仅 welcome 页 + 非扫描状态），无原生 `WM_DEVICECHANGE` 监听的简易替代
- `admin_unix.go` `syscall.Kill(getpid(), SIGTERM)` 导致 Wails bindings 生成阶段父进程异常退出 → CI "dead parents" —— 改为 `return true, nil` 让 main 正常退出 + 非交互环境跳过
- `ScanEncryptedVolumes` 多扫描路径重复命中去重
- `DecryptingReader` 原来只支持卷 offset=0；加 `volumeOffset` 让物理盘上任意位置的 BitLocker 卷都能解
- `dedupeEncryptedVolumes` 按 (kind, drivePath, offset) 正确去重
- APFS UUID 格式按 GPT 混合字节序（前 3 段 LE 反转）与磁盘管理器一致
- Carver `sync.Pool` 死代码清理
- NTFS scanner ctx 取消 + 分区遍历
- FileName / OriginalPath 空兜底

### Infrastructure
- **36 个 Go 包全绿** `go test -race -count=1 -short`（原 11 → 36）
- 新增 25+ 包：apfs / bitlocker / btrfs / xfs / f2fs / zfs / luks / veracrypt / raid / gpt / volmgr / sed / compress (+lzx 子包) / forensics / exif / dedup / ocr / parallel / backup / netfs / diag / hfsplus / refs / apfs (keybag/keywrap/lzfse/lzfse_v2/snapshot/encrypted_btree)
- 依赖新增 `github.com/hirochachacha/go-smb2` （SMB 协议级）
- CI 跨平台 build + race test + cross-compile smoke + 月度集成测试

### Security
- BitLocker recovery key / memory VMK / FileVault password 全程只在内存里用，**不落盘**
- Chain of Custody 保管链自证（manifest 自 sha256）
- VirusTotal 只查 hash 不上传文件
- SHA256SUMS + HTTPS 双供应链校验

## [Unreleased]

（本区域当前为空；本次 v2.0.0 发布后，后续 PR 改动写到这里）

## [v1.0.0] - 2025 年上半年

详见 git log。
