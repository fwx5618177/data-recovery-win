# 版本历史

遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

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
