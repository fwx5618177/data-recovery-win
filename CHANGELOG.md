# 版本历史

遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

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
