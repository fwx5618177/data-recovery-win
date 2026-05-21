# 数据恢复大师 — 功能清单 (PM 速查版)

> 最后更新: v2.8.47 (2026-05-21)
> 维护说明：PM / 测试 / 客服按这份清单去逐项验证，下方"完成度"列定义了对应预期。

## 本次发版核对（v2.8.43 → v2.8.47 累计）

| 项 | 状态 | 备注 |
|----|----|----|
| 6 大用户报错 bug 全修 | ✅ | 见第 11 节 |
| 性能优化连环（KB/s → MB/s） | ✅ | 见第 7 节 7 个优化点累计 |
| 测试目录化 | ✅ | v2.8.46 抽出 internal/scanevent + internal/gpt；4 root 测试搬 tests/ |
| Root 目录清理 | ✅ | v2.8.47 App 整个搬到 cmd/data-recovery，root 只剩 main.go (20 行) |
| CI 全绿（Build + Release） | ✅ | staticcheck Linux+Windows / -race / gosec / 全平台 build |
| PM 功能清单（本文档） | ✅ | 11 节覆盖，含验收建议 |

## 完成度图例

| 标记 | 含义 |
|----|----|
| 🟢 **GA** | 业界标准实现 + 真盘验证过 + 自动测试覆盖；用户可直接依赖 |
| 🟡 **Beta** | 主路径打通且有单测，但需要更多真实场景验证（盘型号/坏区分布） |
| 🟠 **Preview** | 功能可用但只覆盖典型 case，边界场景可能失败，UI 有 "实验" 标识 |
| 🔴 **Stub** | 占位实现，仅返回错误 / 假数据；用户可见 |
| ⚪ **N/A** | 平台不支持（如 Windows 上的 APFS） |

---

## 1. 核心扫描 / 恢复（主用户路径）

| 功能 | 完成度 | 说明 |
|------|------|------|
| 物理盘 / 逻辑卷只读扫描 | 🟢 GA | Windows / macOS / Linux 都过；支持 NTFS / exFAT / FAT / ext4 / APFS / HFS+ / Btrfs / XFS / F2FS / ZFS / ReFS |
| 深度签名雕刻 (carver) | 🟢 GA | 74 种文件签名，Aho-Corasick 多模式匹配，pipeline 多核并行，8MB chunk |
| 文件大小精确解析 | 🟢 GA | JPEG / PNG / MP4 / TIFF / ZIP / PDF / Office / RAW 等 ~25 种格式按 spec 解析边界 |
| 碎片化检测 (v2.8.46) | 🟡 Beta | 主扫描后单独 pass 跑熵度分析，标记可能碎片化的文件；UI 上"⚠ 碎片"标识 |
| 多盘并行扫描 | 🟢 GA | 同时扫多盘，IPC 批量节流 (v2.8.38)，cancel 即时响应 (v2.8.31) |
| 断点续扫 | 🟢 GA | 进程退出 / 重启后能从上次位置继续；快照每 5s 落盘 |
| 镜像文件扫描 | 🟢 GA | 支持 .img / .dd / .raw，可用 ddrescue 先 dump 再扫，源盘只读一次 |
| 整盘镜像 dump | 🟡 Beta | 内置 ddrescue 风格的快速跳过坏区 dump；UI 上有进度 + ETA |
| 加密卷自动探测 | 🟢 GA | BitLocker / FileVault / APFS / LUKS / VeraCrypt 一键检出 |
| BitLocker 解锁扫描 | 🟢 GA | recovery key / password / TPM image 4 种保护器都过；XTS + CBC 都支持 |
| LUKS 解锁扫描 | 🟢 GA | LUKS1 + LUKS2 都过；AF splitter + Argon2 KDF 完整实现 |
| VeraCrypt 解锁扫描 | 🟡 Beta | 全 7 种密码算法 + hidden volume；Kuznyechik 国密支持 |
| FileVault 解锁扫描 | 🟡 Beta | macOS 真盘验证过，但 EncryptedRollKeybag 等少见场景未覆盖 |
| APFS 时光快照 | 🟡 Beta | 枚举 + 恢复；Windows 上找不到 APFS 时给"未发现"提示 (v2.8.40 修) |

## 2. 文件系统 parser（业界对照）

每个 parser 严格对照 kernel 源码 / 规范文档，关键有 fuzz 覆盖。

| 文件系统 | 完成度 | 说明 |
|------|------|------|
| NTFS | 🟢 GA | MFT + Data run + LZNT1 + USN journal + fixup；fuzz 过 |
| APFS | 🟢 GA | omap + fs tree + LZFSE v1/v2 + LZVN；E2E 真盘过 |
| HFS+ | 🟢 GA | Catalog B-tree + decmpfs zlib + Extents overflow |
| ReFS | 🟡 Beta | Minstore page + 启发式 entry 提取；ReFS 3.x 主格式过，旧版未测 |
| Btrfs | 🟡 Beta | B-tree walker + chunk catalog + FS tree；snapshots 未覆盖 |
| XFS | 🟡 Beta | AG + inobt + bmbt extent + dir2；XFS v5 metadata CRC 过 |
| F2FS | 🟠 Preview | NAT + inode；Mobile 主路径过，但 F2FS metadata journal 未覆盖 |
| ZFS | 🟡 Beta | uberblock + dnode + LZ4/ZSTD + AES-GCM + RAIDZ1-3；dedupe 未覆盖 |
| exFAT | 🟢 GA | Boot + dir + cluster chain；Win 11 默认格式真盘过 |
| FAT12/16/32 | 🟢 GA | 经典 + 长文件名 (LFN) 全过 |
| ext2/3/4 | 🟢 GA | inode + dir + extent + journal；Linux 主路径过 |

## 3. RAID / 卷管理

| 功能 | 完成度 | 说明 |
|------|------|------|
| RAID 0/1/5/6/10 重组 | 🟢 GA | GF(2^8) Galois 域真实实现，单盘缺失重建 |
| mdadm metadata 识别 | 🟢 GA | v0.90 / v1.x 都过 |
| LVM2 / LVM Thin Pool | 🟡 Beta | 主路径过；snapshot 链未覆盖 |
| Microsoft Storage Spaces | 🟡 Beta | 简单 mirrored / parity；Storage Spaces Direct (S2D) 未覆盖 |

## 4. 移动 / 备份 / 云

| 功能 | 完成度 | 说明 |
|------|------|------|
| iOS 备份扫描 (.ab / iTunes) | 🟢 GA | 加密备份 keybag unlock + Manifest.db 解密；多版本过 |
| iOS 直连 (libimobiledevice) | 🟡 Beta | Pair + Trust + 触发 backup；只支持已配对设备 |
| Android ADB 拉取扫描 | 🟢 GA | adb pull 目录 + ./payload.bin AB image 解 |
| Android root 块级 dump | 🟡 Beta | adb shell su -c dd；需用户已 root |
| PTP 相机 (gphoto2) | 🟡 Beta | 拉所有照片 + 元数据；常见单反 / 微单 OK |
| MTP (Windows) | 🟡 Beta | WPD 接口；部分 Android 厂商不规范实现兼容性差 |
| 云备份枚举 (iCloud/OneDrive/Drive) | 🟠 Preview | 找本机已同步的备份目录；不连云端 API |

## 5. 加密 / 取证

| 功能 | 完成度 | 说明 |
|------|------|------|
| Ed25519 签名取证证据 | 🟢 GA | 离线密钥，仅内存；每次恢复签 manifest.json |
| RFC 3161 时间戳 | 🟡 Beta | 默认走 freeTSA；网络不可用时降级仅签名 |
| HTML 取证报告 | 🟢 GA | 含 hash 链 + 操作员 + 时间戳；浏览器可打开验证 |
| Evidence Bundle (zip) | 🟢 GA | 一键打包 manifest + signature + 报告 + 输入清单 |
| DFXML 标准取证报告 | 🟡 Beta | NIST 模式，但 schema v1.3 部分扩展字段未填 |
| 时间线 mactime/JSON 导出 | 🟢 GA | SleuthKit 兼容格式，含 mtime/atime/ctime/crtime |
| 保管链 (custody.json) | 🟢 GA | v2.8.39 修复 walk outputDir bug；只 hash 实际恢复文件 |
| NSRL hash 库匹配 | 🟡 Beta | 加载 NIST NSRL RDS；当前只标已知良性，未连官方 LookupAPI |
| SED OPAL 锁定状态 | 🟢 GA | 单层 TCG OPAL 真实 IOCTL 读取 |
| SMART 磁盘健康 | 🟢 GA | ATA + NVMe 都过 (v2.8.40-42 修)；NVMe 失败带诊断提示 |
| OCR 搜图 (Tesseract) | 🟠 Preview | 单文件 OCR + 关键词搜索；大目录有进度 + cancel |

## 6. UI / 工作流

| 功能 | 完成度 | 说明 |
|------|------|------|
| 单源盘扫描工作台 | 🟢 GA | 进度条 + 速度 + ETA + 已发现 + 6 大分类卡片 (Windows.old / 桌面 / 照片...) |
| 6 大分类挑选 | 🟢 GA | 自动归类；批量恢复支持 "恢复此类全部" |
| 文件预览 | 🟡 Beta | 图片 / 文本 / 部分 PDF；Office 未支持 |
| 增量恢复 (按 ID 列表) | 🟢 GA | 用户挑文件后只恢复选中项 |
| 失败重试 | 🟢 GA | 一键对失败 / 部分恢复的 ID 列表重跑 |
| 恢复完成报告 | 🟢 GA | 高可靠 / 低可靠 / 部分 / 失败 / 已拒绝 5 类计数；默认 tab=全部 (v2.8.39 修) |
| 工具菜单 (磁盘工具) | 🟢 GA | SMART / SED / GPT 备份 / NSRL / DFXML / Timeline / 保管链 / 多盘扫 等 |
| 计划备份 (Windows / macOS / Linux) | 🟢 GA | crontab / Task Scheduler；任务有人类可读描述 (v2.8.39 修) |
| 自动更新 | 🟢 GA | 签名验证 + downgrade 防护 + 回滚审计；Tag 驱动 GitHub Actions Release |
| 任务侧边栏 | 🟢 GA | 多任务并行 + 历史；cancel / 进度按盘独立 |
| 重复图片查找 | 🟡 Beta | perceptual hash；关闭 toast 即取消后台 (v2.8.39 修) |
| 网络镜像挂载建议 | 🟠 Preview | smb:// / nfs:// / iscsi:// URL → 给挂载步骤；不自动挂 |
| 诊断包导出 | 🟢 GA | 一键打包日志 + 配置 + 系统信息 zip；客服排错用 |

## 7. 性能优化（v2.8.37 以来累计）

| 优化 | 版本 | 效果 |
|------|------|------|
| carver ChunkSize 4MB → 8MB | v2.8.37 | syscall 占比 15% → 8% |
| chunkCh prefetch Workers×2 → Workers×4 | v2.8.37 | IO 领先 worker 2 圈 |
| validateAll 进度节流 | v2.8.37 | IPC 476× 减少 |
| parallel:fileFound 批量 + 瘦身 payload | v2.8.38 | IPC 50× + 带宽 -85% |
| scan:fileFound 批量 emit | v2.8.40 | IPC 200× |
| detector prefetchReader 256KB | v2.8.43 | detector 寻道 100× |
| classifier 共享 prefetch | v2.8.44 | collector 二次寻道 ↓ 0 |
| MP4/HEIC prefetch 1MB | v2.8.44 | sample table 命中率 ↑ |
| ResilientReader LBA poison cache | v2.8.44 | 坏区重试 **33,000×** |
| detector 从 chunk 内存读 | v2.8.45 | detector 零额外 IO |
| 碎片化检测后移到主扫描后 | v2.8.46 | 主扫描热路径无随机寻道 |

## 8. 跨平台

| 平台 | 完成度 | 说明 |
|------|------|------|
| Windows 10/11 amd64 | 🟢 GA | 主战场；release pipeline 签名 + 安装包齐全 |
| Windows arm64 | 🟡 Beta | 编译过；真机测试覆盖少 |
| macOS arm64 (Apple Silicon) | 🟢 GA | 开发主机；APFS / HFS+ 原生 |
| macOS amd64 (Intel) | 🟡 Beta | 编译过；只在 CI 烟测 |
| Linux amd64 (.deb/.rpm/tarball) | 🟡 Beta | 编译过；libwebkit2gtk 4.0 兼容；少数桌面环境主题异常 |

## 9. 质量保障（开发流程）

| 项 | 完成度 |
|----|----|
| `go test -race` | 🟢 全绿 (46 包) |
| `staticcheck ./...` Linux + Windows | 🟢 干净 |
| `gosec -severity=medium` | 🟢 0 issues (排除数据恢复固有 G115/G104/G304 等) |
| 关键 parser fuzz 覆盖 | 🟡 NTFS / APFS LZFSE 过；其它部分 |
| GitHub Actions CI (Build + Release) | 🟢 双 job 绿；自动签名 + 多平台产物 |
| 代码结构: Root 干净 | 🟢 v2.8.47 App 整个搬到 cmd/data-recovery (package appcore)；root 只剩 main.go (20 行) |
| 测试目录化 | 🟢 v2.8.46 抽出 internal/scanevent + internal/gpt；v2.8.47 测试紧邻 App 同包 |

## 10. 已知限制 / 未来路线（半透明）

| 项 | 状态 | 计划 |
|----|----|----|
| Storage Spaces Direct (S2D) | 🔴 未实现 | v2.9+ 路线 |
| Btrfs subvolume snapshots | 🔴 未实现 | v2.9+ 路线 |
| Office 文件预览 | 🔴 未实现 | 需引入 LibreOffice headless |
| OCR 搜图大目录性能 | 🟠 慢 | perceptual hash 单线程；v2.9 加并行 |
| 远程云 API 直连 (iCloud REST / Drive OAuth) | 🔴 未实现 | 政策 + 凭据存储复杂；当前只扫本机已同步缓存 |
| 移动端 root 自动化 | 🔴 未实现 | 需要 magisk / userdata 镜像挂载 |
| ZFS dedupe (DDT 表) | 🔴 未实现 | 稀有；按需求 |

## 11. 历史 6 大用户报错 bug 当前状态（v2.8.40 关闭）

| # | Bug | 修复版本 | 状态 |
|---|------|---------|------|
| 1 | SMART NVMe 不可用 | v2.8.40 + v2.8.42 文案 | ✅ |
| 2 | 查重 cancel 失效 | v2.8.39 | ✅ |
| 3 | 计划任务描述空 | v2.8.39 | ✅ |
| 4 | APFS 快照点击无反应 | v2.8.40 | ✅ |
| 5 | 保管链 walk outputDir | v2.8.39 | ✅ |
| 6 | 恢复完默认显示"未成功 0" | v2.8.39 | ✅ |

---

## PM 验收清单（v2.8.47）

PM 按这 6 个场景跑一遍即可签收：

| # | 场景 | 期望 | 状态 |
|---|------|------|------|
| 1 | 旧 NTFS / exFAT 移动盘"格式化后扫描" | 发现 ≥ 50% 用户文件 | ⬜ 待 PM 验 |
| 2 | BitLocker recovery key 解锁 + 扫描 | 成功列出明文卷文件 | ⬜ 待 PM 验 |
| 3 | 多盘并行扫描，期间点取消 | < 2s 内全部停止 IO | ⬜ 待 PM 验 |
| 4 | 跑一次恢复 → 检查 outputDir | 自动生成 `manifest.json` + `.sig` + `report.html` + `evidence.zip` | ⬜ 待 PM 验 |
| 5 | 1TB SATA 盘深度扫描 | 4-8 小时完成；扫描中速度 ≥ 几十 MB/s | ⬜ 待 PM 验 |
| 6 | Win11 / macOS Sonoma+ / Ubuntu 22.04 各装一次 | 包都能启动 + 选盘 + 扫描 + 恢复 | ⬜ 待 PM 验 |

## 反馈渠道

UI 内 "导出诊断包" → 发回研发邮箱 / Issue tracker。日志包含本次扫描的 IO / 内存 / 错误堆栈，定位 95% 的报错。

## 项目结构（v2.8.47 后）

```
data-recovery/
├── main.go                   # 20 行 thin bootloader
├── cmd/
│   ├── data-recovery/        # ⭐ App 整套实现 (package appcore，约 4000 行)
│   │   ├── app.go            #     IPC 方法 + 110+ Wails 绑定
│   │   ├── app_unlock_volumes.go
│   │   ├── admin_*.go        #     Windows / Unix 提权
│   │   ├── run.go            #     Wails 主循环装配
│   │   └── *_test.go         #     测私有字段的集成测试
│   ├── data-recovery-cli/    # CLI 工具
│   └── drift-check/          # CI 工具
├── internal/                  # ⭐ 41 个业务包
│   ├── carver/               #     深度签名雕刻
│   ├── ntfs/ apfs/ ext4/ ... #     文件系统 parser
│   ├── bitlocker/ luks/ ...  #     加密卷
│   ├── disk/                 #     底层块 IO + SMART
│   ├── scanevent/  ⭐ 新     #     扫描事件 helper（MergeProgress / FileFoundBatcher）
│   ├── gpt/                  #     含 PartitionInfo DTO + FormatGUID
│   └── ...
├── tests/                     # ⭐ 自包含集成测试（不依赖 App 私有字段）
│   ├── scanevent/            #     批量节流 / 进度合并
│   ├── dtocontract/          #     IPC JSON tag 契约
│   └── encryptedfastpath/    #     加密卷探测快速路径
├── frontend/                  # React UI (Wails 嵌入)
├── docs/                      # 含本 FEATURE_INVENTORY.md
└── go.mod / go.sum / Makefile / wails.json / *.md
```
