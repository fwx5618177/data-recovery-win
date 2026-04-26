# 数据恢复大师

开源、跨平台、完全离线的数据恢复工具。专为"电脑被盗 / 系统被重置 / 误删 / 误格式化 / BitLocker 锁住 / RAID 崩盘"等真实场景设计。

[![Release](https://img.shields.io/github/v/release/fwx5618177/data-recovery-win)](../../releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](./LICENSE)
[![staticcheck](https://img.shields.io/badge/staticcheck-0%20warnings-green)]()
[![gosec](https://img.shields.io/badge/gosec-0%20issues-green)]()

---

## 下载安装

**Windows / Linux**：[Releases 页面](../../releases) 下对应平台。

首次运行需管理员权限（读原始磁盘扇区必需）：
- **Windows**：双击 exe，接受 UAC
- **Linux**：`sudo ./DataRecovery-linux-amd64`

> 验证下载文件完整性（推荐）：
> ```bash
> sha256sum -c SHA256SUMS.txt
> openssl pkeyutl -verify -pubin -inkey release_pubkey.pem \
>   -rawin -in SHA256SUMS.txt -sigfile SHA256SUMS.txt.sig
> ```

---

## 支持的设备

| 设备类型 | 连接方式 | 推荐度 |
|---|---|---|
| **机械硬盘 HDD** | SATA / USB 硬盘盒 | ⭐⭐⭐⭐⭐ 最推荐 |
| **笔记本拆出的硬盘** | 硬盘盒外接 | ⭐⭐⭐⭐⭐ 被盗场景 |
| **SSD** | 同上 | ⭐⭐⭐ TRIM 前能恢复，TRIM 后物理归零 |
| **U 盘 / SD 卡 / 相机卡** | 直接插 USB | ⭐⭐⭐⭐ |
| **Android 手机存储** | 通过读卡器读内置 eMMC / UFS 镜像 | ⭐⭐⭐ F2FS 基础枚举 |
| **NAS 硬盘** | 拆出后硬盘盒 | ⭐⭐⭐⭐ 支持 RAID 重组 |
| **磁盘镜像文件** | `.img` / `.dd` / `.raw` / `.vhd` / `.vhdx` | ⭐⭐⭐⭐⭐ **最安全** |
| **VSS 卷影副本** | 直接扫 Windows 系统快照 | ⭐⭐⭐⭐ 重装后找回旧文件 |

> **强烈推荐**先用 `ddrescue` / `HDDSuperClone` 把源盘 dump 成镜像，再扫镜像。源盘只读一次，后续所有分析在镜像上做 —— 防写入、能反复试。

---

## 支持的文件系统

| 文件系统 | 识别 | 文件枚举 | 已删除恢复 | 常见场景 |
|---|:-:|:-:|:-:|---|
| **NTFS** | ✅ | ✅ MFT 深度 | ✅ | Windows 系统盘、U 盘、移动硬盘 |
| **FAT12 / FAT16 / FAT32** | ✅ | ✅ | ✅ | 老 U 盘、相机卡、启动盘 |
| **exFAT** | ✅ | ✅ | ✅ | 现代 U 盘 / SD 卡 / Xbox |
| **ext2 / ext3 / ext4** | ✅ | ✅ extent tree | ✅ | Linux 系统 / Android |
| **APFS** | ✅ | ✅ omap + fs B-tree | ✅ | macOS 10.13+ / iOS |
| **HFS+ / HFSX** | ✅ | ✅ Catalog B-tree | ⚠️ 残留 | Time Machine 备份 |
| **Btrfs** | ✅ | ✅ FS-tree + chunk catalog + 路径回溯 | ✅ | openSUSE / Synology NAS |
| **XFS** | ✅ | ✅ inobt + bmbt | ⚠️ | RHEL / CentOS |
| **F2FS** | ✅ | ✅ NAT + inode | ⚠️ | Android / 嵌入式 |
| **ZFS** | ✅ | ✅ dnode + ZAP micro | ⚠️ | TrueNAS / FreeBSD |
| **ReFS** | ✅ | 🔶 启发式提取 | ⚠️ | Windows Server / Win11 Pro |
| **LUKS / LUKS2** | ✅ | ✅ 真解锁后扫（PBKDF2 + Argon2id + AFsplitter + AES-XTS / CBC-ESSIV） | ✅ | Linux 加密盘 |
| **VeraCrypt / TrueCrypt** | ✅ | ✅ 真解锁后扫（PBKDF2-SHA512/256/RIPEMD-160 + AES/Twofish/Serpent + cascade + PIM） | ✅ | 跨平台加密 |

---

## 加密卷解锁

| 加密 | 解锁方式 | 状态 |
|---|---|---|
| **BitLocker** (AES-XTS) | Recovery key (48 位) | ✅ |
| **BitLocker** (AES-XTS) | 用户密码 | ✅ |
| **BitLocker** (AES-XTS) | Startup key (BEK 文件) | ✅ |
| **BitLocker** (AES-XTS) | TPM 卷的内存镜像 VMK 暴力搜 | ✅ 支持 `hiberfil.sys` / winpmem / DumpIt / VMware `.vmem` |
| **BitLocker** (AES-CBC + Elephant Diffuser) | Vista / Win7 老格式 | ✅ |
| **FileVault** (APFS 加密卷) | 用户密码 | ✅ 完整链：keybag → PBKDF2 → AES-KeyWrap → VEK |
| **ZFS native encryption** | 用户密码 | ✅ PBKDF2-SHA512 + AES-KeyWrap + HKDF + AES-GCM |
| **LUKS1 / LUKS2** | 用户密码 | ✅ PBKDF2 + Argon2id KDF + AFsplitter + AES-XTS-plain64 / CBC-ESSIV / CBC-plain；4K sector + sha1/sha512 csum + 跨 keyslot 进度回调 |
| **VeraCrypt / TrueCrypt** | 用户密码 [+ PIM] | ✅ PBKDF2-{SHA-512/256/RIPEMD-160} × {AES-XTS, Twofish-XTS, Serpent-XTS, AES-Twofish/Twofish-Serpent/Serpent-AES cascade, AES-Twofish-Serpent/Serpent-Twofish-AES 3-cipher cascade}；含系统加密 layout (offset 31744) + auto-detect 路径 |

**BitLocker TPM 卷**：自动扫描挂载盘内 `C:\hiberfil.sys` / `C:\Windows\MEMORY.DMP` 等作为候选 memory image。

---

## RAID / 存储池

| 类型 | 支持 | 说明 |
|---|:-:|---|
| **RAID 0** | ✅ | 任意条带宽度 |
| **RAID 1** | ✅ | 镜像 |
| **RAID 5** | ✅ | left-symmetric，单盘缺失 XOR 重建 |
| **RAID 6** | ✅ | GF(2⁸) Reed-Solomon 双盘缺失 |
| **RAID 10** | ✅ | mirror pair × stripe |
| **mdadm 自动检测** | ✅ | 读 v1.x superblock，按 array UUID 跨盘分组 + role 排序 |
| **ZFS RAIDZ1** | ✅ | XOR 重建 |
| **ZFS RAIDZ2** | ✅ | 单缺 / 双 data / P+data / Q+data / 双 parity 全组合 |
| **ZFS RAIDZ3** | ✅ | 3 data 盘同时缺（3×3 Vandermonde GF 求逆） |
| **LVM2** | ⚠️ | 识别，建议原系统 `vgchange -ay` 后挂载再扫 |
| **Windows Storage Spaces** | ⚠️ | 识别，建议在原 Windows 挂载池后再扫 |

---

## 碎片重组 (Carving + Stitching)

大多数工具只能 carve "连续扇区" 的文件。本工具对**碎片化**文件做深度重组：

| 格式 | 算法 | 原理 |
|---|---|---|
| **JPEG** | block-graph stitching + entropy 健康度 | RST marker 序号约束 + 熵流非法 marker 比例检测 |
| **PNG** | chunk CRC32 驱动 | 每 chunk 独立 CRC → 拼接正确性数学可验证 |
| **MP4 / MOV / HEIC** | atom 自述 size 链 | box size 做硬边界 + moov+mdat 双命中验证 |
| **ZIP** | Central Directory 反查 | 从文件尾 EOCD 跳到 CD → 按 entry LocalHeader offset 读取；支持 ZIP64 |
| **PDF** | startxref 偏移验证 + obj 数量兜底 | 解 startxref 值验证 xref 表位置 + 兼容 PDF 1.5+ xref stream |

### 深度雕刻签名库
30+ 文件类型签名：图像、文档、音频、视频、压缩、数据库、邮件、虚拟机、3D 模型、CAD 图纸等。

---

## 压缩算法

| 压缩 | 实现 | 用途 |
|---|---|---|
| **LZNT1** | 纯 Go | NTFS 压缩文件 |
| **LZX** | 纯 Go（780 行） | WIM / Compact OS / Exchange |
| **LZFSE v1 / bvxn (LZVN)** | 纯 Go | macOS decmpfs 默认小文件 |
| **LZFSE v2 / bvx2** | 纯 Go FSE | macOS decmpfs 大文件 |
| **LZ4** | 纯 Go（本地实现） | ZFS 默认压缩 |
| **ZSTD** | klauspost/compress | ZFS / Btrfs 现代压缩 |
| **zlib (deflate)** | 标准库 | HFS+ decmpfs / Btrfs / 通用 |

---

## 取证功能（B2B 差异化）

每次恢复自动生成：

| 文件 | 内容 |
|---|---|
| `custody.json` | 保管链：工具版本 / 操作员 / 时间 / 源盘 / 每文件 SHA-256 / manifest 自 SHA-256 |
| `custody.signed.json` | 上述 + Ed25519 数字签名 + RFC 3161 时间戳 |
| `evidence_report.html` | 专业取证报告（浏览器 Ctrl+P 可打成 PDF） |
| `evidence.zip` | 一键交付包：以上全部 + 公钥 + 校验脚本 + README |

**证据链强度**：
- 签名：本地 Ed25519（PBKDF2 派生，支持扩展到 HSM/KMS）
- 时间戳：默认 freetsa.org / digicert / sectigo（RFC 3161 可信 TSA）
- 第三方可用 `openssl ts -verify` + `bash verify.sh` 独立校验

---

## 文件完整性校验

恢复前 validator 检测碎片化文件，避免"半截图打开失败":

- **JPEG**：扫 SOS 之后到 EOI 之间的熵流非法 marker 比例（检出 NTFS 碎片 extent）
- **PNG**：chunk CRC 验证
- **PDF**：startxref 偏移在文件内 + 指向有效 xref / xref stream
- **MP4**：moov + mdat 必须双命中 + box 链完整遍历

低健康度文件自动分到 `_low_confidence/` 子目录，不冒充"成功"。

---

## 自动更新（外部审计级）

每次发布新版本，已安装用户自动获取更新，**完全静默**：

```
启动 → 检测 pending（上次下载好的新版）→ 替换 exe → 拉起新版
↓
3 秒后后台 check GitHub → 新版本？
  ├─ rollback 防护（IsVersionNewer 严格单调）
  ├─ 自动下载新版 binary
  ├─ 验证 SHA256 对比 SHA256SUMS.txt
  ├─ 验证 Ed25519 签名（代码内 pin 公钥）
  └─ 写 pending，下次启动时替换
```

安全保障（完整威胁模型见 [SIGNING.md](./SIGNING.md)）：
- TLS + HTTPS
- SHA256 比对
- Ed25519 签 SHA256SUMS.txt
- 公钥 build-time pin（防攻击者替换公钥）
- Rollback 攻击防护
- Apply 失败自动回滚（保留旧版 backup）
- JSONLines 审计日志 `$CONFIG/data-recovery/update_audit.log`
- `DATA_RECOVERY_NO_AUTO_UPDATE=1` 可 opt-out

---

## 典型使用场景

### 1. 电脑被盗 / 被重置

1. 拆硬盘 → 用硬盘盒外接到另一台电脑（**不要**把盘装回或格式化）
2. 用 `ddrescue` 整盘 dump 到大容量目标盘：
   ```bash
   ddrescue --no-scrape /dev/sdX /path/to/image.img /path/to/map.log
   ```
3. 启动本工具 → 选镜像文件 → 完整扫描
4. BitLocker 自动检测 → 填 recovery key 或 hiberfil.sys 路径
5. 选文件恢复到**另一块物理盘**（同盘保护自动阻止）
6. 恢复完成自动生成 `evidence.zip` 可作司法存证

### 2. U 盘误格式化

1. 插 U 盘，**不要**写任何东西
2. 启动工具 → 选 U 盘 → 完整扫描（含 NTFS MFT + FAT dir + 深度 carver + 签名识别）
3. `_low_confidence/` 子目录放可能碎片化文件，建议手动打开确认

### 3. NAS 硬盘 RAID 恢复

1. 把 NAS 所有硬盘同时接到一台 Linux / 带多 SATA 口的机器
2. 本工具 → "RAID 自动检测" → 选所有盘 → 自动识别 mdadm / ZFS 阵列
3. 组装后虚拟盘 → 常规扫描

### 4. 系统重装后找回老文件

1. 管理员 CMD / PowerShell → `vssadmin list shadows`
2. 本工具启动时自动列出所有 VSS 快照
3. 选重装前的快照 → 扫描 → 恢复

---

## 质量保证

```
Go 包数量：30+  |  代码行数：~40,000
静态分析（staticcheck / gosec）：0 警告
并发安全（go test -race -count=10 核心包）：0 DATA RACE
Fuzz 覆盖（NTFS / APFS / carver / Btrfs parser）：2500 万次执行
Fuzz + 组件 round-trip 抓到的真 bug：13 个（全部已修 + 加回归测试）
跨平台交叉编译：Windows amd64/arm64 / Linux amd64 / macOS arm64
CI：staticcheck + gosec + race test 每 PR 跑
```

---

## 对比业内工具

本工具不取代专业商业工具（R-Studio 有 20 年真实案例积累，开源工具很难追平）。**定位差异化**：

| 维度 | 本工具 | PhotoRec | R-Studio | EaseUS |
|---|:-:|:-:|:-:|:-:|
| 开源可审计 | ✅ | ✅ | ❌ | ❌ |
| 取证证据链（签名+时间戳） | ✅ | ❌ | ❌ | ❌ |
| BitLocker 解锁 | ✅ 全套 | ❌ | ✅ 全套 | 🟡 部分 |
| ZFS 完整栈（LZ4/ZSTD/加密/RAIDZ） | ✅ | ❌ | ❌ | ❌ |
| 碎片重组 | 🔶 基础 | ❌ | ✅ 业界第一 | ✅ |
| 真实案例沉淀 | ❌ 新项目 | ✅ 20 年 | ✅ 20 年 | ✅ 10 年 |

**用法建议**：关键数据用 PhotoRec + R-Studio Demo + 本工具**交叉验证**，三者结果对比。

---

## 物理上做不到的事

| 场景 | 为什么 |
|---|---|
| SSD 完全 TRIM 后 | 控制器物理归零，数据在硬件层消失 |
| 整盘写零 / 安全擦除 | 旧数据被真实覆盖 |
| 没 recovery key 且无原机内存 | TPM 密钥在原机硬件里，跨平台无法获取 |
| 磁头损坏 / 物理坏道 | 必须先用 ddrescue 抢救，本工具吃镜像 |

---

## 从源码构建

```bash
# 需要 Go 1.22+ / Node 20+ / Wails v2.12.0
go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
cd frontend && pnpm install && cd ..

# 开发模式（热重载）
wails dev

# 发布构建
wails build -platform windows/amd64
wails build -platform linux/amd64

# 测试
go test -race ./...
staticcheck ./...
```

---

## 隐私保证

- 🔒 **完全离线**：除"检查 GitHub 新版"外不连任何外网
- 🔒 **密钥不落盘**：BitLocker key / FileVault key / 内存 VMK 只在内存使用
- 🔒 **只读源盘**：扫描全程源盘只读
- 🔒 **同盘保护**：输出目录必须不同物理盘（Windows IOCTL 真实校验）
- 🔒 **无遥测**：不收集任何使用数据
- 🔒 **诊断包透明**：只含日志 + session，导出前可自行审查

---

## 文档

- [SIGNING.md](./SIGNING.md) — 自动更新安全模型 + 密钥管理 + 外部审计 checklist
- [CHANGELOG.md](./CHANGELOG.md) — 版本历史

---

## License

AGPL-3.0 — 确保所有修改版本保持开源，B2B 友好。

## 致谢

参考开源项目：sleuthkit / dislocker / libfsapfs / btrfs-progs / openzfs / klauspost/compress
