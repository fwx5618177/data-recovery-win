# Data Recovery / 数据恢复大师

> 帮被偷电脑 / 误删 / 误格式化 / BitLocker 锁住等场景下的用户找回数据。
> 开源、跨平台、零网络（一切操作在本地完成，密钥不上云）。

A free open-source data recovery tool for stolen laptops, accidental deletions,
quick formats, BitLocker-locked drives, and similar scenarios. Cross-platform,
fully offline, no telemetry, no key escrow.

---

## 主要能力 / Features

### 文件系统识别 + 文件枚举
- ✅ **NTFS** — 完整 MFT 解析 + 已删除文件 + ADS + LZNT1 解压
- ✅ **FAT12 / FAT16 / FAT32 / exFAT** — 含已删除目录项
- ✅ **ext2 / ext3 / ext4** — 含 ext4 extent tree + 删除残留检测
- ✅ **APFS** — 容器/卷枚举 + omap + fs B-tree 完整文件遍历
- ✅ **HFS+ / HFSX** — Catalog B-tree 文件枚举
- 🔍 **ReFS** — 卷头识别 + Minstore page 索引（B-tree 完整解尚未做）

### 加密卷解锁
- ✅ **BitLocker** — Recovery key / 用户密码 / Startup key (BEK) / **TPM 卷的内存镜像 brute-force**
- ✅ **AES-XTS-128/256** — Win10+ 默认
- ✅ **AES-CBC + Elephant Diffuser** — Vista/Win 7 老格式
- ⚠️ **FileVault** — XTS 解 cipher + PBKDF2 派生已就绪；keybag → KEK → VEK 完整链尚未做

### RAID 虚拟重组
- ✅ **RAID 0** — 任意条带大小
- ✅ **RAID 1** — 镜像
- ✅ **RAID 5 (left-symmetric)** — 单盘缺失实时 XOR 重建

### 深度签名雕刻 (Carving)
- ✅ 30+ 文件类型（图像 / 文档 / 音频 / 视频 / 压缩 / 数据库）
- ✅ 碎片化检测 (paranoid level 2): 多点采样 + 字节熵突变 + 格式专项

### Windows VSS 卷影副本
- ✅ vssadmin 解析（中英 / Win 11 时间格式都支持）
- ✅ 直接扫快照设备 `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`

### 工程能力
- ✅ 多线程流水线（IO 单线程 + 多线程分析 + 单线程写）
- ✅ 会话恢复（中途崩溃后能从快照接着扫）
- ✅ 自动更新（GitHub Releases + 重启时应用）
- ✅ 诊断包导出（一键打包日志 / session / 平台信息成 zip）
- ✅ i18n 框架（中文 / English）

---

## 快速开始 / Quick Start

### 二进制下载

去 [Releases](../../releases) 下载对应平台的预编译版：
- `data-recovery-windows-amd64.exe`
- `data-recovery-darwin-arm64.app.tar.gz`（Apple Silicon）
- `data-recovery-darwin-amd64.app.tar.gz`（Intel Mac）
- `data-recovery-linux-amd64`

### Windows
双击 `.exe`。首次运行会请求 UAC（必须管理员才能读原始磁盘）。

### macOS
解压 `.tar.gz`，把 `.app` 拖到 `/Applications`。**首次启动**会弹密码框（用 osascript
让 Finder 弹原生 Touch ID / 密码对话框，授权后以 root 权限重启 — 这是读原始磁盘必需的）。

如果对话框被取消、或者命令行启动想跳过自动 sudo：
```sh
sudo /Applications/Data\ Recovery.app/Contents/MacOS/data-recovery
# 或不要自动提权
DATA_RECOVERY_NO_AUTO_SUDO=1 /Applications/Data\ Recovery.app/Contents/MacOS/data-recovery
```

### Linux
```sh
chmod +x data-recovery-linux-amd64
sudo ./data-recovery-linux-amd64
# 或装 polkit 后用图形化提权
pkexec ./data-recovery-linux-amd64
```

---

## 典型场景 / Typical Workflows

### 1. 被偷的笔记本，硬盘单独取出来扫
1. 把被取出的硬盘通过硬盘盒 / SATA-USB 连到本机
2. 启动本工具，授权管理员
3. 选刚连上的盘 → 选"完整扫描" → 等待
4. 在结果里勾选要恢复的文件 → 选输出目录（必须**不同**物理盘）→ 立即恢复

### 2. BitLocker 加密盘 + 有 recovery key
1. 选盘后，工具会自动检测出 BitLocker 卷预警
2. 点该卷的"解锁并扫描" → 输入 48 位 recovery key
3. 派生 1-2 秒后自动进入扫描

### 3. BitLocker TPM-only 卷（没 recovery key）
要先从原机抓内存镜像或 hiberfil.sys：
- 原机能开机：管理员 PowerShell 跑 `winpmem.exe -o C:\mem.raw`
- 或抓休眠文件：`copy /b C:\hiberfil.sys D:\hiberfil.sys`（必须管理员 + 系统 attrib）

然后在 BitLocker 解锁对话框切到 "内存镜像 (TPM)" 标签，输入路径，扫 2-3 分钟（4GB 镜像）。

### 4. RAID 阵列重组
准备好所有盘 / 镜像文件路径，按"原阵列编号"顺序：
```
RAID5: [/dev/sda, /dev/sdb, /dev/sdc]  stripe=64KB
RAID5 缺一盘: [/dev/sda, "", /dev/sdc]  → 自动从 P 重建
```
（当前 RAID UI 暂时通过 IPC 调用，CLI 入口规划中）

### 5. Windows 系统重装后用 VSS 找回数据
工具启动时会自动列出本机 Volume Shadow Copy，每个快照可单独扫，
"R-Studio 时光机"模式 — 重装前的旧文件常完好保留在快照里。

---

## 安全与隐私 / Security & Privacy

- 🔒 **零网络**：除了"自动检查 GitHub 是否有新版"外，本工具**不**连接任何外网
- 🔒 **密钥不落盘**：BitLocker recovery key / 内存镜像里搜出的 VMK 全部只在内存里用
- 🔒 **只读源盘**：扫描全程对源盘只读；恢复目录强制必须在不同物理盘
- 🔒 **无遥测**：不收集任何使用数据
- 🔒 **诊断包透明**：导出诊断 zip 只含日志 / session / pending update info，
  打开看清楚再发出去

---

## 不能做什么 / Limitations

| 想做的事 | 现状 |
|---|---|
| 完全格式化（写零）后恢复 | ❌ 物理上不可能 |
| SSD + TRIM 后恢复 | ❌ TRIM 会让控制器把对应块物理归零 |
| BitLocker 没 recovery key 也没原机内存 | ❌ TPM 在原机硬件里，跨平台无法解 |
| FileVault 没用户密码 | ⚠️ 理论可，需 keybag 完整解（路线图中） |
| 严重碎片化文件的精确重组 | ⚠️ R-Studio 商业版的核心壁垒；本工具能告诉你"这个文件可能是碎片化的" |
| 物理坏盘 / 磁头损坏 | ❌ 必须先用 ddrescue 抢救成镜像，再用本工具扫镜像 |

被偷电脑 + SSD + TRIM 几乎是绝望组合。机械硬盘 + 仅快速格式化 / 重装是希望最大的场景。

---

## 行业对照工具 / Reference Tools

如果本工具不能解你的问题，这些是行业主流：

| 工具 | License | 强项 |
|---|---|---|
| [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec) | GPL | 签名雕刻，命令行，跨平台 |
| [TestDisk](https://www.cgsecurity.org/wiki/TestDisk) | GPL | 分区表恢复 |
| [R-Studio](https://www.r-studio.com/) | 商业 | 碎片重组业界第一 + 老牌 RAID |
| [DMDE](https://dmde.com/) | Free / Pro | 文件系统级深度修复 |
| [dislocker](https://github.com/Aorimn/dislocker) | GPL | BitLocker 解锁 + FUSE 挂载 |

---

## 从源码构建 / Build from Source

需要 Go 1.22+ / Node 20+ / Wails v2.12.0。

```sh
go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
cd frontend && pnpm install && cd ..

wails build -platform windows/amd64
wails build -platform darwin/arm64
wails build -platform linux/amd64

go test -race ./...
```

---

## 贡献 / Contributing

欢迎贡献。优先级最高的（路线图）：
- FileVault keybag 完整解
- APFS LZFSE / LZVN 解压
- 真正的碎片重组（block-graph for JPEG/PDF）
- ReFS Minstore B-tree 完整解析（无公开规范，需逆向）
- TUI / CLI 模式

---

## License

MIT（占位；以仓库根 `LICENSE` 文件为准）
