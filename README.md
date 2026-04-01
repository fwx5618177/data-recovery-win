# 🔧 数据恢复大师 v1.0

> 专业数据恢复工具 — 从重置/格式化的 Windows 系统中恢复丢失的数据

## 📋 项目概述

电脑被盗并被重置系统后，磁盘上的数据并未真正消失。本工具通过底层磁盘扫描技术，最大程度地找回丢失的文件。

### 核心技术

| 技术 | 原理 | 适用场景 |
|------|------|---------|
| **NTFS MFT 扫描** | 自动发现物理磁盘中的 NTFS 分区，解析主文件表（MFT），恢复已删除文件并尽量保留原始文件名和目录结构 | 误删、重装、整盘扫描 |
| **文件签名雕刻 (File Carving)** | 使用 Aho-Corasick 多模式匹配算法扫描磁盘原始数据，通过文件头部/尾部签名识别和提取文件 | 格式化后恢复、文件系统损坏 |
| **多线程流水线** | IO 线程顺序读盘 → N 个工作线程并行分析 → 收集线程去重汇总 | 最大化磁盘吞吐和 CPU 利用率 |
| **文件完整性验证** | 格式专用验证器（JPEG/PNG/PDF/ZIP/MP4/MP3）+ Shannon 熵分析 + SHA256 写入校验 | 确保恢复的文件可用 |

### 支持的文件类型

| 分类 | 格式 |
|------|------|
| 🖼️ 图片 | JPEG, PNG, GIF, BMP, TIFF, WebP, ICO, PSD, SVG |
| 📄 文档 | PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX, RTF |
| 🎬 视频 | MP4, AVI, MKV, MOV, FLV, WMV |
| 🎵 音频 | MP3, WAV, FLAC, OGG, AAC, WMA, M4A |
| 📦 压缩包 | ZIP, RAR, 7Z, GZIP, BZIP2 |
| 🗃️ 数据库 | SQLite |
| ⚙️ 其他 | EXE, DLL, ELF |

## 🏗️ 技术架构

```
Go 后端 (高性能磁盘扫描)          Wails IPC          React 前端 (简洁恢复流程)
┌─────────────────────────┐    ◄──────────►    ┌──────────────────────┐
│ disk/     磁盘原始读取    │    函数绑定         │ WelcomePage  驱动器选择│
│ signature/ Aho-Corasick  │    + Events        │ ScanningPage 扫描进度 │
│ carver/   多线程流水线    │                    │ ResultsPage  结果浏览 │
│ ntfs/     MFT 解析       │                    │ RecoveryPage 恢复完成 │
│ validator/ 完整性验证     │                    └──────────────────────┘
│ recovery/  恢复协调器     │
└─────────────────────────┘
```

### 多线程流水线架构

```
IO Goroutine (1个)          Worker Goroutines (N个)        Collector (1个)
┌───────────────┐           ┌───────────────────┐          ┌─────────────┐
│ 顺序读磁盘     │──chunk──►│ Aho-Corasick      │──match──►│ 去重         │
│ 4MB/块         │  chan     │ 签名匹配 + 格式解析 │  chan     │ 分类         │
│ 自动 overlap   │          │ 文件大小检测        │          │ 回调通知 UI   │
└───────────────┘           └───────────────────┘          └─────────────┘
                            × runtime.NumCPU()
```

### 项目结构

```
data-recovery/
├── main.go                          # Wails 入口
├── app.go                           # Wails 绑定（前后端桥梁）
├── admin_windows.go                 # Windows 管理员权限检测 + UAC 提权
├── admin_unix.go                    # Unix 权限检测
├── go.mod                           # Go 模块定义
├── wails.json                       # Wails 项目配置
├── Makefile                         # 构建脚本
├── build/windows/
│   └── wails.exe.manifest           # Windows manifest（默认请求管理员权限）
│
├── internal/
│   ├── types/
│   │   └── types.go                 # 共享类型定义
│   ├── disk/
│   │   ├── reader.go                # DiskReader 接口
│   │   ├── reader_windows.go        # Windows: CreateFileW + 扇区对齐
│   │   ├── reader_other.go          # macOS/Linux: 标准文件 IO
│   │   ├── drives.go                # ListDrives 入口
│   │   ├── drives_windows.go        # Windows 驱动器枚举
│   │   └── drives_other.go          # Unix 驱动器枚举
│   ├── signature/
│   │   ├── database.go              # 40+ 文件签名数据库
│   │   └── ahocorasick.go           # Aho-Corasick 多模式匹配 O(n+m+z)
│   ├── carver/
│   │   ├── engine.go                # 文件雕刻引擎（多线程流水线）
│   │   └── formats.go               # 8 种格式专用解析器
│   ├── ntfs/
│   │   ├── parser.go                # NTFS 引导扇区/MFT/属性/数据运行解析
│   │   └── recovery.go              # NTFS 恢复辅助逻辑
│   ├── validator/
│   │   └── validator.go             # 7 种格式验证器 + Shannon 熵分析
│   └── recovery/
│       ├── engine.go                # 恢复引擎（顶层协调器）
│       └── writer.go                # 安全文件写入 + SHA256 校验
│
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── main.jsx                 # React 入口
        ├── App.jsx                  # 根组件（页面流程 + 全局状态）
        ├── style.css                # 全局样式
        ├── formatters.js            # 展示格式化工具
        ├── recovery-helpers.js      # 恢复流程辅助逻辑
        └── components/
            ├── WelcomePage.jsx       # 驱动器选择 + 默认完整扫描说明
            ├── ScanningPage.jsx      # 实时扫描进度
            ├── ResultsPage.jsx       # 结果浏览 + 筛选 + 选择
            └── RecoveryPage.jsx      # 恢复进度 + 完成统计
```

## 🖥️ 系统要求

| 项目 | 要求 |
|------|------|
| **目标平台** | Windows 10/11（需要管理员权限） |
| **开发平台** | macOS / Linux / Windows |
| **Go** | 1.21 或更高版本 |
| **Node.js** | 16 或更高版本 |
| **Wails CLI** | v2.9+ |
| **内存** | 建议 4GB 以上 |

## 📦 安装与构建

### 1. 安装前置依赖

```bash
# 安装 Go (https://go.dev/dl/)
# 安装 Node.js (https://nodejs.org/)

# 安装 Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# 检查环境
wails doctor
```

### 2. 克隆项目并安装依赖

```bash
cd data-recovery

# 安装 Go 依赖
go mod tidy

# 安装前端依赖
cd frontend && pnpm install && cd ..
```

### 3. 开发模式运行

```bash
# 启动开发服务器（热重载）
wails dev
```

### 4. 构建发布版本

```bash
# 构建当前平台
wails build

# 从 macOS 交叉编译 Windows 版本
wails build -platform windows/amd64

# 输出: build/bin/DataRecovery.exe
```

### 使用 Makefile

```bash
make deps           # 安装所有依赖
make dev            # 开发模式
make build          # 本地构建
make build-windows  # 交叉编译 Windows
make clean          # 清理构建产物
```

## 🚀 使用指南

### 步骤 1：直接启动程序

Windows 版本默认在启动时请求管理员权限。双击 `DataRecovery.exe` 后请确认 UAC 授权。

> ⚠️ 读取磁盘原始数据必须有管理员权限。若拒绝 UAC，程序将无法执行真实扫描。

### 步骤 2：选择目标磁盘

在欢迎页面中，程序会列出所有可用的物理磁盘和逻辑分区。选择被重置的磁盘。

### 步骤 3：直接执行默认完整恢复扫描

前端不再暴露复杂扫描策略。程序默认执行最完整的恢复流程：
- 自动发现物理磁盘里的 NTFS 分区
- 扫描 MFT 并重建可恢复文件路径
- 执行文件雕刻补齐未被文件系统索引的内容
- 对候选文件做完整性验证

### 步骤 4：等待扫描

扫描过程中可以实时查看：
- 扫描进度和速度
- 已发现的文件列表
- 预计剩余时间

### 步骤 5：筛选和选择文件

在结果页面中：
- 按分类浏览（图片、文档、视频...）
- 按来源筛选（NTFS / 雕刻）
- 按有效性筛选
- 搜索文件名
- 勾选需要恢复的文件

### 步骤 6：恢复文件

选择输出目录（**必须是其他磁盘/U盘/移动硬盘**），点击恢复。

恢复过程包括：
1. 从磁盘原始数据中读取文件内容
2. 写入临时文件
3. SHA256 校验确保数据完整
4. 重命名为最终文件

## ⚠️ 重要注意事项

1. **立即行动** — 被删除/重置的数据随时可能被新数据覆盖，越早恢复成功率越高
2. **不要写入源盘** — 恢复的文件必须保存到其他存储设备，否则可能覆盖未恢复的数据
3. **管理员权限** — 读取磁盘原始数据的必要条件
4. **SSD 注意** — SSD 的 TRIM 机制可能已擦除部分数据，恢复率低于机械硬盘
5. **文件完整性** — 雕刻恢复的文件可能不完整，建议逐个检查
6. **耐心等待** — 默认完整扫描会比传统“快速扫描”更慢，但更适合系统被重置后的大范围恢复

## 🔬 核心算法说明

### Aho-Corasick 多模式匹配

传统方法对 40+ 个文件签名逐个搜索，复杂度 O(n×k)。本工具使用 Aho-Corasick 自动机，单次线性扫描同时匹配所有签名，复杂度 **O(n+m+z)**，提速约 40 倍。

### 格式专用文件边界检测

| 格式 | 算法 |
|------|------|
| JPEG | 解析 FF marker 链 → SOS → 熵编码数据扫描 → FFD9 EOI |
| PNG | 遍历 chunk 链（length + type + data + CRC）直到 IEND |
| PDF | 搜索最后一个 `%%EOF` 标记 |
| ZIP | 搜索 EOCD (End of Central Directory) 签名 |
| MP4 | 解析顶层 atom/box 链（支持 64-bit extended size） |
| MP3 | 解析 ID3v2 syncsafe integer + 验证连续帧头 |
| RIFF | 读取 4 字节 LE 文件大小字段 |
| OLE2 | 根据 sector power 和 FAT sector count 计算大小 |

### SHA256 写入验证

每个恢复的文件都经过双重校验：
1. 读取时计算 SHA256
2. 写入后重新读取计算 SHA256
3. 两次哈希必须一致，否则标记为写入失败

## 🛠️ 开发说明

### 项目依赖

**Go 依赖：**
- `github.com/wailsapp/wails/v2` — 桌面应用框架
- `golang.org/x/sys` — Windows 系统调用

**前端依赖：**
- `react` 18+ — UI 框架
- `vite` 5.0+ — 构建工具

### 跨平台构建标签

项目使用 Go build tags 实现跨平台：
- `//go:build windows` — Windows 专用代码（磁盘读取、驱动器枚举、管理员检测）
- `//go:build !windows` — macOS/Linux 兼容代码（开发测试用）

### 前端开发模式

前端包含完整的模拟数据，即使没有 Wails 后端也能独立运行和调试：

```bash
cd frontend
pnpm run dev
# 访问 http://localhost:5173
```

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
