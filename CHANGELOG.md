# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **NTFS LZNT1 压缩文件解压** —— 带 "压缩内容以节省磁盘空间" 属性的 NTFS 文件现在能正确恢复为原始内容（此前拿到的是压缩后的二进制）
- **Volume Shadow Copy 枚举（Windows）** —— 调用 `vssadmin list shadows` 解析系统还原点 / VSS 快照，用户能从重装前的快照里找文件
- **VSS 扫描入口** —— WelcomePage 新增一块，列出所有快照（含时间戳 / 原始卷），点击即可扫描
- **自动更新（重启生效）** —— 后台下载新版本到 pending 目录 + manifest，用户点"立即重启"时 helper 进程替换 exe 并启动新版
- **镜像扫描入口** —— 选择 `.img/.dd/.raw` 文件作为扫描源
- **整盘 dump 到镜像**（带坏道跳过 + 比例熔断）
- **FAT12/16/32 支持** —— 老 U 盘 / SD 卡 / 老相机存储卡
- **exFAT FAT 链支持** —— 碎片化 exFAT 文件现在能完整恢复（此前只支持连续存储）
- **NTFS $ATTRIBUTE_LIST** —— 极碎片化大文件 MFT 记录溢出时的子条目合并
- **NTFS 已删除分区扫描** —— 分区表被重写后仍能定位旧 NTFS 分区
- **NTFS ADS 枚举** —— 命名 $DATA 流元数据收集
- **签名库扩展** —— HEIC / HEIF / AVIF / CR2 / CR3 / DjVu / MIDI / XZ 等现代格式
- **图片预览** —— 从源盘直接读前若干字节预览图片
- **Windows.old 识别** —— 重置后保留的旧系统目录里的用户数据高优先级标记

### Changed
- Carver 默认跳过 `.ico / .exe / .elf` 噪声签名（用户数据恢复场景价值低）
- 系统文件（`.exe / .dll / .sys` 等）默认从扫描结果里隐藏，界面多一个开关
- 扫描进度条权重重新分配（NTFS 0-12% / exFAT 12-14% / FAT 14-15% / Carver 15-95% / Validate 95-100%）
- NTFS 暴力搜索引导扇区从 "每 1MB 一次 512B 读" 改为 "4MB 块 + 512KB 步进"，大盘上 IO 次数减少 ~8000x

### Fixed
- 跨源 SHA-256 去重排序：NTFS 优先保留（字母序 "carver" < "ntfs" 反而让 carver 先落地的经典坑）
- NTFS 部分写入时 SHA256 / 时间戳不再回填（避免被删文件在 manifest 里误留痕迹）
- 启动恢复失败不再把用户甩到空白报告页
- Carver 内存：sync.Pool 复用 chunk 缓冲 + `seen` map 水位线裁剪，大盘不再越扫越慢
- ICO 格式检测收紧（color planes / bit count / 数据偏移校验），减少自由空间噪声误报
- 更新检查器 3 个 bug：
  - `os.Signal(nil)` → 改成固定等待 + 指数退避重试
  - `Asset.DownloadURL` JSON tag 对外走 camelCase `downloadUrl`（不泄露 GitHub API 契约）
  - `DownloadProgress` 字段加 JSON tag，前端进度不再永远 0%

### Infrastructure
- CI 覆盖 Windows amd64 / arm64 / Linux amd64（macOS 因 Wails 产物路径异常暂移除）
- `go test -race ./...` 全套通过（11 个 Go 包）
- Node.js 20 deprecation：workflow 顶层 `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` 迁移

## [v1.2.0] - 前期

详见 git log。
