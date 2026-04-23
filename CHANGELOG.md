# 版本历史

遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

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
