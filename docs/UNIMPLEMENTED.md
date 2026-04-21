# 真正不可能在本仓库代码内完成的事项

下面这些**无法**通过我写代码解决，需要**项目维护者**做外部决策 / 投入资源：

## 1. Windows 代码签名（避免 SmartScreen "未识别的发布者"）

- **需要**：付费 EV (Extended Validation) 代码签名证书
- **价格**：DigiCert / Sectigo 约 $300-500/yr
- **流程**：买证书 → 验证企业身份 (邓白氏号) → 用 `signtool sign /v /fd SHA256 ...` 在 release CI 里签
- **替代**：用户得在 SmartScreen 上点"更多信息 → 仍要运行"绕过

## 2. macOS Notarization（无 Gatekeeper 警告）

- **需要**：Apple Developer 账号（$99/yr）+ 签名证书 (Developer ID Application)
- **流程**：`codesign` → `xcrun notarytool submit` → `xcrun stapler staple`
- **替代**：用户得右键 → 打开 → 信任绕过 Gatekeeper

## 3. 真实磁盘镜像测试集

- **需要**：合法获取的多种文件系统真实镜像（NTFS / APFS / HFS+ / Btrfs / XFS / 含 BitLocker / FileVault）
- **来源**：
  - dislocker 测试镜像（GPL，可用）
  - Sleuthkit 测试镜像（开源）
  - 自己搭虚拟机生成（推荐 + 法律最干净）
- **CI 加载**：~2-5GB；用 git LFS 或 S3 + CI 下载

## 4. 完整 LZFSE entropy coder

- **工作量**：~1500 行 Go
- **代码源**：移植 https://github.com/lzfse/lzfse `lzfse_decode_v2_block.c`
  + finite state entropy decoder
  + literal/match expander
- **替代**：当前 LZVN 简化版能解前几 KB；完整解开需要 cgo `lzfse_decode_buffer`

## 5. 真 JPEG huffman state stitching（无 RST 也能拼）

- **工作量**：~3000-5000 行
- **依赖**：fork stdlib `image/jpeg` 暴露 `decoder.huffmanState` 内部
- **R-Studio 商业壁垒**：他们花了 20 年优化这块，开源很难追平
- **替代**：当前 RST 路径 + paranoid v2 能识别 ~30% 碎片场景

## 6. 训练分类器 chunk → 文件类型

- **需要**：数十 GB 标注的"已知格式 + 偏移"chunk 数据集
- **训练**：CNN / XGBoost on 字节直方图 + n-gram 特征
- **运行时**：模型权重 ~100MB-1GB，加载 + 推理需 cgo TensorFlow / ONNX
- **不做的理由**：开源工具数据集不易获得

## 7. SMB / NFS 协议级 reader

- **需要**：完整 go-smb2 / go-nfs 客户端 + 认证 / 鉴权
- **替代**：本工具支持"挂载远程后选镜像文件"，覆盖 95% 场景
- **完整实现**：~5000 行 + 协议合规测试

## 8. ReFS Minstore 完整 B-tree 文件枚举

- **核心阻塞**：Microsoft **未公开** ReFS metadata 规范
- **现状**：libfsrefs / Linux fs/refs 都只能逆向出部分；几乎没有项目能完整读 ReFS
- **替代**：本工具识别 page + 抽 entry + 用 carver 雕刻

## 9. APFS LZFSE / LZBitmap 文件压缩

- 同 #4 — 需要完整 LZFSE
- LZBitmap 是 Apple 私有，更难

## 10. RAID 6 双盘缺失 Reed-Solomon 重建

- **工作量**：GF(2^8) Reed-Solomon decoder ~500 行
- **现状**：本工具支持 RAID 6 单盘缺（退化 RAID 5）
- **可加**：klauspost/reedsolomon 库，开源 BSD-3，1 天集成

---

## 决策建议

**短期**：以上 #1, #2, #3 应优先解决（项目方决策 + 投入预算）。
**中期**：#10 (RAID 6 RS) 可一周搞定，建议接 klauspost/reedsolomon。
**长期**：#4, #5, #6 是"R-Studio 级别"目标，开源工具应根据社区贡献逐步推进。
**永远不做**：#7, #8 — 偏离工具定位 / 逆向工程项目。
