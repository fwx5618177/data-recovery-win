# 已知限制

这些事项**不在代码范围内**，需要项目方投入资源 / 外部决策才能解决。

---

## 1. Windows 代码签名（避免 SmartScreen 警告）

- **需要**：付费 EV (Extended Validation) 代码签名证书
- **价格**：DigiCert / Sectigo 约 $300-500 / 年
- **流程**：买证书 → 验证企业身份（邓白氏号）→ release CI 里 `signtool sign`
- **当前替代**：用户需在 SmartScreen 点"更多信息 → 仍要运行"

## 2. macOS Notarization（避免 Gatekeeper 警告）

- **需要**：Apple Developer 账号（$99/年）+ Developer ID Application 证书
- **流程**：`codesign` → `xcrun notarytool submit` → `xcrun stapler staple`
- **当前替代**：用户右键 → 打开 → 信任绕过 Gatekeeper

## 3. 真实磁盘镜像测试集

- **需要**：合法获取的多文件系统镜像（NTFS / APFS / Btrfs / BitLocker 等）
- **来源**：sleuthkit 测试镜像 / 自建虚拟机（法律最干净）
- **规模**：~2-5 GB，用 git LFS 或 S3 + CI 下载

## 4. 真 JPEG Huffman state stitching（无 RST 也能拼）

- **工作量**：~3000-5000 行
- **依赖**：fork stdlib `image/jpeg` 暴露 `decoder.huffmanState` 内部
- **R-Studio 20 年壁垒**：开源很难追平
- **当前替代**：block-graph + entropy 健康度 + RST 序号约束，覆盖 ~30% 场景

## 5. 训练分类器判断 chunk → 文件类型

- **需要**：数十 GB 标注数据集 + ML 模型
- **运行时**：cgo + TensorFlow / ONNX，模型权重 ~100MB
- **不做的理由**：偏离工具定位；开源数据集不易获得

## 6. SMB / NFS 协议级 reader

- **工作量**：完整 go-smb2 / go-nfs 客户端 ~5000 行
- **当前替代**：支持"挂载远程后选镜像文件"，覆盖 95% 场景

## 7. HSM / KMS 签名集成

- **现状**：release signing 用 GitHub Secret 存 Ed25519 私钥
- **升级方向**：AWS KMS / HashiCorp Vault / YubiKey PKCS#11
- **阻塞**：需要企业账号 + 付费服务
- **影响**：当前足够个人 / 小团队用；大型 B2B 合规会要求升级

## 8. TUF (The Update Framework) 完整 role separation

- **现状**：单一 release 私钥签 SHA256SUMS.txt
- **TUF 要求**：root / snapshot / timestamp / targets 多角色密钥 + metadata expiry
- **不做的理由**：对单开发者项目过重；SIGNING.md 明示

---

## 决策建议

- **短期**（发布前）：#1, #2 付费解决
- **中期**（B2B 客户要求时）：#3 真实测试集，#7 HSM 升级
- **长期 / 看社区**：#4, #5 是行业老大难
- **永远不做**：#6 偏离工具定位
