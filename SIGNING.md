# Release Signing & Supply-Chain Integrity

本文档描述 DataRecoveryMaster 自动更新的安全模型，供：

- **最终用户** 独立验证下载的 binary 是我们签的（不是 MITM）
- **企业合规审查** 理解更新流程的威胁模型和缓解措施
- **外部安全审计方**（NCC / Cure53 / 自行审查）对照 checklist

## 威胁模型

| 攻击 | 缓解 |
|---|---|
| MITM 替换 binary | SHA256SUMS.txt 对比 |
| MITM 同时替换 binary + SHA256SUMS | Ed25519 签名 SHA256SUMS.txt |
| 攻击者替换公钥 | **代码内 pin**（`EmbeddedPublicKey`），root-of-trust 在我司代码仓 |
| Rollback（让用户升级到老的含漏洞版本） | `IsVersionNewer` 严格单调版本号检查 |
| 下载后到 apply 之间 binary 被改 | `RunApplyHelper` 再次计算 hash 对比 pending manifest |
| Apply 失败导致 brick | `RunApplyHelper` 先 backup 旧 exe → 失败回滚 |
| 事后追溯 | `update_audit.log` JSONLines 审计日志 |

## 签名密钥

**当前状态（开发期）**：未配置，签名缺省跳过。
**生产期**：GitHub Secrets 里放 Ed25519 私钥（`RELEASE_SIGNING_KEY`），CI 自动签 SHA256SUMS.txt。

### 生成新密钥对（首次发布前做）

```bash
# OpenSSL 1.1.1+ 支持 Ed25519
openssl genpkey -algorithm Ed25519 -out release_priv.pem
openssl pkey -in release_priv.pem -pubout -out release_pubkey.pem

# 私钥放到 GitHub → Settings → Secrets → Actions → 新建 RELEASE_SIGNING_KEY
# 值是 release_priv.pem 文件内容（PEM，含 BEGIN/END 标头）

# 公钥 pin 到代码（生产发布前）：
# 方式 A: build ldflags 注入
cat release_pubkey.pem | base64   # 复制输出
# 然后 release.yml 里：
#   go build -ldflags "-X data-recovery/internal/updater.EmbeddedPublicKey=<base64-value>"

# 方式 B: 直接改源码
# internal/updater/verify_release.go 里 var EmbeddedPublicKey 设为 PEM 字符串
```

### 密钥轮换（每 2 年建议一次）

1. 生成新密钥对
2. 先在新 release 里**同时**附两个公钥（`release_pubkey.pem` + `release_pubkey_next.pem`），verify 代码支持多公钥兜底
3. 等旧公钥用户都升级了（监控分布）再把新公钥设为默认
4. 旧私钥放入 HSM 冷存归档

**如果私钥泄露**：
1. 立刻**新建密钥对**（不能继续用）
2. 发 revocation notice（GitHub Advisory + 邮件列表 + Issue pin）
3. 强制用户手动下载 → 无法通过自动更新恢复信任链
4. 审查 audit 日志 + 已发版本 hash，看有无被冒签的版本

## 用户侧验证流程

下载 release 后任何人可离线验证：

```bash
# 1. 验 binary hash 对 SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt

# 2. 验 SHA256SUMS.txt 的 Ed25519 签名
openssl pkeyutl -verify \
  -pubin -inkey release_pubkey.pem \
  -rawin -in SHA256SUMS.txt \
  -sigfile SHA256SUMS.txt.sig
# 输出 "Signature Verified Successfully" 才可信任
```

**pin 公钥**：生产用户应该**不信任** release 附带的 `release_pubkey.pem`（攻击者能一起替换），而是从**独立渠道**（网站 / keyserver / fingerprint 对比）获取公钥。

当前项目的公钥 SHA256 fingerprint（**首次发布时 pin**）：

```
<待首次 release 后填入>
```

## 客户端自动更新流程

```
startup
  ↓
ApplyPendingUpdateOnStartup()        ← 如有 pending → 验 hash → spawn helper → exit
  ↓                                    helper 替换 exe → 启动新版
autoCheckForUpdate()                 ← 3s 后后台 check
  ↓ (HasUpdate)
pickPlatformAsset                    ← 按 GOOS + GOARCH 选 asset
  ↓
IsVersionNewer(current, target)      ← rollback 防护
  ↓
DownloadAsset                         ← HTTPS + Go 默认 TLS strict
  ↓
FetchSHA256SUMS + VerifyAssetChecksum  ← 供应链完整性
  ↓
VerifySumsSignatureFromRelease        ← Ed25519 验签（防 SHA256SUMS 被改）
  ↓
SavePending                           ← 写 pending manifest（含 sha256）
  ↓
<下次 startup>
  ↓
RunApplyHelper                        ← 重新 compute sha256 vs manifest → 替换 exe
  ├→ hash mismatch → reject (audit log)
  └→ copyFile 失败 → 从 backup 回滚
```

## 外部安全审计 checklist

当你联系 NCC / Cure53 等第三方审计时，他们会看：

- [x] 下载 TLS（Go 标准 HTTPS）
- [x] Binary hash 对比（SHA256SUMS.txt）
- [x] Checksum 文件签名（Ed25519）
- [x] 公钥 pin（EmbeddedPublicKey，生产需真实填）
- [x] Rollback 防护（IsVersionNewer）
- [x] Apply 前再次 hash 校验
- [x] Apply 失败回滚（backup + restore）
- [x] 审计日志（update_audit.log JSONLines）
- [x] 用户 opt-out（DATA_RECOVERY_NO_AUTO_UPDATE env）
- [ ] HSM / KMS 签名（当前为 GitHub Secret；升级到 AWS KMS / HashiCorp Vault / YubiKey 可加分）
- [ ] TUF (The Update Framework) 完整实现（role separation + metadata expiry）—— 对单开发者过重
- [ ] Certificate transparency 日志监控（`sigstore` 生态）
- [ ] 独立 timestamp authority（RFC 3161 TSA）—— 目前 forensics 包已有，更新流程未接入

## 已知限制

1. **EmbeddedPublicKey 未填**：开发期公钥走 release 文件 fallback；生产发布前必须 pin
2. **opt-out 通过 env 变量**：无 UI 开关；B2B 企业部署需文档化
3. **首次下载未用 CT log**：GitHub Actions runners 出口 IP 理论可被国家级对手 MITM（概率极低）
4. **无远程撤销**：私钥泄露后只能靠"新版本自动推送"让用户切换到新公钥；旧公钥用户需手动重装
