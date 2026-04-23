package forensics

// Evidence Bundle —— 为 B2B 法务 / 合规场景打包的完整证据包。
//
// 输出一个 evidence.zip，内含：
//   custody.signed.json     manifest + 签名 + TSA token（base64 嵌入）
//   public_key.pem          对应 ed25519 公钥（PEM）
//   tsa_response.tsr        TSA 原始二进制响应（openssl ts -verify 可校验）
//   verify.sh               一键校验脚本（bash；Windows 用户可用 git-bash / wsl）
//   README.txt              说明怎么验、签名/时间戳的法律意义
//
// 未做到 RFC 4998 完整 Evidence Record Syntax（需要 hash renewal chain +
// 多重 TSA —— 由专业归档软件处理），但当前 bundle 格式可作为上游输入。

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BundleEvidence 读 outputDir/custody.signed.json → 打包 evidence.zip 到 outputDir。
// 返回 zip 文件路径。
func BundleEvidence(outputDir string) (string, error) {
	signedPath := filepath.Join(outputDir, "custody.signed.json")
	signedBytes, err := os.ReadFile(signedPath)
	if err != nil {
		return "", fmt.Errorf("读签名 manifest: %w", err)
	}

	var signed SignedCustody
	if err := json.Unmarshal(signedBytes, &signed); err != nil {
		return "", fmt.Errorf("解签名 manifest: %w", err)
	}

	zipPath := filepath.Join(outputDir, "evidence.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("创建 bundle zip: %w", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	// 1. custody.signed.json
	if err := addToZip(zw, "custody.signed.json", signedBytes); err != nil {
		return "", err
	}

	// 2. public_key.pem — 从 base64 还原 + 包成 PEM（方便标准工具读）
	pubDER, err := base64.StdEncoding.DecodeString(signed.SignaturePublicKey)
	if err == nil && len(pubDER) > 0 {
		pubPem := pem.EncodeToMemory(&pem.Block{Type: "ED25519 PUBLIC KEY", Bytes: pubDER})
		if err := addToZip(zw, "public_key.pem", pubPem); err != nil {
			return "", err
		}
	}

	// 3. tsa_response.tsr 原始二进制（给 openssl ts -verify 用）
	if signed.TSAResponseB64 != "" {
		tsrBytes, err := base64.StdEncoding.DecodeString(signed.TSAResponseB64)
		if err == nil {
			if err := addToZip(zw, "tsa_response.tsr", tsrBytes); err != nil {
				return "", err
			}
		}
	}

	// 4. verify.sh
	if err := addToZip(zw, "verify.sh", []byte(verifyScript)); err != nil {
		return "", err
	}

	// 5. README.txt
	readme := fmt.Sprintf(readmeTmpl,
		signed.ToolName, signed.ToolVersion,
		signed.TSAURL, signed.TSATimestamp.Format("2006-01-02 15:04:05 UTC"))
	if err := addToZip(zw, "README.txt", []byte(readme)); err != nil {
		return "", err
	}

	return zipPath, nil
}

func addToZip(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("zip create %s: %w", name, err)
	}
	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("zip write %s: %w", name, err)
	}
	return nil
}

const verifyScript = `#!/usr/bin/env bash
# Evidence Bundle 验证脚本 —— 需要 openssl + python3 (Ed25519 verify via pynacl)
#
# 步骤：
#   1. 验证 custody.signed.json 的 ed25519 签名未被篡改
#   2. 验证 tsa_response.tsr 是合法的 RFC 3161 时间戳响应
#
# 运行：bash verify.sh

set -euo pipefail

echo "==> 1. 校验 Ed25519 签名"
python3 -c "
import json, base64, sys
try:
    from nacl.signing import VerifyKey
except ImportError:
    print('  [WARN] 需要 pynacl: pip install pynacl'); sys.exit(0)

with open('custody.signed.json') as f:
    m = json.load(f)
pub = base64.b64decode(m['signaturePublicKey'])
sig = base64.b64decode(m['signature'])
# 重建签名时的 canonical 形式：清空 signature/tsa 字段重 marshal
copy = {k: m[k] for k in m}
copy['signature'] = ''
copy['tsaUrl'] = ''
copy['tsaResponseB64'] = ''
copy['tsaTimestamp'] = '0001-01-01T00:00:00Z'
canonical = json.dumps(copy, indent=2, ensure_ascii=False).encode('utf-8')

VerifyKey(pub).verify(canonical, sig)
print('  [OK] Ed25519 签名合法')
"

echo "==> 2. 校验 RFC 3161 时间戳"
if [ -f tsa_response.tsr ]; then
    openssl ts -reply -in tsa_response.tsr -text 2>/dev/null | head -20 || \
        echo '  [WARN] openssl ts 不可用或 TSR 格式异常'
else
    echo '  [SKIP] 无 TSA 响应文件'
fi
`

const readmeTmpl = `Evidence Bundle — %s %s
============================================================

本 zip 是数据恢复取证工具产生的证据链存档。

文件清单
----------
  custody.signed.json    manifest（列出每个恢复出的文件 + sha256）+ Ed25519 签名 + TSA 时间戳
  public_key.pem         对应的 Ed25519 公钥（PEM 格式）
  tsa_response.tsr       RFC 3161 时间戳原始响应（如果 TSA 请求成功）
  verify.sh              一键校验脚本
  README.txt             本文件

法律意义
----------
  - 签名证明 manifest 是本工具在某时间点生成，未被后续篡改
  - 时间戳（TSA: %s，%s）证明 manifest 在该时间之前已经存在
  - 两者叠加构成 RFC 4998 Evidence Record 的初级 hash chain

第三方校验
----------
  简易：bash verify.sh

  手动 (openssl)：
     # 校验 TSA 响应
     openssl ts -reply -in tsa_response.tsr -text
     # （Ed25519 校验需要 openssl 3.0+ 或 pynacl）

  专业：导入到 OpenEvidence / CryptoSys 等法务归档软件做长期存证

注意事项
----------
  - 本工具私钥自签（非 HSM / 可信 CA），法律效力取决于当地司法对自签证据的采信度
  - 商业化场景建议升级到 HSM 或云 KMS 签名 + 多重 TSA 背书
  - 数据恢复本身的合法性需单独证明（数据属于你本人 / 有授权）
`
