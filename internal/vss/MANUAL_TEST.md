# VSS 端到端手工测试（Windows 真机）

我们的 macOS 开发机无法跑 `vssadmin`，所以 VSS 模块的端到端测试**必须在 Windows 真机上**做。
本文档列明 step-by-step 操作，你或测试者按这个走一遍即可验证。

## 测试前置条件

- Windows 10 / 11
- **管理员权限**（vssadmin 必须 admin）
- 至少有 5GB 空闲 C: 盘空间（创建快照用）

## Step 1：制造一个 VSS 快照

```powershell
# PowerShell（必须以管理员身份打开）

# 列出当前已有的快照（首次运行可能为空）
vssadmin list shadows

# 临时启用 C: 盘的快照功能（如果尚未启用）
vssadmin add shadowstorage /for=C: /on=C: /maxsize=10%

# 手动创建一个 C: 盘快照
$class = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
$class.create("C:\", "ClientAccessible")

# 再次列出快照，应能看到刚创建的
vssadmin list shadows
```

记下输出里的 `Shadow Copy Volume` 路径，形如：
```
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7
```

## Step 2：运行本工具检查 VSS 枚举

启动本工具（带管理员权限）：
1. 欢迎页应该自动检测到刚才创建的快照
2. 列表应显示快照 ID / DevicePath / 创建时间
3. 点击「扫描此快照」应能进入工作台并开始扫描

预期结果：
- ✅ 快照被识别
- ✅ 创建时间正确显示
- ✅ 扫描能开始（NTFS 路径走通即可，能找到快照里的文件）

## Step 3：清理（测试完毕后）

```powershell
# 删除刚才创建的快照（其他生产快照不要删）
vssadmin delete shadows /for=C: /shadow={SHADOWID}

# 或一次清理 C: 上所有手动创建的（谨慎）
# vssadmin delete shadows /for=C: /all
```

## Step 4：常见失败排查

| 现象 | 原因 / 排查 |
|---|---|
| `vssadmin list shadows` 提示"没有匹配查询的项目" | C: 盘根本没启用快照；按 Step 1 的 add shadowstorage 命令启用 |
| 本工具说"VSS 枚举仅在 Windows 平台可用" | 你装的是非 Windows 版本；下载 Windows exe |
| 检测到快照但点扫描后报"打开失败" | 没有以管理员身份启动 |
| 中文 Windows 上字段解析为空 | 我们已经加了"卷影复制 ID / 原始卷"等中文字段名兼容；如仍失败请把 `vssadmin list shadows` 输出贴给我，加 regex |
| 快照创建命令失败 | Windows 服务 "Volume Shadow Copy" / "Microsoft Software Shadow Copy Provider" 未启动 |

## 已自动化覆盖（无需手工）

`parse_test.go` 用真实 Windows 输出样本（去敏后）做了 7 个解析测试：
- 英文 Win10 输出
- 中文 Win10 输出
- Win11 实测输出
- 多 ShadowCopySet 多 shadow
- 字段缺失边界
- 创建时间格式三种 layout
- 无快照场景
