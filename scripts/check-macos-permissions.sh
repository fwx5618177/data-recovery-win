#!/usr/bin/env bash
# check-macos-permissions.sh —— 在 make dev 之前一次性检查 macOS 权限状态
# 不去申请权限（macOS 沙盒限制无法自动），只**报告 + 给可执行指引**。
#
# 检查：
#   1. 是否 root（Geteuid == 0）
#   2. wails CLI 是否在 PATH
#   3. Full Disk Access (TCC) 状态 —— 用 sqlite3 查 TCC.db
#      （注意：查 TCC 本身需要 Full Disk Access；查不到不报错）
#   4. /dev/disk0 能否打开（不真打开，只 ls -l）
#   5. 当前是否 dev 模式（DATA_RECOVERY_DEV_MODE=1）
#
# 输出：分级提示（OK / WARN / FAIL）+ 修复建议。

set -u

ESC=$'\033'
GREEN="${ESC}[32m"
YELLOW="${ESC}[33m"
RED="${ESC}[31m"
DIM="${ESC}[2m"
RESET="${ESC}[0m"

ok() { echo "${GREEN}✓${RESET} $1"; }
warn() { echo "${YELLOW}⚠${RESET} $1"; }
fail() { echo "${RED}✗${RESET} $1"; }
hint() { echo "${DIM}  → $1${RESET}"; }

echo "🔍 macOS 权限自检（make dev 友好版）"
echo

# 1. 平台检查
if [[ "$(uname -s)" != "Darwin" ]]; then
  ok "本脚本仅 macOS 用；当前 $(uname -s)，跳过"
  exit 0
fi

# 2. wails CLI
WAILS_BIN="$(go env GOPATH 2>/dev/null)/bin/wails"
if [[ -x "$WAILS_BIN" ]]; then
  ok "wails CLI 找到：$WAILS_BIN"
else
  fail "wails CLI 未找到（$WAILS_BIN）"
  hint "运行：make install-wails"
fi

# 3. dev 模式 env var
if [[ "${DATA_RECOVERY_DEV_MODE:-}" == "1" ]]; then
  ok "DATA_RECOVERY_DEV_MODE=1 已设置（dev 跳物理盘枚举）"
else
  warn "DATA_RECOVERY_DEV_MODE 未设置 —— make dev 会自动设；直接 wails dev 不会"
  hint "建议用 make dev 而非直接 wails dev"
fi

# 4. root 检查
if [[ "$(id -u)" == "0" ]]; then
  ok "已 root（物理盘扫描可用）"
else
  if [[ "${DATA_RECOVERY_DEV_MODE:-}" == "1" ]]; then
    ok "非 root，但 dev 模式不需要"
  else
    warn "非 root —— 物理盘扫描会失败"
    hint "测试物理盘需要：make dev-elevated（会要 sudo 密码）"
  fi
fi

# 5. /dev/disk0 ls 检查（不真打开 → 不弹权限框）
if ls -l /dev/disk0 >/dev/null 2>&1; then
  ok "/dev/disk0 可见（ls）"
else
  warn "/dev/disk0 不可见 —— 即便 root 也读不了（极少见，可能 SIP 限制）"
fi

# 6. Full Disk Access (TCC) 状态
TCC_DB="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [[ -r "$TCC_DB" ]]; then
  # 能读 TCC.db 本身就说明 Full Disk Access 已授权（chicken-and-egg）
  if sqlite3 -readonly "$TCC_DB" "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2 LIMIT 5" 2>/dev/null | grep -q . ; then
    ok "TCC: Full Disk Access 已授权给某些 app"
    hint "若 wails dev 仍报权限错，可能要把 Terminal.app / iTerm.app 加进 Full Disk Access"
  else
    warn "TCC: 当前没 app 拿到 Full Disk Access（或 TCC.db 是空的）"
  fi
else
  warn "无法读 TCC.db（说明 Terminal 没 Full Disk Access）"
  hint "如果 make dev 还是弹权限框，去：系统设置 → 隐私与安全 → 完整磁盘访问 → 加 Terminal.app（或 iTerm.app）"
fi

# 7. dev 模式建议总结
echo
echo "📋 推荐工作流："
if [[ "${DATA_RECOVERY_DEV_MODE:-}" == "1" || "${1:-}" == "--dev" ]]; then
  echo "  日常开发     ：make dev          ← 你现在在这"
  echo "  测物理盘扫描 ：make dev-elevated （要 sudo 密码）"
else
  echo "  日常开发     ：make dev          （DATA_RECOVERY_DEV_MODE=1 自动跳物理盘）"
  echo "  测物理盘扫描 ：make dev-elevated （要 sudo 密码）"
fi
echo "  打包         ：make build"
echo
