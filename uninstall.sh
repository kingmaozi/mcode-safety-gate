#!/bin/bash
#
# mcode-safety-gate · 一键卸载
#
#   sudo ./uninstall.sh
#
# 撤销全部改动：服务、hosts、CA 信任、代理例外、环境变量。
# 运行副本与日志保留在安装目录，确认无误后可自行删除。

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="safety-gate"

if [ "$(id -u)" -ne 0 ]; then
  echo "→ 需要管理员权限，即将提权…"
  exec sudo bash "$REPO_DIR/uninstall.sh" "$@"
fi

REAL_USER="${SUDO_USER:-$(id -un)}"
if [ "$REAL_USER" = "root" ]; then
  REAL_USER="$(stat -f '%Su' /dev/console)"
fi
REAL_UID="$(id -u "$REAL_USER")"
REAL_HOME="$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -n "$REAL_HOME" ] || REAL_HOME="/Users/$REAL_USER"

# 优先用安装目录（可被环境变量覆盖），否则回退到标准位置
ROOT="${SAFETY_GATE_ROOT:-$REAL_HOME/Library/Application Support/$APP_NAME}"
SCUTIL="/usr/sbin/scutil"
CA_CN="Local Safety Gate CA"
DOMAINS=(agent.minimax.cn agent.minimax.io)

step() { echo "[$(date '+%H:%M:%S')] $*"; }

echo "╭─ mcode-safety-gate 卸载 ─────────────────────────"
echo "│ 用户: $REAL_USER   安装目录: $ROOT"

# 1. 卸载 launchd 服务
step "卸载 launchd 服务"
for l in com.safetygate.gate com.safetygate.hosts com.safetygate.proxy; do
  launchctl bootout "system/$l" 2>/dev/null && step "  ✓ bootout $l" || true
  launchctl unload -w "/Library/LaunchDaemons/$l.plist" 2>/dev/null || true
  rm -f "/Library/LaunchDaemons/$l.plist"
done
launchctl bootout "gui/$REAL_UID/com.safetygate.nodeca" 2>/dev/null && step "  ✓ bootout nodeca" || true
rm -f "$REAL_HOME/Library/LaunchAgents/com.safetygate.nodeca.plist"

# 2. 停止门
step "停止门进程"
pkill -f 'safety-gate/gate.mjs' 2>/dev/null && step "  ✓ 已终止" || step "  - 未在运行"

# 3. 还原 /etc/hosts
step "还原 /etc/hosts"
if grep -qF '# safety-gate:begin' /etc/hosts 2>/dev/null; then
  cp /etc/hosts "/etc/hosts.safetygate-bak-$(date +%s)"
  tmp="$(mktemp /tmp/sg-hosts.XXXXXX)"
  awk '
    $0 == "# safety-gate:begin" { skip = 1; next }
    $0 == "# safety-gate:end"   { skip = 0; next }
    skip { next }
    { print }
  ' /etc/hosts >"$tmp" && cat "$tmp" >/etc/hosts
  rm -f "$tmp"
  dscacheutil -flushcache 2>/dev/null; killall -HUP mDNSResponder 2>/dev/null
  step "  ✓ 条目已移除"
else
  step "  - 无需改动"
fi

# 4. 移除 CA
step "移除本地 CA"
for kc in "$REAL_HOME/Library/Keychains/login.keychain-db" /Library/Keychains/System.keychain; do
  [ -f "$kc" ] || [ "$kc" = "/Library/Keychains/System.keychain" ] || continue
  if security find-certificate -c "$CA_CN" "$kc" >/dev/null 2>&1; then
    security delete-certificate -c "$CA_CN" "$kc" >/dev/null 2>&1 \
      && step "  ✓ 已从 $(basename "$kc") 移除" || step "  ⚠ $(basename "$kc") 移除失败，请手动检查钥匙串"
  fi
done

# 5. 还原代理例外
step "还原系统代理例外"
read_exceptions() {
  "$SCUTIL" --proxy 2>/dev/null | awk '
    /^  ExceptionsList : <array> \{/ { inlist = 1; next }
    inlist && /^  \}/                { inlist = 0; next }
    inlist { line = $0; sub(/^ +[0-9]+ : /, "", line); if (line != "") print line }
  '
}
cur=()
while IFS= read -r line; do [ -n "$line" ] && cur+=("$line"); done < <(read_exceptions)
if [ "${#cur[@]}" -eq 0 ]; then
  step "  - 无可读例外列表，跳过"
else
  keep=(); removed=0
  for e in "${cur[@]}"; do
    case "$e" in
      agent.minimax.cn|agent.minimax.io) removed=$((removed+1)) ;;
      *) keep+=("$e") ;;
    esac
  done
  if [ "$removed" -eq 0 ]; then
    step "  - 列表中没有目标域名"
  else
    cmd="open
get State:/Network/Global/Proxies
d.remove ExceptionsList
d.add ExceptionsList * "
    for e in "${keep[@]}"; do cmd+="$e "; done
    cmd+="
set State:/Network/Global/Proxies
quit"
    printf '%s\n' "$cmd" | "$SCUTIL" >/dev/null 2>&1 \
      && step "  ✓ 移除 $removed 条，保留 ${#keep[@]} 条" \
      || step "  ⚠ 移除失败（代理可能已重写该配置）"
  fi
fi

# 6. 环境变量
step "清理 NODE_EXTRA_CA_CERTS"
launchctl asuser "$REAL_UID" launchctl unsetenv NODE_EXTRA_CA_CERTS 2>/dev/null && step "  ✓ 已清理" || true

echo "╰──────────────────────────────────────────────────"
echo
echo "还原完成。请重启 MiniMax Code。"
echo "确认一切正常后，可手动删除："
echo "  rm -rf \"$ROOT\""
