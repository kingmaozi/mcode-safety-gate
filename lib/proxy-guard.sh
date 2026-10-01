#!/bin/bash
# safety-gate · 系统代理例外守护
#
# 小火箭(Shadowrocket)/Clash 这类工具会让系统代理进程自己解析域名，
# 从而绕过 /etc/hosts，使审核请求直达真实服务器。本守护把两个目标域名
# 幂等写入系统代理的 ExceptionsList，保证流量回到本机门。
#
# 安全约束（避免破坏用户网络）：
#   - 仅在检测到系统代理开启时才动作
#   - 两个域名都已存在 → 立即退出，零改动
#   - 改动前完整备份 scutil --proxy，改动后立即读回校验，失败则回滚
#   - 从不移除用户已有条目，只做追加

set -u

ROOT="${SAFETY_GATE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LOG="$ROOT/logs/guard-proxy.log"
STATE="$ROOT/state"
SCUTIL="/usr/sbin/scutil"
DOMAINS=(agent.minimax.cn agent.minimax.io)

mkdir -p "$STATE" "$(dirname "$LOG")" 2>/dev/null

ts() { date "+%Y-%m-%dT%H:%M:%S%z"; }
log() { printf '[%s] %s\n' "$(ts)" "$*" >>"$LOG" 2>/dev/null; }

proxy_dump() { "$SCUTIL" --proxy 2>/dev/null; }

# 代理是否开启（HTTP / HTTPS / SOCKS 任一）
proxy_enabled() {
  proxy_dump | grep -qE '^\s*(HTTPEnable|HTTPSEnable|SOCKSEnable) : 1'
}

# 顶层 ExceptionsList（排除 __SCOPED__ 内的嵌套同名数组）
read_exceptions() {
  proxy_dump | awk '
    /^  ExceptionsList : <array> \{/ { inlist = 1; next }
    inlist && /^  \}/                { inlist = 0; next }
    inlist {
      line = $0
      sub(/^ +[0-9]+ : /, "", line)
      if (line != "") print line
    }
  '
}

has_domain() { # $1 = domain
  read_exceptions | grep -qFx "$1"
}

all_present() {
  local missing=0
  for d in "${DOMAINS[@]}"; do has_domain "$d" || missing=1; done
  return $missing
}

apply_domains() {
  local backup="$STATE/proxy-backup.txt"
  proxy_dump >"$backup"

  local existing=()
  while IFS= read -r line; do
    [ -n "$line" ] && existing+=("$line")
  done < <(read_exceptions)

  local cmd="open
get State:/Network/Global/Proxies
d.remove ExceptionsList
d.add ExceptionsList * "
  local e
  for e in "${existing[@]}"; do cmd+="$e "; done
  for d in "${DOMAINS[@]}"; do cmd+="$d "; done
  cmd+="
set State:/Network/Global/Proxies
quit"

  printf '%s\n' "$cmd" | "$SCUTIL" >/dev/null 2>&1
  sleep 0.5

  # 读回校验
  if all_present; then
    log "PROXY exceptions added (kept $((${#existing[@]})) existing entries)"
    return 0
  fi

  log "PROXY apply FAILED verification; restoring backup"
  # 回滚：用备份重建
  local rb="open
get State:/Network/Global/Proxies
d.remove ExceptionsList
d.add ExceptionsList * "
  for e in "${existing[@]}"; do rb+="$e "; done
  rb+="
set State:/Network/Global/Proxies
quit"
  printf '%s\n' "$rb" | "$SCUTIL" >/dev/null 2>&1
  return 1
}

main_once() {
  if ! proxy_enabled; then
    return 0   # 没有代理，不需要例外
  fi
  if all_present; then
    return 0   # 已齐备，零改动
  fi
  log "PROXY proxy detected, domains missing → apply"
  apply_domains || log "PROXY apply failed"
}

main_once
