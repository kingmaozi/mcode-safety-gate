#!/bin/bash
# safety-gate · hosts 守护（fail-open 核心）
#
# 每 5 秒：
#   1. 探测门是否健康（走完整 TLS 链路 + 证书校验）
#   2. 健康      → 幂等确保 /etc/hosts 指向 127.0.0.1
#   3. 连续 2 次不健康 → 摘掉 hosts 条目并刷新 DNS 缓存，让域名回到直连
#
# 这是"绝不破坏 agent.minimax.cn 正常访问"的保险：门一旦失灵，
# 15 秒内域名自动恢复直连真实服务器，App 照常可用（只是拦截回到原状）。

set -u

ROOT="${SAFETY_GATE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CA="$ROOT/certs/ca.crt"
LOG="$ROOT/logs/guard-hosts.log"
STATE="$ROOT/state"
FAIL_FILE="$STATE/gate-health-failures"
MARK_BEGIN="# safety-gate:begin"
MARK_END="# safety-gate:end"
HOSTS_FILE="/etc/hosts"
DOMAINS=(agent.minimax.cn agent.minimax.io)
MAX_FAILS=2

mkdir -p "$STATE" "$(dirname "$LOG")" 2>/dev/null

ts() { date "+%Y-%m-%dT%H:%M:%S%z"; }
log() { printf '[%s] %s\n' "$(ts)" "$*" >>"$LOG" 2>/dev/null; }

# ── 门健康探测：完整 TLS + CA 校验，等价于 App 的信任路径 ──
health_ok() {
  curl -sS --noproxy '*' --cacert "$CA" --max-time 4 \
    --resolve agent.minimax.cn:443:127.0.0.1 \
    "https://agent.minimax.cn/__safetygate_health" 2>/dev/null \
    | grep -q '"ok":true'
}

hosts_has_entry() {
  grep -qE '^[[:space:]]*127\.0\.0\.1[[:space:]]+agent\.minimax\.cn([[:space:]]|$)' "$HOSTS_FILE" 2>/dev/null
}

ensure_hosts() {
  if hosts_has_entry; then return 0; fi
  # 清理可能残留的不完整块，再整块写入
  strip_hosts
  {
    printf '%s\n' "$MARK_BEGIN"
    for d in "${DOMAINS[@]}"; do printf '127.0.0.1 %s\n' "$d"; done
    printf '%s\n' "$MARK_END"
  } >>"$HOSTS_FILE"
  flush_dns
  log "HOSTS added (gate healthy)"
}

strip_hosts() {
  [ -f "$HOSTS_FILE" ] || return 0
  local tmp
  tmp="$(mktemp /tmp/safetygate-hosts.XXXXXX)" || return 1
  awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
    $0 == b { inblk = 1; next }
    $0 == e { inblk = 0; next }
    inblk { next }
    { print }
  ' "$HOSTS_FILE" >"$tmp" && cat "$tmp" >"$HOSTS_FILE"
  rm -f "$tmp"
}

remove_hosts() {
  if ! hosts_has_entry && ! grep -qF "$MARK_BEGIN" "$HOSTS_FILE" 2>/dev/null; then
    return 0
  fi
  strip_hosts
  flush_dns
  log "HOSTS removed (gate unhealthy → direct access restored)"
}

flush_dns() {
  dscacheutil -flushcache 2>/dev/null
  killall -HUP mDNSResponder 2>/dev/null
}

# ── 主循环体（单次） ──
main_once() {
  local fails
  fails="$(cat "$FAIL_FILE" 2>/dev/null || echo 0)"
  case "$fails" in ''|*[!0-9]*) fails=0 ;; esac

  if health_ok; then
    if [ "$fails" -ne 0 ]; then
      echo 0 >"$FAIL_FILE"
      log "HEALTH recovered (was failing ${fails}x)"
    fi
    ensure_hosts
  else
    fails=$((fails + 1))
    echo "$fails" >"$FAIL_FILE"
    log "HEALTH fail #$fails"
    if [ "$fails" -ge "$MAX_FAILS" ]; then
      remove_hosts
    fi
  fi
}

main_once
