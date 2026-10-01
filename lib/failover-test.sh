#!/bin/bash
# fail-open 验证：停门 → 观察 hosts 是否自动回退 → 恢复门 → 观察 hosts 是否自动写回
# 需要 root（由 osascript 一次性授权）
set -u
ROOT="${SAFETY_GATE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
OUT="/tmp/sgat-failover-test.log"
: >"$OUT"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$OUT"; }
hosts_entry() { grep -c 'safety-gate:begin' /etc/hosts 2>/dev/null || echo 0; }
resolve_now() { dscacheutil -q host -a name agent.minimax.cn 2>/dev/null | awk '/ip_address/{print $2; exit}'; }
reachable() { curl -sS --noproxy '*' -k -o /dev/null -w '%{http_code}' --max-time 6 https://agent.minimax.cn/ 2>/dev/null; }

log "=== 阶段 0：初始状态 ==="
log "hosts 条目: $(hosts_entry)  解析: $(resolve_now)  可达性: $(reachable)"

log "=== 阶段 1：卸载门服务（模拟门故障）==="
launchctl bootout system/com.safetygate.gate 2>/dev/null && log "门已卸载"
pkill -f 'safety-gate/gate.mjs' 2>/dev/null
log "443 监听: $(lsof -nP -iTCP:443 -sTCP:LISTEN 2>/dev/null | wc -l | tr -d ' ') 条"

for i in 5 10 15 20; do
  sleep 5
  log "  +${i}s  hosts=$(hosts_entry)  解析=$(resolve_now)"
done

log "=== 阶段 2：门缺席时的可达性（关键）==="
log "解析: $(resolve_now)"
log "直连可达性(HTTP): $(reachable)"

log "=== 阶段 3：恢复门服务 ==="
launchctl bootstrap system /Library/LaunchDaemons/com.safetygate.gate.plist 2>/dev/null && log "门已重新加载"
for i in 5 10 15; do
  sleep 5
  log "  +${i}s  hosts=$(hosts_entry)  解析=$(resolve_now)"
done

log "=== 阶段 4：最终状态 ==="
log "hosts 条目: $(hosts_entry)  解析: $(resolve_now)  可达性: $(reachable)"
log "=== 完成 ==="
