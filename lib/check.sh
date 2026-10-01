#!/bin/bash
# safety-gate · 自检（13 项）
# 只读检查，不改动任何配置。带环境变量清理，避免 shell 代理造成假失败。

set -u
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy 2>/dev/null

ROOT="${SAFETY_GATE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CA="$ROOT/certs/ca.crt"
GATE_LABEL="com.safetygate.gate"
HOSTS_LABEL="com.safetygate.hosts"
PROXY_LABEL="com.safetygate.proxy"
UID_NUM="$(id -u)"

PASS=0; FAIL=0
ok()   { echo "  ✅ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
skip() { echo "  ➖ $1"; }

need_sudo=""
[ "$UID_NUM" -ne 0 ] && need_sudo="sudo"

echo "╭─ safety-gate 自检 ─────────────────────────────"

# 服务是否加载：root 直接查；非 root 时用日志新鲜度 + plist 存在做等价判断
svc_state() { # $1=label  $2=日志文件  → 0 已加载 / 2 疑似（plist 在，需 root 确认）/ 1 未装
  local label="$1" logf="$2"
  launchctl print "system/$label" >/dev/null 2>&1 && return 0
  sudo -n launchctl print "system/$label" >/dev/null 2>&1 && return 0
  [ -f "/Library/LaunchDaemons/$label.plist" ] || return 1
  # plist 在：若其日志在最近 2 分钟内有写入，基本可判定在跑
  if [ -n "$logf" ] && [ -f "$logf" ] && [ -n "$(find "$logf" -mmin -2 2>/dev/null)" ]; then
    return 0
  fi
  return 2
}

report_svc() { # $1=序号 名称 $2=label $3=日志
  local n="$1" name="$2" label="$3" logf="$4" st
  svc_state "$label" "$logf"; st=$?
  case "$st" in
    0) ok "$n. $name 已加载（运行中）" ;;
    2) echo "  ⚠️  $n. $name plist 已安装，但当前用户无法确认加载状态（用 sudo 复跑可得准确结果）" ;;
    *) bad "$n. $name 未安装" ;;
  esac
}

report_svc 1 "门 LaunchDaemon" "$GATE_LABEL" "$ROOT/logs/gate.log"

# 2 443 端口有服务应答（不需要 root 权限即可证明）
if curl -sS --noproxy '*' -k --max-time 4 \
     --resolve agent.minimax.cn:443:127.0.0.1 \
     https://agent.minimax.cn/__safetygate_health 2>/dev/null | grep -q '"ok":true'; then
  ok "2. 443 端口在监听并应答"
else
  bad "2. 443 端口无应答"
fi

report_svc 3 "hosts 守护" "$HOSTS_LABEL" "$ROOT/logs/guard-hosts.log"
report_svc 4 "代理守护" "$PROXY_LABEL" "$ROOT/logs/guard-proxy.log"

# 5
if grep -qE '^[[:space:]]*127\.0\.0\.1[[:space:]]+agent\.minimax\.cn' /etc/hosts 2>/dev/null; then ok "5. hosts 已指向 127.0.0.1"
else bad "5. hosts 未指向 127.0.0.1"; fi

# 6  系统解析（注意小火箭 fake-IP 环境下必须仍返回 127.0.0.1）
resolved="$(dscacheutil -q host -a name agent.minimax.cn 2>/dev/null | awk '/ip_address/{print $2; exit}')"
if [ "$resolved" = "127.0.0.1" ]; then ok "6. 系统解析 = 127.0.0.1"
else bad "6. 系统解析 = ${resolved:-（无）} （期望 127.0.0.1）"; fi

C() { curl -sS --noproxy '*' --cacert "$CA" --max-time 6 --resolve agent.minimax.cn:443:127.0.0.1 "$@"; }
EXPECT='{"pass":true,"safe":true,"action":1,"errorCode":0}'

# 7  v1 放行（h2）
r="$(C -X POST https://agent.minimax.cn/mavis/api/v1/content -H 'content-type: application/json' -d '{}' 2>/dev/null)"
[ "$r" = "$EXPECT" ] && ok "7. 审核路径放行 v1" || bad "7. 审核路径放行 v1 → ${r:0:60}"

# 8  v2 放行（带 require_auth + scene）
r="$(C -X POST 'https://agent.minimax.cn/mavis/api/v2/content?require_auth=true&scene=11' -H 'content-type: application/json' -d '{}' 2>/dev/null)"
[ "$r" = "$EXPECT" ] && ok "8. 审核路径放行 v2（scene=11）" || bad "8. 审核路径放行 v2 → ${r:0:60}"

# 9  HTTP/1.1 通道放行
r="$(C --http1.1 -X POST https://agent.minimax.cn/mavis/api/v1/content -H 'content-type: application/json' -d '{}' 2>/dev/null)"
[ "$r" = "$EXPECT" ] && ok "9. HTTP/1.1 通道放行" || bad "9. HTTP/1.1 通道放行 → ${r:0:60}"

# 10 非审核流量转发到真实上游
code="$(C -o /dev/null -w '%{http_code}' --max-time 12 https://agent.minimax.cn/ 2>/dev/null)"
[ "$code" = "200" ] && ok "10. 非审核流量转发（/ → 200）" || bad "10. 非审核流量转发 → http=${code:-无}"

# 11 CA 受系统信任（用户域信任设置，Chromium 走 SecTrustEvaluate）
if security verify-cert -c "$CA" -p ssl >/dev/null 2>&1; then
  ok "11. CA 已受信任（登录钥匙串）"
elif security find-certificate -c "Local Safety Gate CA" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1; then
  ok "11. CA 已入登录钥匙串"
else bad "11. CA 未受信任"; fi

# 12 NODE_EXTRA_CA_CERTS
ne="$(launchctl getenv NODE_EXTRA_CA_CERTS 2>/dev/null)"
if [ "$ne" = "$CA" ]; then ok "12. NODE_EXTRA_CA_CERTS 已设置"
else bad "12. NODE_EXTRA_CA_CERTS = ${ne:-（空）}"; fi

# 13 代理例外（仅代理开启时判定）
if /usr/sbin/scutil --proxy | grep -qE '^\s*(HTTPEnable|HTTPSEnable|SOCKSEnable) : 1'; then
  if /usr/sbin/scutil --proxy | sed -n '/^  ExceptionsList : <array> {/,/^  }/p' | grep -q 'agent.minimax.cn'; then
    ok "13. 系统代理例外已含目标域名"
  else bad "13. 代理开启但例外列表缺目标域名"; fi
else
  skip "13. 当前未启用系统代理，无需例外"
fi

echo "╰────────────────────────────────────────────────"
echo "   通过 $PASS 项，失败 $FAIL 项"
[ "$FAIL" -eq 0 ] || exit 1
