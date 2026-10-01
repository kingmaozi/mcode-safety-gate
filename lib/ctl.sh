#!/bin/bash
# safety-gate · 控制台
# 用法: ctl.sh status|health|start|stop|restart|logs|hosts|proxy|uninstall
# 需要 root 的子命令会提示用 sudo。

set -u
ROOT="${SAFETY_GATE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
GATE_LABEL="com.safetygate.gate"
HOSTS_LABEL="com.safetygate.hosts"
PROXY_LABEL="com.safetygate.proxy"
CA="$ROOT/certs/ca.crt"

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "此操作需要 root：请用 sudo $0 $1" >&2
    exit 1
  fi
}

health_json() {
  curl -sS --noproxy '*' --cacert "$CA" --max-time 4 \
    --resolve agent.minimax.cn:443:127.0.0.1 \
    "https://agent.minimax.cn/__safetygate_health" 2>/dev/null
}

case "${1:-status}" in
  status)
    echo "── 门进程 ──"
    pgrep -lf 'safety-gate/gate.mjs' || echo "(未运行)"
    echo
    echo "── 443 监听 ──"
    lsof -nP -iTCP:443 -sTCP:LISTEN 2>/dev/null | tail -n +1 || echo "(无)"
    echo
    echo "── launchd 服务 ──"
    for l in "$GATE_LABEL" "$HOSTS_LABEL" "$PROXY_LABEL"; do
      if ${SUDO} launchctl print "system/$l" >/dev/null 2>&1; then
        echo "  $l : 已加载"
      else
        echo "  $l : 未加载"
      fi
    done
    echo
    echo "── 健康 ──"
    h="$(health_json)"
    if [ -n "$h" ]; then echo "$h" | python3 -m json.tool 2>/dev/null || echo "$h";
    else echo "(门无响应)"; fi
    ;;

  health)
    health_json | python3 -m json.tool 2>/dev/null || echo "(门无响应)"
    ;;

  start)    need_root start;    launchctl kickstart -k "system/$GATE_LABEL" && echo "门已启动" ;;
  stop)     need_root stop;     launchctl bootout "system/$GATE_LABEL" 2>/dev/null; pkill -f 'safety-gate/gate.mjs'; echo "门已停止（hosts 守护会自动摘除条目）" ;;
  restart)  need_root restart;  launchctl kickstart -k "system/$GATE_LABEL" && echo "门已重启" ;;

  logs)
    tail -n "${2:-40}" "$ROOT/logs/gate.log" 2>/dev/null || echo "(无门日志)"
    ;;

  guard-logs)
    echo "── hosts 守护 ──"; tail -n "${2:-20}" "$ROOT/logs/guard-hosts.log" 2>/dev/null
    echo "── 代理守护 ──";  tail -n "${2:-20}" "$ROOT/logs/guard-proxy.log" 2>/dev/null
    ;;

  hosts)
    echo "── /etc/hosts 中的 safety-gate 块 ──"
    awk '/# safety-gate:begin/,/# safety-gate:end/' /etc/hosts 2>/dev/null || echo "(无)"
    echo "── 系统解析 ──"
    dscacheutil -q host -a name agent.minimax.cn 2>/dev/null | grep ip_address || echo "(未解析)"
    ;;

  proxy)
    echo "── 代理状态 ──"
    /usr/sbin/scutil --proxy | sed -n '1,14p'
    ;;

  uninstall)
    need_root uninstall
    exec "$ROOT/bin/uninstall.sh"
    ;;

  *)
    sed -n '2,4p' "$0"
    exit 1
    ;;
esac
