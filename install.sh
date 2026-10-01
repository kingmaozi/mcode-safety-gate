#!/bin/bash
#
# mcode-safety-gate · 一键安装
#
#   git clone https://github.com/kingmaozi/mcode-safety-gate.git
#   cd mcode-safety-gate && sudo ./install.sh
#
# 会自动：检测环境 → 安装文件到 ~/Library/Application Support/safety-gate
#        → 生成该机专属的本地 CA 与域名证书 → 注册 3 个 LaunchDaemon + 1 个 LaunchAgent
#        → CA 写入登录钥匙串 → 等门就绪并自检。
#
# 不修改 MiniMax Code.app；不改模型与提示词；443 上只绑 127.0.0.1。

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="safety-gate"

# ── 自动提权 ──
if [ "$(id -u)" -ne 0 ]; then
  echo "→ 需要管理员权限（安装 LaunchDaemon、监听 443），即将提权…"
  exec sudo bash "$REPO_DIR/install.sh" "$@"
fi

# ── 识别真实用户（sudo 下 $HOME 会变成 /var/root，必须显式取回）──
REAL_USER="${SUDO_USER:-$(id -un)}"
if [ "$REAL_USER" = "root" ]; then
  REAL_USER="$(stat -f '%Su' /dev/console)"
fi
REAL_UID="$(id -u "$REAL_USER")"
REAL_HOME="$( { dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null || true; } | awk '{print $2}')"
[ -n "$REAL_HOME" ] || REAL_HOME="/Users/$REAL_USER"
ROOT="$REAL_HOME/Library/Application Support/$APP_NAME"

echo "╭─ mcode-safety-gate 安装 ─────────────────────────"
echo "│ 用户: $REAL_USER (uid=$REAL_UID)"
echo "│ 主目录: $REAL_HOME"
echo "│ 安装到: $ROOT"

# ── 1. 环境检查 ──
echo "│"
echo "│ [1/8] 环境检查"

if [ "$(uname)" != "Darwin" ]; then
  echo "╰─ ✗ 仅支持 macOS"; exit 1
fi

NODE_BIN=""
for c in "$(command -v node 2>/dev/null || true)" /opt/homebrew/bin/node /usr/local/bin/node; do
  if [ -n "$c" ] && [ -x "$c" ]; then NODE_BIN="$c"; break; fi
done
if [ -z "$NODE_BIN" ]; then
  echo "│  ✗ 找不到 node。请先安装："
  echo "│      brew install node"
  echo "│    或 https://nodejs.org"
  echo "╰─ 中止"
  exit 1
fi
NODE_VER="$("$NODE_BIN" -v)"
NODE_MAJOR="$(echo "$NODE_VER" | sed 's/^v//' | cut -d. -f1)"
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "│  ✗ node 版本过低（$NODE_VER，需要 ≥18）"; echo "╰─ 中止"; exit 1
fi

# 443 占用检查（按 PID 反查命令行，识别并放行我们自己的门）
OCCUPIED=""
for pid in $(lsof -nP -iTCP:443 -sTCP:LISTEN -t 2>/dev/null || true); do
  cmd="$(ps -o command= -p "$pid" 2>/dev/null || true)"
  case "$cmd" in
    *safety-gate/gate.mjs*) ;;                       # 是我们自己，跳过
    "") ;;
    *) OCCUPIED="${OCCUPIED}${pid}  ${cmd}"$'\n' ;;
  esac
done
if [ -n "$OCCUPIED" ]; then
  echo "│  ✗ 本机 443 已被占用，门无法接管："
  echo "$OCCUPIED" | sed 's/^/│      /'
  echo "│"
  echo "│  说明：审核请求走 https 默认端口 443，无法改用其他端口。"
  echo "│  如占用者是旧版本安装，先运行： sudo ./uninstall.sh"
  echo "╰─ 中止（未做任何改动）"
  exit 1
fi

if [ ! -d "/Applications/MiniMax Code.app" ]; then
  echo "│  ⚠ 未在 /Applications 找到 MiniMax Code.app（仍会安装，装上后再启动 App 即可）"
fi
echo "│  ✓ node $NODE_VER"

# ── 2. 安装文件 ──
echo "│"
echo "│ [2/8] 安装文件"
mkdir -p "$ROOT"/{certs,guards,bin,install,state,logs}
install -m 644 "$REPO_DIR/lib/gate.mjs"               "$ROOT/gate.mjs"
install -m 755 "$REPO_DIR/lib/hosts-guard.sh"         "$ROOT/guards/hosts-guard.sh"
install -m 755 "$REPO_DIR/lib/proxy-guard.sh"         "$ROOT/guards/proxy-guard.sh"
for s in check ctl failover-test; do
  install -m 755 "$REPO_DIR/lib/$s.sh"                "$ROOT/bin/$s.sh"
done
install -m 755 "$REPO_DIR/install.sh"                 "$ROOT/bin/install.sh"
install -m 755 "$REPO_DIR/uninstall.sh"               "$ROOT/bin/uninstall.sh"
if [ -f "$REPO_DIR/README.md" ]; then
  install -m 644 "$REPO_DIR/README.md" "$ROOT/README.md"
fi
chown -R "$REAL_USER" "$ROOT"
echo "│  ✓ 已装到 $ROOT"

# ── 3. 生成本机专属证书 ──
echo "│"
echo "│ [3/8] 生成证书"
cd "$ROOT/certs"
if [ -f ca.crt ] && [ -f leaf.crt ] && [ -f leaf.key ]; then
  echo "│  ✓ 已存在，沿用（如需重签：删除 $ROOT/certs 后重跑）"
else
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -keyout ca.key -out ca.crt \
    -subj "/CN=Local Safety Gate CA" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
    -subj "/CN=agent.minimax.cn" 2>/dev/null
  openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -sha256 \
    -extfile <(printf "subjectAltName=DNS:agent.minimax.cn,DNS:agent.minimax.io,DNS:*.minimax.cn,DNS:*.minimax.io,IP:127.0.0.1") \
    -out leaf.crt 2>/dev/null
  rm -f leaf.csr
  chmod 700 "$ROOT/certs"
  chmod 600 ca.key leaf.key
  chmod 644 ca.crt leaf.crt
  echo "│  ✓ 本机专属 CA + agent.minimax.cn/.io 证书"
fi
chown -R "$REAL_USER" "$ROOT/certs"

# ── 4. 写入 hosts 备份 ──
echo "│"
echo "│ [4/8] 备份 /etc/hosts"
BAK="/etc/hosts.bak-safetygate-$(date +%Y%m%d%H%M%S)"
[ -f "$BAK" ] || cp /etc/hosts "$BAK"
echo "│  ✓ $BAK"

# ── 5. 渲染并安装 plist ──
echo "│"
echo "│ [5/8] 注册服务"
render() { # $1=模板 $2=输出
  sed -e "s|__ROOT__|$ROOT|g" \
      -e "s|__NODE__|$NODE_BIN|g" \
      -e "s|__USER__|$REAL_USER|g" \
      -e "s|__HOME__|$REAL_HOME|g" \
      "$1" >"$2"
}
for l in gate hosts proxy; do
  render "$REPO_DIR/plists/$l.plist.in" "/Library/LaunchDaemons/com.safetygate.$l.plist"
  chown root:wheel "/Library/LaunchDaemons/com.safetygate.$l.plist"
  chmod 644 "/Library/LaunchDaemons/com.safetygate.$l.plist"
  install -m 644 "/Library/LaunchDaemons/com.safetygate.$l.plist" "$ROOT/install/com.safetygate.$l.plist"
done
mkdir -p "$REAL_HOME/Library/LaunchAgents"
render "$REPO_DIR/plists/nodeca.plist.in" "$REAL_HOME/Library/LaunchAgents/com.safetygate.nodeca.plist"
chown "$REAL_USER" "$REAL_HOME/Library/LaunchAgents/com.safetygate.nodeca.plist"
chmod 644 "$REAL_HOME/Library/LaunchAgents/com.safetygate.nodeca.plist"
echo "│  ✓ 3 个 LaunchDaemon + 1 个 LaunchAgent"

# ── 6. CA 写入登录钥匙串（用户域信任，Chromium 走 SecTrustEvaluate）──
echo "│"
echo "│ [6/8] 信任本地 CA"
CA="$ROOT/certs/ca.crt"
LOGIN_KC="$REAL_HOME/Library/Keychains/login.keychain-db"
if security find-certificate -c "Local Safety Gate CA" "$LOGIN_KC" >/dev/null 2>&1; then
  echo "│  ✓ 已受信任"
else
  if sudo -u "$REAL_USER" env HOME="$REAL_HOME" \
       security add-trusted-cert -r trustRoot -k "$LOGIN_KC" "$CA" 2>/dev/null; then
    echo "│  ✓ 已写入登录钥匙串并设为信任根"
  else
    echo "│  ⚠ 自动写入失败（钥匙串可能锁着）。请手动执行一次："
    echo "│      security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db '$CA'"
  fi
fi

# ── 7. 加载服务 ──
echo "│"
echo "│ [7/8] 启动服务"

# bootout 是异步的：旧实例尚在终止时立即 bootstrap 会静默失败。
# 因此重试并核验 launchctl print 的真实状态，避免"假成功"。
load_daemon() { # $1 = 短名（gate/hosts/proxy）
  local label="com.safetygate.$1" plist="/Library/LaunchDaemons/com.safetygate.$1.plist"
  launchctl bootout "system/$label" 2>/dev/null || true
  local i ok=0
  for i in 1 2 3 4 5 6; do
    sleep 1
    launchctl bootstrap system "$plist" 2>/dev/null || true
    if launchctl print "system/$label" >/dev/null 2>&1; then ok=1; break; fi
  done
  if [ "$ok" -eq 1 ]; then echo "│  ✓ $label"; return 0; fi
  # 旧版 launchctl 兜底
  launchctl load -w "$plist" 2>/dev/null || true
  sleep 1
  if launchctl print "system/$label" >/dev/null 2>&1; then
    echo "│  ✓ $label (legacy)"; return 0
  fi
  echo "│  ✗ $label 加载失败 —— 手动重试： sudo launchctl bootstrap system $plist"
  return 1
}
DAEMON_FAIL=0
for l in gate hosts proxy; do load_daemon "$l" || DAEMON_FAIL=1; done

launchctl bootout "gui/$REAL_UID/com.safetygate.nodeca" 2>/dev/null || true
sleep 1
launchctl bootstrap "gui/$REAL_UID" "$REAL_HOME/Library/LaunchAgents/com.safetygate.nodeca.plist" 2>/dev/null \
  && echo "│  ✓ com.safetygate.nodeca (用户域)" || echo "│  ⚠ LaunchAgent 未加载，下次登录仍会生效"

# 本会话立即注入，免等重新登录
launchctl asuser "$REAL_UID" launchctl setenv NODE_EXTRA_CA_CERTS "$CA" 2>/dev/null \
  && echo "│  ✓ NODE_EXTRA_CA_CERTS 已注入当前会话"

# ── 8. 等门就绪 ──
echo "│"
echo "│ [8/8] 等待门就绪"
READY=0
for i in $(seq 1 30); do
  if curl -sS --noproxy '*' -k --max-time 2 \
       --resolve agent.minimax.cn:443:127.0.0.1 \
       "https://agent.minimax.cn/__safetygate_health" 2>/dev/null | grep -q '"ok":true'; then
    READY=1; echo "│  ✓ 门已就绪（${i}s）"; break
  fi
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  echo "│  ⚠ 门未在 30s 内就绪。hosts 守护此时不会改动 hosts，域名仍走直连。"
  echo "│    最近的门日志："
  tail -5 "$ROOT/logs/gate.log" 2>/dev/null | sed 's/^/│      /' || true
  echo "│    排查： bash '$ROOT/bin/ctl.sh' status"
fi

echo "╰──────────────────────────────────────────────────"
echo
echo "接下来（约 10 秒）："
echo "  1) 完全退出并重开 MiniMax Code —— 让 NODE_EXTRA_CA_CERTS 生效"
echo "  2) 验证： bash \"$ROOT/bin/check.sh\"      （应 13 项全绿）"
echo "  3) 看拦截：bash \"$ROOT/bin/ctl.sh\" logs   （出现 SAFETY ... local-pass）"
echo
echo "卸载： sudo bash \"$ROOT/bin/uninstall.sh\""
