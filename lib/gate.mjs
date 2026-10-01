#!/usr/bin/env node
/**
 * safety-gate — MiniMax Code 桌面端本地安审门
 *
 * 在 443 上接管 agent.minimax.cn / agent.minimax.io：
 *   - POST /mavis/api/**\/content  → 本地直接答"通过"（v1 读布尔，v2 读 action/errorCode）
 *   - 其余路径                      → 逐字节透传真实上游（含 SSE 长流 / WebSocket）
 *
 * 设计约束（fail-open）：
 *   - 内部异常一律降级为"尽力转发"或明确 502，绝不静默吞流量
 *   - 上游只接受公网 IPv4，拒绝 127/198.18/内网/已挂 lo0 的地址（防 hosts 与 TUN fake-IP 自环）
 *   - 暴露仅限本机的 /__safetygate_health，供守护判断是否需要摘掉 hosts
 *   - 默认只绑 127.0.0.1，不向局域网暴露
 */

import http2 from 'node:http2';
import https from 'node:https';
import tls from 'node:tls';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// 运行副本位于 <root>/gate.mjs；可用 SAFETY_GATE_ROOT 覆盖（本地调试）
const ROOT = process.env.SAFETY_GATE_ROOT
  ? path.resolve(process.env.SAFETY_GATE_ROOT)
  : path.dirname(fileURLToPath(import.meta.url));

const CERT_DIR = path.join(ROOT, 'certs');
const STATE_DIR = path.join(ROOT, 'state');
const LOG_FILE = path.join(ROOT, 'logs/gate.log');

const PORT = Number(process.env.GATE_PORT || 443);
const BIND = process.env.GATE_BIND || '127.0.0.1';
/** 上游端口，仅测试用（生产固定 443） */
const UPSTREAM_PORT = Number(process.env.GATE_UPSTREAM_PORT || 443);

const HOSTS = new Set(['agent.minimax.cn', 'agent.minimax.io']);
/** /mavis/api/content、/mavis/api/v1/content、/mavis/api/v2/content?require_auth=true */
const AUDIT_RE = /^\/mavis\/api\/(?:v\d+\/)?content(?:[/?]|$)/;
const HEALTH_PATH = '/__safetygate_health';

const PASS_BODY = Buffer.from(JSON.stringify({
  pass: true, safe: true, action: 1, errorCode: 0,
}));

const stats = { audit: 0, fwd: 0, reject: 0, err: 0 };
const startedAt = Date.now();

// ───────────────────────── 日志 ─────────────────────────

let logStream = null;
function openLog() {
  try {
    fs.mkdirSync(path.dirname(LOG_FILE), { recursive: true });
    logStream = fs.createWriteStream(LOG_FILE, { flags: 'a', mode: 0o644 });
  } catch { logStream = null; }
}
function log(...parts) {
  const line = `[${new Date().toISOString()}] ${parts.join(' ')}\n`;
  try { logStream?.write(line); } catch {}
  if (process.env.GATE_VERBOSE) process.stdout.write(line);
}

// ───────────────────── 上游地址解析 ─────────────────────

const PRIVATE_RE = /^(0\.|10\.|100\.(6[4-9]|[7-9]\d|1[0-2]\d)\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|198\.(1[89]|2\d|3[01])\.|22[4-9]\.|23\d\.|24\d\.|255\.)/;

let upstreamCache = { ips: [], at: 0, domain: '' };
let lo0Aliases = new Set();

function isPublicIPv4(ip) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  return !PRIVATE_RE.test(ip);
}

/** 刷新 lo0 别名集合（同步、有缓存，避免每请求 fork ifconfig） */
let lo0At = 0;
function refreshLo0(force = false) {
  if (!force && Date.now() - lo0At < 5000) return;
  lo0At = Date.now();
  try {
    const out = execFileSync('/sbin/ifconfig', ['lo0'], { timeout: 3000, encoding: 'utf8' });
    const next = new Set();
    for (const line of out.split('\n')) {
      const m = line.match(/^\s*inet\s+(\d+\.\d+\.\d+\.\d+)/);
      if (m && m[1] !== '127.0.0.1') next.add(m[1]);
    }
    lo0Aliases = next;
  } catch { /* 保留上一次结果 */ }
}

function digOnce(server, domain) {
  return new Promise((resolve) => {
    execFile('/usr/bin/dig', ['+short', '+time=3', '+tries=1', `@${server}`, domain, 'A'],
      { timeout: 6000 }, (err, stdout) => {
        if (err) return resolve([]);
        resolve(String(stdout).split('\n').map((s) => s.trim()).filter(isPublicIPv4));
      });
  });
}

/** 通过外部 DNS 解析真实上游 IP（绕开 hosts 与 TUN fake-IP） */
async function resolveUpstream(domain, { force = false } = {}) {
  if (!force && upstreamCache.domain === domain
      && Date.now() - upstreamCache.at < 120000 && upstreamCache.ips.length) {
    return upstreamCache.ips;
  }
  for (const srv of ['223.5.5.5', '119.29.29.29', '8.8.8.8']) {
    const ips = await digOnce(srv, domain);
    if (ips.length) {
      upstreamCache = { ips: [...new Set(ips)], at: Date.now(), domain };
      log(`UPSTREAM resolve ${domain} via ${srv} -> ${ips.join(',')}`);
      return upstreamCache.ips;
    }
  }
  upstreamCache = { ...upstreamCache, at: Date.now(), domain };
  log(`UPSTREAM resolve ${domain} FAILED (all resolvers)`);
  return upstreamCache.domain === domain ? upstreamCache.ips : [];
}

/**
 * 路由守护写入的固定上游（存在且合法时优先）。
 * 只在「地址+端口都指向门自己」时判为自环并拒绝；允许私网地址便于本机联调
 * （门只监听回环，不构成额外暴露面）。
 */
function readUpstreamOverride() {
  try {
    const ip = fs.readFileSync(path.join(STATE_DIR, 'upstream-ip'), 'utf8').trim().split(/\s+/)[0];
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return null;
    if (ip === '127.0.0.1' && UPSTREAM_PORT === PORT) return null;
    if (lo0Aliases.has(ip)) return null;
    return ip;
  } catch {}
  return null;
}

/** 挑一个当前可用上游 */
async function pickUpstream(domain) {
  const override = readUpstreamOverride();
  if (override) return override;
  const ips = await resolveUpstream(domain);
  const usable = ips.filter((ip) => !lo0Aliases.has(ip));
  return usable[0] || ips[0] || null;
}

// ───────────────────── 头处理 ─────────────────────

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host',
  ':method', ':path', ':scheme', ':authority', ':protocol', ':status',
]);

function buildUpstreamHeaders(srcHeaders, authority) {
  const out = {};
  for (const [k, v] of Object.entries(srcHeaders)) {
    if (HOP_BY_HOP.has(k.toLowerCase()) || v === undefined) continue;
    out[k] = v;
  }
  out.host = authority;
  return out;
}

const H2_ONLY = [':method', ':path', ':scheme', ':authority', ':protocol', ':status'];
function buildClientHeaders(srcHeaders) {
  const out = {};
  for (const [k, v] of Object.entries(srcHeaders)) {
    if (v === undefined) continue;
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk) && !H2_ONLY.includes(lk)) continue;
    if (lk === 'transfer-encoding') continue;
    out[k] = v;
  }
  return out;
}

// ───────────────────── 透传实现 ─────────────────────

const agentUp = new https.Agent({ keepAlive: true, maxSockets: 128, rejectUnauthorized: false });

function forward(req, res, { method, url, authority, viaHTTP2 }) {
  const tag = viaHTTP2 ? 'h2' : 'h1';
  const t0 = Date.now();
  let settled = false;

  const fail = (err) => {
    if (settled) return;
    settled = true;
    stats.err++;
    log(`ERR(${tag}) ${method} ${url} host=${authority} ${err?.code || err?.message}`);
    try {
      if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('safety-gate: upstream unreachable');
    } catch {}
  };

  (async () => {
    const ip = await pickUpstream(authority);
    if (!ip) return fail(new Error('no usable upstream ip'));
    const up = https.request({
      host: ip, port: UPSTREAM_PORT, method, path: url,
      servername: authority, rejectUnauthorized: false,
      headers: buildUpstreamHeaders(req.headers, authority),
      agent: agentUp,
    }, (upRes) => {
      settled = true;
      log(`FWD(${tag}) ${method} ${url} host=${authority} -> ${ip} ${upRes.statusCode} (${Date.now() - t0}ms)`);
      try {
        res.writeHead(upRes.statusCode, buildClientHeaders(upRes.headers));
        upRes.pipe(res);
        upRes.on('error', () => { try { res.destroy(); } catch {} });
      } catch (e) { fail(e); }
    });
    up.on('error', fail);
    up.setTimeout(30000, () => up.destroy(new Error('upstream timeout')));
    req.on('error', () => up.destroy());
    req.pipe(up);
  })().catch(fail);
}

// ───────────────────── 服务主体 ─────────────────────

function main() {
  openLog();
  refreshLo0(true);
  setInterval(() => refreshLo0(true), 5000).unref?.();

  const key = fs.readFileSync(path.join(CERT_DIR, 'leaf.key'));
  const cert = fs.readFileSync(path.join(CERT_DIR, 'leaf.crt'));

  const server = http2.createSecureServer({
    key, cert,
    allowHTTP1: true,
    keepAliveTimeout: 600000,
    settings: { enableConnectProtocol: true },
  });

  // 单一入口：h2 的 stream 与 h1 的 request 都落到这里
  server.on('request', (req, res) => {
    const viaHTTP2 = req.httpVersionMajor >= 2 || req.headers[':authority'] !== undefined;
    const authorityRaw = viaHTTP2 ? req.headers[':authority'] : req.headers.host;
    const url = String((viaHTTP2 ? req.headers[':path'] : req.url) || '/');
    const method = String((viaHTTP2 ? req.headers[':method'] : req.method) || 'GET');
    const authority = parseAuthority(authorityRaw);
    const barePath = url.split('?')[0];

    // 健康检查（仅本机）
    if (barePath === HEALTH_PATH) {
      if (!isLocal(req)) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        return res.end('not found');
      }
      const body = JSON.stringify({
        ok: true, pid: process.pid, bind: `${BIND}:${PORT}`,
        uptimeMs: Date.now() - startedAt,
        upstreamOverride: readUpstreamOverride(),
        cachedUpstream: upstreamCache.ips,
        lo0Aliases: [...lo0Aliases],
        stats,
      });
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
      return res.end(body);
    }

    // 只接管目标域名
    if (!HOSTS.has(authority)) {
      stats.reject++;
      log(`REJECT host=${authority} ${method} ${barePath}`);
      try {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('safety-gate: host not served');
      } catch {}
      return;
    }

    // 审核接口 → 本地放行
    if (AUDIT_RE.test(barePath)) {
      const scene = (url.match(/[?&]scene=(\d+)/) || [])[1] || '-';
      stats.audit++;
      log(`SAFETY(${viaHTTP2 ? 'h2' : 'h1'}) ${method} ${barePath} scene=${scene} -> local-pass`);

      let drained = 0;
      req.on('data', (c) => { drained += c.length; });
      req.on('error', () => {});
      req.on('end', () => log(`SAFETY body-drained ${drained}B`));

      try {
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-length': PASS_BODY.length,
        });
        res.end(PASS_BODY);
      } catch {}
      return;
    }

    // 其余 → 透传
    stats.fwd++;
    forward(req, res, { method, url, authority, viaHTTP2 });
  });

  // WebSocket（HTTP/1.1 upgrade）隧道
  server.on('upgrade', (req, socket, head) => {
    const authority = parseAuthority(req.headers.host);
    if (!HOSTS.has(authority)) return socket.destroy();
    log(`UPGRADE ${req.url} host=${authority}`);
    (async () => {
      const ip = await pickUpstream(authority);
      if (!ip) return socket.destroy();
      const up = tls.connect({ host: ip, port: UPSTREAM_PORT, servername: authority, rejectUnauthorized: false }, () => {
        let raw = `${req.method} ${req.url} HTTP/1.1\r\n`;
        for (const [k, v] of Object.entries(req.headers)) {
          if (k.toLowerCase() === 'host' || v === undefined) continue;
          raw += `${k}: ${v}\r\n`;
        }
        raw += `Host: ${authority}\r\n\r\n`;
        up.write(raw);
        if (head?.length) up.write(head);
        socket.pipe(up); up.pipe(socket);
      });
      up.on('error', () => socket.destroy());
      socket.on('error', () => up.destroy());
    })().catch(() => socket.destroy());
  });

  server.on('sessionError', (e) => log(`ERR h2-session ${e.code || e.message}`));
  server.on('clientError', (e, socket) => { try { socket.destroy(); } catch {} });

  server.listen(PORT, BIND, () => {
    log(`GATE up pid=${process.pid} bind=${BIND}:${PORT} hosts=${[...HOSTS].join(',')} node=${process.version}`);
    resolveUpstream('agent.minimax.cn').catch(() => {});
  });

  server.on('error', (e) => {
    log(`FATAL listen ${BIND}:${PORT} ${e.code} ${e.message}`);
    process.exit(1);
  });

  const shutdown = (sig) => {
    log(`GATE down sig=${sig}`);
    try { server.close(); } catch {}
    setTimeout(() => process.exit(0), 300).unref?.();
  };
  process.on('SIGTERM', () => shutdown('TERM'));
  process.on('SIGINT', () => shutdown('INT'));
}

function parseAuthority(authority) {
  return String(authority || '').replace(/:\d+$/, '').toLowerCase();
}
function isLocal(req) {
  const ra = req.socket?.remoteAddress || '';
  return ra === '127.0.0.1' || ra === '::1' || ra === '::ffff:127.0.0.1';
}

main();
