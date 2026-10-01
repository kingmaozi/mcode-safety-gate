# mcode-safety-gate

macOS 版 **MiniMax Code 桌面端**的本地安审门：解决偶发的

> 「这条请求可能涉及版权或我不便回答的内容 — 已经把消息放回输入框」

（整轮回复被回撤 + 弹横幅，官方设置里没有开关。）

它在本机 443 上接管 `agent.minimax.cn` / `agent.minimax.io`：只把审核接口
`POST /mavis/api/**/content` 恒答「通过」，**其余请求逐字节透传**到真实服务器。

- **不改 App 本体** —— 签名与自动更新不受影响
- **不改模型与提示词** —— 模型收到的 prompt 和返回的 token 与未安装时完全一致，不影响回答质量
- **不影响其他网站** —— 只接管这两个域名，其余流量（含你的代理规则）照旧
- **门失灵会自动让路** —— 见下方「安全设计」

## 快速开始（约 1 分钟）

前置：macOS + 已装 [Node.js](https://nodejs.org)（≥18，`brew install node` 即可）

```bash
git clone https://github.com/kingmaozi/mcode-safety-gate.git
cd mcode-safety-gate
sudo ./install.sh        # 会提示输入管理员密码
```

装完**完全退出并重开 MiniMax Code**（让它拿到新的 CA 环境变量），然后：

```bash
bash "$HOME/Library/Application Support/safety-gate/bin/check.sh"
```

13 项全绿即成功。之后在 App 里正常对话，日志出现 `SAFETY ... local-pass` 就说明拦截路径已被接管：

```bash
bash "$HOME/Library/Application Support/safety-gate/bin/ctl.sh" logs
```

## 常用命令

```bash
CTL="$HOME/Library/Application Support/safety-gate/bin/ctl.sh"
bash "$CTL" status      # 门 / 443 / 服务 / 健康 一览
bash "$CTL" health      # 实时统计（转发数、放行数、错误数）
bash "$CTL" logs 60     # 最近 60 行门日志
bash "$CTL" guard-logs  # 两个守护的日志
sudo bash "$CTL" restart
```

## 卸载

```bash
sudo ./uninstall.sh
```

会还原 hosts、删除 CA 信任、移除代理例外、卸载全部服务。之后重启 MiniMax Code。

## 安全设计（为什么它不会把你的网络搞坏）

1. **门不健康就绝不碰 hosts**
   安装脚本自己不写 hosts。条目由守护进程在「门通过完整 TLS 健康探测」之后才添加。
   门起不来 → 域名始终走真实服务器。

2. **运行时断线自愈（实测）**

   | 阶段 | hosts | 解析 | 访问情况 |
   |---|---|---|---|
   | 门正常 | 有 | 127.0.0.1 | 200 |
   | 门故障 +15 秒 | **自动移除** | 真实路径 | **200（直连，不中断）** |
   | 门恢复 +5 秒 | 自动写回 | 127.0.0.1 | 200 |

3. **上游只认公网地址**：门用外部 DNS（223.5.5.5 等）解析真实 IP，并拒绝 127/198.18/内网地址，杜绝自环。

4. **只绑回环**：门监听 `127.0.0.1:443`，不对局域网暴露。

## 常见问题

**Q：能改成别的端口吗（比如 55568）？**
不能。请求是 `https://agent.minimax.cn/...`，URL 里没有端口 → HTTPS **默认走 443**；
而 `/etc/hosts` 只能做「域名 → IP」映射，**没有端口语法**。门一旦离开 443，
App 就会连到空端口上直接报废。443 是这个方案的物理必需，不是可配置项。

**Q：443 被别的程序占了怎么办？**
安装脚本会检测并明确报错（不会做任何改动）。注意门只绑 `127.0.0.1:443`：
其他程序绑**其他端口**或**具体网卡地址的 443**（如 `192.168.1.5:443`）都不冲突，
只有绑 `0.0.0.0:443` / `127.0.0.1:443` 才会撞。

**Q：会影响 App 的智能程度吗？**
不会。门只对一个审核接口本地应答，其余请求（模型推理、对话上下文、工具调用）逐字节转发，
模型侧看到的内容与未安装时完全相同。

**Q：我开着 Shadowrocket / Clash，需要额外设置吗？**
不需要。这类工具的 TUN/fake-IP 模式会让代理进程自己解析域名从而绕过 hosts，
安装时注册的守护会把这两个域名幂等写进系统代理例外（每 30 秒检查补回）。
代理重连会重写该配置，所以存在 ≤30 秒空窗——该窗口内审核请求直达服务器，
也就是**拦截暂时回到原状，但不影响可用性**。

**Q：门会跟着 App 一起退出吗？**
不会。门是常驻系统服务（开机自启、崩溃自动拉起），因为它需要在任何时刻接住发往
这两个域名的请求——包括你在浏览器或别的工具里访问时。空闲内存约 55 MB。

**Q：怎么彻底确认它在工作？**
在 App 里发一条**以前会触发横幅**的消息，然后看日志：

```
SAFETY(h2) POST /mavis/api/v2/content scene=11 -> local-pass
```

`scene=11` 是正文输出审核、`scene=13` 是思考审核。

## 目录结构

```
~/Library/Application Support/safety-gate/
├── gate.mjs                  门服务（HTTP/2 + HTTP/1.1 + SSE + WebSocket 透传）
├── certs/                    本机专属 CA 与 agent.minimax.cn/.io 证书
├── guards/hosts-guard.sh     hosts fail-open 守护（每 5s）
├── guards/proxy-guard.sh     代理例外守护（每 30s）
├── bin/{check,ctl,failover-test,install,uninstall}.sh
├── install/                  已渲染的 launchd plist 备份
├── state/                    运行时状态与代理配置备份
└── logs/
```

证书**在每台机器上独立生成**，仓库中不包含任何私钥。

## 许可证

仅用于个人在本机对自己安装的客户端做网络层调整。请自行确认符合你所处地区的法律法规与服务条款。
