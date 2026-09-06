# H3 Mesh 的连接角色、端口与多 Peer 设计

日期：2026-09-06。基线：已发布的 `v1.102.3-quic.1` / `0bcfa8346dcf8e873d976782ee9fecf9281301cd`。
分支：`experimental/h3-mesh-roles-20260906`。

本轮先实现角色与可观察状态的基础，不伪称已经复刻浏览器。没有改动已发布 tag、生产 Tailscale 程序/配置、路由器、防火墙、证书或节点状态。

启动开发时 Mac 磁盘只剩约 117 MiB；只清理了约 123 GB 可再生成的 Go 构建缓存，未删除源码、发布产物或用户数据。

## 1. 三个概念必须分开

- 连接角色：TLS/QUIC client 发起握手，server 响应。角色归属于一条连接，不是机器的永久类型，也不随内层 SSH/TCP 业务方向反转。
- 可达性：TCP/UDP、IPv4/IPv6、入站/出站各自不同。一个家宽无法接收公网 TCP 443 入站，不能推出它无法主动访问远端 TCP/UDP 443；也不能推出所有高位 UDP 都不通。用户的电信/移动链路本轮没有实际测量。
- 外观目标：符合 H3 协议，与看起来像浏览器访问公网网站不同。角色、目的地址、端口、证书/authority、Initial、QUIC 参数和会话行为必须一起考虑。更换 User-Agent 不等于解决这些问题。

H3 可以运行于非 443 的 UDP 端口。客户端不需要监听本地 443。TCP 443 与 UDP 443 是不同监听资源；Caddy 若已占用 UDP 443，不能再让另一个独立 QUIC listener 抢占同一个地址/端口。

## 2. 建议的场景策略

### 家宽 ↔ 公网 VPS

家宽端作为该 Peer 的 H3 client，VPS 作为 H3 server。家宽用允许的本地高位 UDP 端口出站；对端可以是 UDP 443，也可以是明确配置且可达的其他端口。

即使 VPS 上的应用先要访问家里的服务，家宽也应先建立并维持双向隧道，不要求 VPS 反向发起一个新的 TLS 握手。本轮的主动 client 模式解决这个 bootstrap 问题。

浏览器 ClientHello/Initial 模板将来只作用于 client 方向。VPS 应呈现正常 HTTP/3 服务端行为，而不是给 ServerHello 套浏览器客户端模板。公开 CA 证书是可选的服务端部署能力，不是 Tailnet 成员身份本身。

### 国内电信家宽 ↔ 国内移动家宽

优先保留现有 magicsock 地址发现、STUN/disco 与 UDP 打洞；由连接策略决定 TLS 角色。两端可都使用高位端口，不能要求任意一端开放 80/443，也不能把一端的运营商名称或地理位置当成可达性/信任证明。

默认 mesh 策略继续允许按需发起，遇到同时建连沿用已有确定性去重。这是合法的 H3 P2P/私有服务模型，不保证旁观者会认为它是某个公共网站。主动为两端配置互补 client/server 也可以，但不会让 NAT 打洞自动成功。

如果强制两端都必须表现为普通浏览器的公网出站连接，就需要一个可达边缘节点。两条在边缘终结的 TLS 连接不再天然提供 A 到 B 的端到端机密性；要么明确相信边缘节点，要么另加端到端保护。不能用修改 SNI/证书掩盖这个信任变化，也不能为了外观无提示地强制国内流量绕国外。

### 多 Peer 与角色并存

一个节点可以对 A、B 是 H3 client，对 C 是 H3 server，对 D 保持 mesh；每个 Peer 是独立的连接/密钥/拥塞状态。每条连接内两个方向均可传任意获准 IP 数据。

保留共享 socket 上的非零 CID（当前 8 字节）。不能为了照抄零 CID 浏览器模板而破坏多连接分流、NAT 重绑或换网。若后来确实需要零 CID，需要单独的每连接 socket/分流方案和平台验证；不能只改变线上字段。

## 3. 已实现

低层 `PeerConfig.connection_role`：

- `mesh` 或省略：原有按需建连与同时连接去重。
- `client`：只接受自己发起的该 Peer 会话；在身份和 Host 授权有效时主动预连接。所有 Peer 都是 client 时不创建 QUIC server listener，但保留正常 UDP 收包以接收回复。仅添加 client 角色不会开启公共 TCP HTTPS 监听。
- `server`：等待已认证 client 建连，绝不以超时为由偷偷反向 Dial。独立 UDP 模式允许省略动态 client 的 endpoint，由其合法会话确定来源。

这三个值是本地策略，不是新的线协议协商。两端应配置互补的 client/server，或保留兼容的 mesh。两个严格 server 不会自动选出一个 client；不能用自动回落掩盖配置错误。

其他改变：

- 仅显式 client Peer 会主动预连接；默认 mesh 不产生全网常驻连接。
- 单个后台调度器、既有每-Peer actor、最多四个并发 Dial，以及有界退避；不会并行轰炸所有离线 Peer。
- 身份失效/Peer 撤销阻止主动重连，不把 pin 或角色本身当成当前授权。
- 新会话解析当前 Host endpoint，避免预连接提前缓存临时地址。
- H3 CONNECT 的角色检查发生在成功响应之前。
- `peer_connections` 输出每条连接的实际 TLS 角色和拥塞/队列状态；多 Peer 时不再用遍历中的最后一条连接冒充全网统计。单 Peer 保留旧 `connection_stats` 快捷字段；队列数量/丢弃数跨活动连接汇总。
- 诊断明确 `browser_fingerprint: none`，没有开启一个未经验证的 Chrome/Safari 模板。
- 未改 QUIC 库版本、BBR、密码算法、IP 授权/ACL、数据包格式、TUN MTU 或现有 AWG 处理。

## 4. 管理配置与 CLI

新命令（仅本实验分支；已发布 .1 中尚无此命令）：

```sh
# 本机在与该 Peer 的连接里作为主动端；不重启守护进程
 tailscale awg peer role --yes <peer-public-key> client

# 对端以本机公钥为目标设置 server；同样只是保存下次启动策略
 tailscale awg peer role --yes <other-peer-public-key> server

# 恢复原来的按需 Mesh 角色行为
 tailscale awg peer role --yes <peer-public-key> mesh
```

策略只在 `http3-ip` 启动时生效。保持 native 时不会改变 AWG 配置，旧 quic-ip 模式也不解释这组 H3 角色。需要明确重启才能应用，不自动切换协议或修改端口。

私有 profile 里的 `http3_peer_roles` 与公开身份卡分开保存。peer 的“本地 client”不能通过交换卡片变成另一台的“本地 client”。身份卡仍不包含角色、私钥。角色操作有信任检查、取消/EOF 不写入、revision CAS、防外部配置覆盖；删除 Peer 会清除对应角色。

回退到旧 .1 二进制前，用本分支把所有显式角色设回 mesh，让新增字段被省略。旧版的严格 JSON 读取器不会忽略不认识的字段。

重要：每个 H3 Peer 可有不同握手角色，不等于已实现 WG 与 H3 两种数据面在同一节点按 Peer 混用。后者和自动继承 Tailnet 身份仍是独立未完成项。

## 5. 验证范围

角色专项已连续三轮通过；专项 race 已连续两轮通过。测试包括：

- 主动 client 无内层请求也建立会话；server 应用先发数据，后续轮流双向传输不翻转角色、不增加连接数。
- 独立 UDP 与 Host Bind 两种 I/O 的关闭/重开；动态 UDP client 无须为 server 提供固定 endpoint。
- server 等待可取消，不泄漏，也不偷偷反向建连。
- 四个真实 TLS/H3 节点共用各自高位 UDP socket；中间节点同时有两个 client 角色会话和一个 server 角色会话，六个方向并发多轮数据校验和来源身份检查。
- 持久化配置经真实 LocalAPI 保存、实际 tsnet 引擎重启后生效；随后恢复 native，原节点身份不变。
- 角色变更不改变私钥/公开卡；不可信节点不能仅凭角色获得信任；撤销后不因预连接任务自动复活。

11 个相关包完整测试通过，CLI 帮助中的 canonical alias 问题经完整回归发现并修正；旧 AWG 的配置/CLI/disco 回归连续三轮通过，相关 go vet 通过。

Linux amd64/arm64、Windows amd64、macOS arm64、Android arm64、iOS arm64 的相应核心编译/本机测试通过。Android 的桌面 CLI/systray 目标不支持 CGO=0 的这条构建方式，因此移动端只按实际嵌入 VPN 核心范围验收；不声称 APK/IPA 签名或真机测试。

这是本机真实协议/多节点测试，不是中国电信/移动双 CGNAT 实测，也不是新的 WAN 300 Mbps 验收。没有进行 GFW 指纹或阻断效果实验。

后续浏览器适配的验收要覆盖：共享 socket 多 Peer、对端掉线/限速、单边重启、角色冲突、IPv4/IPv6、NAT 重绑、UDP 全阻断转中继、真实浏览器 Initial 差分与相同负载的性能 A/B。当前不声称受限 Peer 对应用层统一发包调度的所有影响均已消除。

## 6. 指纹接入边界

未来以当前角色边界选择 client 模板和 server 行为，不按整个进程统一选择。uTLS 只负责 ClientHello 等握手层特征，QUIC Initial/CID/传输参数与 H3 行为还要分别适配。默认 Mesh 的可靠性优先，不能宣传“不被任何系统识别”。

公网 Web 模式与 P2P Mesh 模式应共享同一个 H3/IP/BBR 实现，区别主要在端点策略、握手角色、允许的指纹 profile 和服务端公开入口，不重新引入 WG 数据加密。

## 7. 依据

- RFC 9000 §5.1：连接 ID、多连接分流与零长度 CID 限制。
  https://www.rfc-editor.org/rfc/rfc9000.html
- RFC 9001：TLS client/server 角色、握手和双向应用数据。
  https://www.rfc-editor.org/rfc/rfc9001.html
- RFC 9114 §3：HTTP/3 可以在任意 UDP 端口提供服务。
  https://www.rfc-editor.org/rfc/rfc9114.html
- Tailscale NAT traversal 与端口说明：
  https://tailscale.com/blog/how-nat-traversal-works
  https://tailscale.com/docs/reference/faq/firewall-ports
- uTLS 的 ClientHello 模仿范围与限制：
  https://github.com/refraction-networking/utls
