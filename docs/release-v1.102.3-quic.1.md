# v1.102.3-quic.1 — 原生 QUIC-IP / HTTP/3 预发行

这是 LiuTangLei 的 Tailscale 1.102.3 fork 的 **prerelease**，不是上游官方版本，也不是全平台生产验收完成的 RC。默认仍然使用 `native`，不会自动改变现有节点的协议、身份或 Headscale 配置。本预发行不取代 Latest 稳定版。

## 已先发布的依赖

- `github.com/LiuTangLei/wireguard-go v0.0.31`，固定提交 `8835972ec5d8acec8e028af84261fc5be3be6648`。
- `github.com/LiuTangLei/quic-go v0.62.0-tailscale.1`，固定提交 `7f38a9286424f7d979bde30dc92ebdef161a6266`。

Tailscale 保留上游 QUIC import 路径，通过版本化 `replace` 指向已发布 fork：

```go
require github.com/LiuTangLei/wireguard-go v0.0.31
require github.com/quic-go/quic-go v0.62.0
replace github.com/quic-go/quic-go => github.com/LiuTangLei/quic-go v0.62.0-tailscale.1
```

不依赖本机目录、临时 candidate.mod 或源码 overlay。普通 `go build` 与 `build_dist.sh` 都使用同一份已发布依赖；缺失 BBR fork API 时编译失败，不静默降级成 Reno。

## 主要变化

原生 `quic-ip` 和 `http3-ip` 直接承载 IP，不创建内层 WG Device，不重复逐包加密。保留当前节点身份、源地址授权、ACL、路由和撤销语义。普通构建拒绝已弃用的 WG-over-QUIC；只有明确的开发标签可以保留该对照模式。

新 QUIC 数据面启用带修复的 BBRv1，正确处理应用受限状态，避免反向小 ACK 或空闲污染带宽估计。库自身零配置仍为上游默认；不改变 native WG/AWG，不关闭拥塞控制或安全认证，也不靠每轮重连恢复吞吐。接收队列有数量/字节上限，队列丢弃与网络丢包分别统计。

HTTP/3 模式包含真实 HTTP/3 SETTINGS、Extended CONNECT、CONNECT-IP 和 HTTP Datagrams，并有普通网页入口。它不是 Chromium 指纹复刻，也不承诺对任何识别系统不可区分。

`tailscale awg` 保留原 AWG 配置功能并提供交互传输管理：状态、身份、可信 Peer、诊断和模式设置。当前/待启用模式及是否需要重启分别显示；取消或 EOF 不保存配置。

## 历史 AWG 兼容

保留历史 AWG 2.x 的有效参数、标量/区间头部和有效 CPS 模板，以及 v3/v3.1 能力判断。同一 WG Device 的 v2 -> v3.1 -> v2 连续回归比较完整 UAPI 状态，防止新参数残留。旧节点继续走 native；不要求旧版本理解新增 QUIC/H3 协议。无效参数和已退休的 `<c>` 标签仍明确拒绝，不保证任意非法配置或所有第三方历史二进制。

## 实测证据与边界

此前相同数据面和相同 QUIC/WG 库提交，在 SG/J 的独立 Linux 内核 TUN 上完成 16 个样本：每方向 8 秒，300 Mbps 总目标，不剔除预热；同一外层会话中反复切换方向，并包含 12 秒空闲后的单流测试。

- 四流 QUIC-IP：J→SG 297.20–297.65 Mbps；SG→J 299.85–299.89 Mbps。
- 四流 HTTP/3-IP：J→SG 297.53–297.65 Mbps；SG→J 299.74–299.89 Mbps。
- 长空闲单流 QUIC-IP：J→SG 296.74–297.45 Mbps；SG→J 284.01–284.02 Mbps。

这是指定链路和负载下的结果，不是速率上限或全网性能保证。完整历史过程在 `docs/quic-stability-prerelease-20260906.md`；该文档中“尚未发布”的描述是发布前的历史记录，以本文件和实际 Release 为准。

切到已发布依赖后重新运行相关包完整测试、AWG 状态回归及管理流程测试。发布产物另外核对真实依赖版本与内容哈希；验证报告与构建清单随 Release 提供。平台矩阵结果只代表核心/辅助目标编译，不代表所有设备实测。

## 必须知道的限制

**当前按节点选择数据面，不支持同一节点同时对旧 Peer 用 native、对新 Peer 用 QUIC。** CLI 会拒绝已知会隔离当前可路由 Peer 的配置。控制面在线不等于数据面可达。

**首次仍需通过可信渠道导入公开身份卡。** 自动继承 Headscale/Tailscale 节点身份的 QUIC 公钥分发尚未实现。私钥只留在本机，不能同步整个 `packet-transport.json`。动态公网 IP 不要求重新申请公共证书。公共证书签发/续期与 Caddy 自动联动未包含在本版。

不建议在缺少带外恢复路径时，把混合版本生产 Tailnet 整体切换到 QUIC。优先在独立测试实例或仅包含已配置新节点的范围内验证。

## 资产与安装

提供 Linux、macOS、Windows 的 amd64/arm64 独立 `tailscale` 和 `tailscaled`，文件名沿用此前 Release。`SHA256SUMS` 与 `BUILD-MANIFEST.json` 记录每个文件的 SHA-256、源提交及两个依赖版本。

这些是独立程序，不是 `.deb/.rpm/.pkg/.msi`、APK 或 IPA。macOS 仅 ad-hoc 签名，没有 Developer ID 公证；Windows 没有 Authenticode 签名。不要把程序直接塞进官方签名 App。替换时保留原有 state、socket、服务参数和身份；本次 GitHub 发布不自动替换任何生产机器。

源码构建：Go 1.26.6，检出本 tag 后执行 `./build_dist.sh ./cmd/tailscale` 或 `./build_dist.sh ./cmd/tailscaled`。构建完整资产可运行 `python3 scripts/build-published-prerelease.py --output <源码目录之外的目录>`。
