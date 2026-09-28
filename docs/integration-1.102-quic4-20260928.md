# 1.102 分支 AWG / QUIC 优化集成（未发布）

本地分支：`integration/1.102-awg-quic4-20260928`。本次只集成、修复和验证；
不打版本标签、不推送、不发布、不更换正在运行的守护进程。
等待官方 1.102.6 后，再合并官方最终提交并执行发布验收。

## 输入版本

| 项目 | 本次输入 |
| --- | --- |
| 官方 release-branch/1.102 | `f07b22d4dffb345c90fed07160c3ba9cb5fc5fff`，2026-09-28 拉取；当时最新官方标签为 1.102.5，没有 1.102.6 |
| 既有 AWG / QUIC 集成 | `b4f1aa3cd300`，包含已发布的 1.102.4 集成、激活/NAT/MTU 修复，以及后续共享 H3/TUN 优化 |
| Tailcat 参考 | `v0.7.0-quic.4`；复用其共享库，不导入 Tailcat 应用、浏览器或 WASM 界面 |
| QUIC | `github.com/LiuTangLei/quic-go v0.63.0-quic.3`，`3d9e7d1f348241b89ec1060f733ea39b967e7f82` |
| WG / AWG / TUN | `github.com/LiuTangLei/wireguard-go v0.0.33-0.20260910045057-ed22747d204e` |
| 工具链 | Go 1.27.1，Linux amd64 |

AWG 保留已经发布的集成依赖，未替换成不兼容的原版 WireGuard 模块。
官方 AmneziaWG `v3.1.20260828` 指向 `b5928efb6ca19f0153958460c3d141f04abc5c2e`；
本项目的移植提交 `8835972ec5d8acec8e028af84261fc5be3be6648` 明确记录
`1b86b2a..b5928ef` 来源，包含 DisableCookies 绕过整个 underload challenge
和移除旧 cookie 发送短路的修复。该提交是 `ed22747d204e` 的祖先；
AWG 3.1 random trailers、cookie、UAPI 事务及设备通信测试也重新执行。

模块使用公开版本和 go.sum，无本地路径 replacement。

## 固定的产品策略

- QUIC 只有微调 BBRv3 + HTTP/3 CONNECT-IP + TLS 1.3。
- 身份和 Tailnet 节点认证自动配置，额外只展示 `server on|off`，默认 off。
- 不提供控制器、TLS 档位或 raw QUIC 选择；旧 CLI 名称统一选择 H3。
- 旧托管 `quic-ip` 配置加载为 H3，保留私钥、证书、peer pins、原认证范围和 server 值。
  缺失的 H3 authority 从公开节点 key 确定性生成。读取不改磁盘，原文件 hash 仍用于 CAS，
  下一次显式保存才持久化 H3 名称。历史 raw QUIC 的两端需要一起升级。
- 历史 identity/peer 工具不再出现在菜单和普通帮助中，但兼容命令仍可管理已有 pin。
  旧客户端显式要求 pin-only 认证时不会被别名转换擅自改成 node-key 信任。
- 原生 WG / AWG、认证撤销、ACL、1200 字节 Initial、MSS 修正、有界队列和无 0-RTT 策略保留。

共享库已把旧 BBR/CUBIC API 归一化为微调 BBRv3，因此不能以旧字段名字推断实际控制器。
本次明确调用 BBRv3 API，并检查真实连接的 `ConnectionStats.CongestionControl`、
TLS 1.3 和 h3 ALPN。旧 `bbr_v3` JSON/Go 字段只为兼容已有调用者保留，不再是选项。
低层 raw carrier 测试/嵌入接口不是面向用户的托管模式选择。

## 借鉴范围与修复

共享库带来 DATAGRAM 成组分配、带宽采样记账减少分配、微调 BBRv3 和恢复修复。
已有 TUN ready reads、批量 DATAGRAM、直接接收、固定 MTU 的 MSS 修正继续使用。
Tailcat 的可靠 TCP 流重传/FIN ACK 改进适用于共享嵌入接口；VPN 仍通过 CONNECT-IP
承载 IP 包，不能直接套用 Tailcat 文件传输的性能结论。浏览器 js.Func 回收不属于 tailscaled。

本次额外发现并修复：

1. 地址缓存只有辅助函数和微基准，实际 `readHost` 仍每包创建 wrapper。
   现在接入每个收包 goroutine 的单项缓存，保留 endpoint 对象和原始字节。
2. `reflect.Type.Comparable` 不能保证包含 interface 的结构体值可比较。
   自定义嵌套 endpoint 能触发 panic；改成 `reflect.Value.Comparable`。
3. `ReadFrom` 在 Close 后仍可能从已就绪队列返回成功。
   优先检查关闭，并在出队后复查；Backend 关闭等待生产者/QUIC 退出后回收原始队列。
4. H3 客户端收到认证完成消息后立即开 TCP CONNECT，服务端可能尚未安装会话，
   从而偶发拒绝已认证请求。增加按 QUIC 连接隔离的安装就绪通知；等待受认证超时、
   请求取消和 generation 关闭约束，就绪后仍重新验证 session、撤销 epoch 和目标授权。
5. AWG `up --force-reauth` 回归测试继承运行者的 SSH_CLIENT，导致误触交互确认。
   测试隔离 SSH 环境，不改变生产确认逻辑。

前 3 项补充用例在修复前分别复现：未复用 wrapper、不可比较值 panic、Close 后返回数据。
第 4 项由完整 race 运行中的 net.Conn/CloseRead 测试暴露；修复后这组真实 H3 测试重复
10 次通过，并加入确定性的就绪/超时/取消/未准入测试。

## 验证

以下检查通过：

```sh
go test -short ./wgengine/... ./net/tstun ./ipn/... ./cmd/tailscale/cli ./cmd/wgcompat-lab ./cmd/containerboot ./tsnet ./disco
go test -race -p=2 ./wgengine/wgtransport/... ./wgengine/quicip ./wgengine/transportprofile ./net/tstun ./wgengine/wgcfg ./disco
go test -race ./wgengine/wgtransport/quicbind -run 'Test(HTTP3StreamWaits|H3TCPConnContract|HTTP3CloseReadStill)' -count=10
go test -mod=readonly github.com/LiuTangLei/wireguard-go/device -run 'TestAWG(31|Padd)' -count=3
go vet ./wgengine/... ./net/tstun ./ipn/... ./cmd/tailscale/cli ./cmd/containerboot ./tsnet ./disco
go mod verify
go build -mod=readonly -o /tmp/tailscale-quic4-bin/ ./cmd/tailscale ./cmd/tailscaled ./cmd/wgcompat-lab
```

这不是整个 Tailscale 仓库所有平台的全部测试。普通 suite 使用 `-short`；
race 覆盖本次关键传输、配置和队列包。迁移后的真实引擎 LocalAPI/restart 测试
验证 H3、TLS 1.3、BBRv3、节点 key 不变、pin-only 拒绝缺失 peer 和配置 CAS。

`scripts/check-quic-platforms.py` 最终检查 Linux amd64/arm64、Windows amd64、
macOS arm64、Android arm64 的 Go 核心包全部通过；这属于交叉编译，不是设备实测、
Android APK、Windows 安装包或 Apple 签名验证。

最终 CLI 的 `awg --help` 实际输出已检查：只描述固定 BBRv3/H3 策略和 server 开关，
identity/peer 不在普通子命令列表中。

最终本地 lab 二进制分别执行直连和强制 DERP，各 10 个阶段：3 轮并发双向
256 KiB 上传/下载、65 秒空闲恢复、双方分别 rebind、对端重启、双方分别
SIGKILL 后恢复、同时重启。长度和 SHA-256 检查通过；强制 DERP 没有逃逸到直连，
直连组确实走 direct；清理错误为零。所有测试只使用临时控制服务器、DERP、
节点状态和进程，不接触生产服务、路由或防火墙。完整报告保留在
`/tmp/tailscale-quic4-final-direct.json` 和 `/tmp/tailscale-quic4-final-derp.json`。

### 性能证据与限制

连续同 endpoint 的 wrapper 微基准，三次运行均从 **16 B/op、1 alloc/op**
降为 **0 B/op、0 alloc/op**；真实 `readHost` 测试确认缓存确实接入数据路径。
这不等于整个 QUIC 路径零分配，也不是整机 CPU 降幅。

真实本地 tsnet 内层 TCP / H3 DATAGRAM 对照：基线为 `b4f1aa3cd300` +
`v0.63.0-tailscale.1`，候选为本分支 + `v0.63.0-quic.3`；相同 Go 1.27.1、
20 Mbps 双向外层 QUIC 限速、60 ms RTT、600000 字节 FIFO、server 声明预热、
复用会话双向文件传输。16 MiB 对照顺序为 A/B、B/A、A/B；所有 SHA-256 一致。
随后各做一次 64 MiB 双向对照。两端实际控制器分别记录为 bbr-v1 与 bbr-v3。

| 大小/方向 | 基线 Mbps（保留所有样本） | 候选 Mbps（保留所有样本） |
| --- | --- | --- |
| 16 MiB 普通节点 → server | 17.11 / 12.47 / 17.11 | 16.88 / 16.84 / 15.54 |
| 16 MiB server → 普通节点 | 17.67 / 17.38 / 10.81 | 10.85 / 12.56 / 17.13 |
| 64 MiB 普通节点 → server | 17.72 | 17.53 |
| 64 MiB server → 普通节点 | 17.81 | 16.21 |

**没有证明 VPN 吞吐提升或达到 95% WG parity。** 16 MiB 反向中位数为基线
17.38、候选 12.56 Mbps；64 MiB 反向候选也仍较慢，不能删去这些结果。
较慢的反向样本在换向前已退出 STARTUP，拥塞窗口约 16–31 KiB；这也出现在
基线慢样本，而较快样本换向前仍处于 STARTUP、窗口约 77 KiB。
此为诊断相关性，不是已证明的单一根因。记录的本地 FIFO、发送/接收队列丢包和
QUIC 丢包均未解释该差异。没有为了提高一个样本而改动共享库算法、增加队列、
延迟攒包、降低认证或向用户增加控制器选项。

可以用现有 opt-in 测试复现（基线/候选在独立 worktree 顺序执行）：

```sh
TS_H3_BULK=1 TS_H3_BULK_BYTES=16777216 TS_H3_BULK_SHAPE=1 TS_H3_BULK_WARM_PROFILE=1 TS_H3_BULK_RESULT=/tmp/h3-result.json go test ./tsnet -run '^TestManagedH3BulkFile$' -count=1 -v
```

原始日志和完整逐段诊断在 `/tmp/tailscale-quic4-comparison/`、
`/tmp/tailscale-quic4-comparison-long/`；结构化摘要随本记录保存在
`docs/validation/integration-1.102-quic4-20260928.json`。

## 发布前仍需完成

- 拉取并合并官方 **1.102.6** 最终提交，再跑受影响测试、平台构建和协议回归。
- 真实多主机双向、直连/DERP、弱网和长期运行验收。当前本地结果不是新的 WAN 结论。
- 继续隔离反向慢启动与内层 TCP/BBRv3 的交互，验证性能退化是否可稳定重现；
  在解决或明确接受该差异前，不把本分支宣传为吞吐优化版本。
- 最终版本、跨平台应用包/签名、公开资产 SHA-256 回读和安装升级验收。

本次没有安装测试包到生产、创建 release/tag 或触发发布流程。
