# QUIC 方向切换与会话复用稳定性验收 — 2026-09-06

## 结论及发布状态

本轮已完成性能修复、隔离实机重复验证、历史 AWG 配置回归与跨平台核心编译。**GitHub 预发行尚未发布**：当前 `gh` 没有登录，实际 `gh api user` 和 `gh repo fork quic-go/quic-go --clone=false --remote=false` 均返回需要 `gh auth login`，没有创建远端 fork、tag 或 Release。

没有提前把 Tailscale 指向尚未发布的库版本。源码中的正式 go.mod 仍保留原来可解析的依赖；测试构建使用产物目录中的独立 candidate.mod 引用本地 QUIC fork。普通旧的 build_dist.sh 并不自动等于本轮 BBR 构建，不能将它标成已经发布的优化版本。

## 精确测试版本

- Tailscale 引擎代码：`effdef02e03881ae1eeb91ab203814481f460880`
- QUIC 库：`7f38a9286424f7d979bde30dc92ebdef161a6266`
- 现有 WG/AWG 依赖：`github.com/LiuTangLei/wireguard-go v0.0.31-0.20260905021413-8835972ec5d8`
- Tailscale 分支：`experimental/quic-stability-prerelease-20260906`
- QUIC 分支：`tailscale-datagram-stability`

最终 WAN 构建时两个工作树均无未提交源码修改。后续新增报告检查工具导致 Local CLI 和 DERP 报告的 source_dirty=true；这两项使用的二进制仍然是同一份已固定 SHA-256 的 bbr-applimited 构建，没有换成另一个未记录的 Go 引擎实现。

## 原因与修复

1. 原 HyStart 在本方向只承载少量内层 TCP ACK、远未填满发送窗口时，也用 RTT 波动决定退出慢启动。定向测试先在旧实现复现，再验证修复。现在应用受限时不让这些样本消耗慢启动机会。
2. 单独修 HyStart、再换成 CUBIC，都没有稳定解决长连接复用退化，失败对照保留。最终采用显式启用的 BBRv1，不改变原生 WG/AWG 路径；库的零配置仍是上游 Reno 默认。
3. BBR 参考实现缺少真实的 application-limited 通知。连接没有待发业务数据、只有反向小 ACK 时，其样本可能挤掉之前的带宽估计。现在检查实际流/重传/DATAGRAM 队列，仅在没有待发数据且未被 cwnd 限制时标记应用受限；后续大流量可以在同一条连接上恢复带宽。
4. 修正 BBR 移植的飞行字节语义、初始 MTU、恢复边界和路径迁移；采样编号在 Initial/Handshake/Application 空间之间唯一，丢弃密钥空间和 PMTU 探测包时释放采样记录。
5. BBR 自己已经包含 pacing gain，不再额外叠加普通 Reno/CUBIC pacer 的 25% 余量。仍保留拥塞窗口、发送节奏、丢包恢复、TLS、Peer 认证和 ACL。没有靠关闭拥塞控制、增加无限队列或每轮重连来提高成绩。

BBR 来源为 tdragoun/quic-go 的两个原始提交，保留其作者与历史；修复和归属说明在本地 QUIC 库 FORK.md，MIT 与 Chromium/QUICHE 衍生许可文件随源保留。

## 最终 SG ↔ J 实机样本

使用两台真实机器的独立网络命名空间、真实 TUN 和 Linux 内核 iperf3；外层复用 magicsock，内层 MTU 1280。不是 gVisor HTTP 下载，不是公网明文 iperf，也不是在生产节点上切协议。

每个方向每轮测量 8 秒，总目标速率 300 Mbps，**预热剔除为 0**。每轮使用新的内层 TCP 流，但外层 QUIC 会话不重建。测试器核对每个样本及整组前后的连接计数和握手错误，并记录完整命令墙钟时间。

| 模式/设置 | 轮次 | J → SG Mbps | SG → J Mbps |
|---|---:|---:|---:|
| QUIC-IP，4 流，每方向前空闲 2 秒，SG 先发 | 1 | 297.61 | 299.87 |
| 同上 | 2 | 297.65 | 299.89 |
| 同上 | 3 | 297.20 | 299.85 |
| HTTP/3-IP，4 流，每方向前空闲 2 秒，J 先发 | 1 | 297.53 | 299.74 |
| 同上 | 2 | 297.65 | 299.89 |
| 同上 | 3 | 297.57 | 299.74 |
| QUIC-IP，1 流，每方向前空闲 12 秒 | 1 | 296.74 | 284.01 |
| 同上 | 2 | 297.45 | 284.02 |

独立检查工具验证了全部 16 个最终样本：

- 最低接收平均吞吐：284.011 Mbps；中位数：297.626 Mbps。
- 以接收字节除以包含命令启动和收尾的完整墙钟时间，最低保守下界：247.243 Mbps。
- 每组 passed=true，cleanup_errors=[]，所记录的生产服务基线前后一致。
- 实际控制器为 bbr-v1，TLS 1.3 与 DATAGRAM 生效，wireguard_encryption=false。
- 每组先做双向加密 TSMP 与 1 MiB 上传/下载内容校验，直连 RTT 约 68 ms。

这是本链路、有上限负载和本测试时长下的结果，不是 300 Mbps 极限宣称，也不是长期所有网络都稳定的保证。中途 Reno/CUBIC 和未完成 BBR 适配的低速报告没有删除。早期 BBR 的 309–351 Mbps 使用了 2 秒预热剔除，可能受到窗口追赶影响，不用于本轮最终成绩。

## 其他验证

- 最终 BBR 构建在强制测试 DERP 下，QUIC-IP 和 HTTP/3-IP 均完成双向加密 TSMP、1 MiB 上传与下载验证；这是中继可用性验证，不是中继 300 Mbps 验收。
- 实际 CLI 二进制完成管理配置保存、重启、QUIC-IP/HTTP/3-IP 双向传输、回到 native 的完整流程。
- Tailscale 18 个相关包完整测试通过；关键配置/身份/QUIC 测试竞态运行 3 次通过。
- QUIC fork `go test ./... -short` 通过（包括其短模式集成测试），拥塞/ACK/HTTP3 的相关竞态测试通过。
- 实际固定的 WG 库 conn/device 包连续 3 次通过。
- 35 项平台编译检查通过，包括 Linux 多架构、Windows、macOS、BSD、Android/iOS 核心和上游特殊辅助目标。**不表示 APK/IPA/tvOS 应用已打包、签名或真机验收。**

## 历史 AWG 2.0+ 配置

保留标量及区间 H1–H4、snake_case JSON、有效 CPS 模板、v2/v3/v3.1 能力判断。新增实际 WG Device 回归，在同一个实例连续三轮 v2 → v3.1 → v2 后比较完整 UAPI 状态，确保 header protection、padding、RandomTrailers、DisableCookies 不残留，再检查 native 重置。

新的 QUIC/H3 线协议并不要求老版本理解。旧 AWG 节点继续用 native 路径。已退休的 `<c>` 标签、无效参数等仍明确拒绝，而不是悄悄忽略。没有声称逐一跑过每个外部历史版本客户端。

## 发布顺序（尚未执行成功）

1. 在 Mac 的正常终端执行 `gh auth login`，确认登录帐号具备 LiuTangLei 对应仓库写权限；不要把访问令牌或密码发到聊天里。
2. 先将 QUIC fork 的已测提交推送到用户仓库，建立固定 tag 和 GitHub Release；WG fork 若需要将现有伪版本正式命名，也先在准确提交 8835972 上发布对应 tag/Release。不要移动已存在的 tag。
3. 然后才把 Tailscale 的 Go 依赖改为这些**实际存在**的版本，并让发布构建直接使用已带补丁的 QUIC fork，不再应用旧上游源码 overlay。普通 import 路径可以保持不变，采用指向已发布用户 fork 版本的 replace；不能使用本地目录 replace 发布。
4. 在干净环境验证模块下载/checksum、构建和关键回归；核对产物 go version -m 中的版本，然后创建 Tailscale prerelease。不能先发主程序，再让用户依赖一个不存在的库。

当前没有创建上述版本，也没有声称预发行已上线。候选和报告保留在本地，可按此顺序继续。

## 仍需在预发行说明中保留的边界

当前传输模式按节点选择，不支持同时用 native 连旧 Peer、用 QUIC 连新 Peer。自动继承 Headscale/Tailscale 节点身份的 QUIC 公钥发现尚未实现，首次可信公开身份卡配置仍需要。HTTP/3 是真实协议，不是浏览器指纹完全复刻。实验分支不能冒充所有功能已经完成的正式 RC。

本轮没有替换生产程序：SG 保持 PID 3887101、native、1.102.3-24-t75ee0cbf0；J 保持 PID 2251338、旧 1.102.2。后续检查时 SG 还有约 1.1 GiB 可用空间，应持续注意它原来的小系统盘和日志保留策略，不能无限留存测试产物。

## 原始证据位置

`/Users/lei/code/tailscale-all/artifacts/quic-stability-20260906/`

- `stability-gate.json`：16 样本独立验收汇总。
- `bbr-applimited/build.json`：实际 Tailscale/QUIC 提交及二进制 SHA。
- `bbr-applimited/quic-idle-reverse.json`、`h3-idle.json`、`quic-long-idle-single.json`。
- `bbr-applimited/derp-integrity.json`。
- `local-cli-bbr.json`。
- `platforms-bbr/matrix.json`。
- `hystart-flight/`、`cubic/`、`bbr/`、`bbr-final/`：保留的中间失败/对照，不纳入最终通过成绩。
