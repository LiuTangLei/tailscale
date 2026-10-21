# Packet carriers for the Tailscale fork

The application packet engine and its carrier are separate. `native` preserves
the existing Tailscale-compatible WireGuard/AWG fork and the exact magicsock
Bind. `http3-ip` creates a native IP packet engine, never a WG Device.

## Distribution policy

- `native`: default and compatibility path for WG/AWG peers.
- `http3-ip`: native IP through a real HTTP/3 CONNECT-IP request and HTTP Datagrams.
- Raw `quic-ip` and version-1 WG-over-QUIC providers are removed. Old managed
  `quic-ip` profiles migrate to H3 while retaining identities and pins. Explicit
  raw environment/embedding configurations fail with an upgrade instruction.

Selection uses `wgengine.Config.Transport` / `tsnet.Server.Transport`, or the
explicit experimental environment configuration. Version-1 WG-over-QUIC JSON
is rejected as well as the retired mode; no development tag re-enables it. There is no silent fallback to bare WG.

## Interfaces and ownership

`Factory`, `Host`, `Backend` and optional lifecycle interfaces form the carrier
boundary. Host callbacks supply current peer admission, session notifications,
packet counters, and protected socket creation. The native IP engine separately
checks source-IP policy and delivers packets through the existing filtered TUN
wrapper. Only public node identity crosses the lifecycle interface.

Native mode returns the underlying Bind verbatim. A wrapper must preserve batch
sizes, headroom offsets, Endpoint identity callbacks and repeated Open/Close.
Final Close must cancel and release every worker. `UnwrapEndpoint` is for the
final host send, not for discarding authenticated peer identity on receive.
For `http3-ip`, a profile may also use node-key auto-trust so that active,
authorized Tailnet peers authenticate without requiring a manual pin list.

Desktop/server independent UDP uses host-protected sockets. Mobile/browser
clients must use magicsock until separate-socket VPN-service rebind/protection
is implemented. HTTP/3 supports that host path. An
in-memory `NewFactoryWithCertificate` is provided for embedding clients.

## HTTP/3 scope

The H3 backend includes SETTINGS, QPACK/control streams, authenticated Extended
CONNECT, HTTP Datagrams, capsule receive support and bounded negotiated packet
fragmentation. Public HTTP/3 GET and optional HTTPS/TCP GET serve a small page;
they cannot open a tunnel without current peer authorization. Tunnel proof is
bound to a TLS exporter and the exact request target, not a reusable bearer
secret. The server sends public SETTINGS before client Finished, but a private
CONNECT still waits for TLS completion and current peer authentication.

Client 0-RTT remains disabled. IP/UDP uses unreliable DATAGRAMs: no FEC,
application retransmission, ACK-wait queue or reliable-stream fallback is added.
The optional embedded TCP stream API uses QUIC's normal reliable loss recovery;
it does not change the delivery contract of UDP packets in the VPN.

Independent sockets request 8 MiB receive / 4 MiB send buffers, retry smaller
sizes when a platform rejects the request, and report actual kernel sizes in
`udp_socket_buffers`. No global socket limits are changed. Per-peer
`last_outgoing_setup` reports TLS, SETTINGS, authentication and total durations
in microseconds for the last completed outgoing attempt, including failed stages.

This is not a universal MASQUE proxy, a Chromium fingerprint implementation or
a claim of indistinguishable browser traffic. STUN/disco are still managed by
the host outside this packet backend. Throughput must be measured; HTTP/3 is
experimental and not the default.

See `../../docs/http3-ip-experimental.md` relative to the repository docs area
(`docs/http3-ip-experimental.md`), `docs/quic-platforms.md`, and
`docs/quic-ip-experimental.md` for configuration, security scope and evidence.
