# Packet carriers for the Tailscale fork

The application packet engine and its carrier are separate. `native` preserves
the existing Tailscale-compatible WireGuard/AWG fork and the exact magicsock
Bind. `quic-ip` and `http3-ip` create a native IP packet engine, never a WG Device.

## Distribution policy

- `native`: default and compatibility path for WG/AWG peers.
- `quic-ip`: native IP through QUIC DATAGRAM.
- `http3-ip`: native IP through a real HTTP/3 CONNECT-IP request and HTTP Datagrams.
- `quic`: legacy WG-over-QUIC; **rejected in normal builds**, available only with
  `-tags ts_dev_wg_over_quic` for development comparisons.

Selection uses `wgengine.Config.Transport` / `tsnet.Server.Transport`, or the
explicit experimental environment configuration. Version-1 WG-over-QUIC JSON
is gated as well as the mode resolver; a supplied factory cannot bypass the
normal-build mode gate. There is no silent fallback to bare WG.

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
is implemented. Native QUIC-IP and HTTP/3 both support that host path. An
in-memory `NewFactoryWithCertificate` is provided for embedding clients.

## HTTP/3 scope

The H3 backend includes SETTINGS, QPACK/control streams, authenticated Extended
CONNECT, HTTP Datagrams, capsule receive support and bounded negotiated packet
fragmentation. Public HTTP/3 GET and optional HTTPS/TCP GET serve a small page;
they cannot open a tunnel without current peer authorization. Tunnel proof is
bound to a TLS exporter and the exact request target, not a reusable bearer
secret. Raw native QUIC continues to use its separately authenticated profile.

This is not a universal MASQUE proxy, a Chromium fingerprint implementation or
a claim of indistinguishable browser traffic. STUN/disco are still managed by
the host outside this packet backend. Throughput must be measured; HTTP/3 is
experimental and not the default.

See `../../docs/http3-ip-experimental.md` relative to the repository docs area
(`docs/http3-ip-experimental.md`), `docs/quic-platforms.md`, and
`docs/quic-ip-experimental.md` for configuration, security scope and evidence.
