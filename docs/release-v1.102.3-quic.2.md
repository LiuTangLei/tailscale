# v1.102.3-quic.2 — HTTP/3 private mesh and per-connection ClientHello

Experimental prerelease; `native` remains the default. This release does not
upgrade or reconfigure running production nodes automatically.

## What changed

- Private `.invalid` HTTP authorities are no longer copied into visible TLS
  SNI. The HTTP authority stays inside authenticated, encrypted HTTP/3; exact
  peer SPKI validation, live node authorization and source-IP/ACL checks remain.
  Explicit real service names retain their own SNI. No third-party domain is
  invented, no certificate validation is disabled as a fallback.
- A single node-local `tailscale awg server on|off` flag, default off, controls
  whether this node advertises itself as a browser-profile target. No per-peer
  role configuration is required.
- Only a **non-server node dialing a trusted, declared server** selects the
  `chromium-h3` TLS1.3 ClientHello. Ordinary mesh, incoming connections, unknown
  peers and server-to-server connections keep the standard TLS implementation.
- Every profile is per-dial, not a mutable global Transport setting. Existing
  authenticated connections are not torn down to change appearance. An unknown
  first connection learns the authenticated server hint for a future connection;
  hints are invalidated by peer revocation.
- The diagnostic profile is the actual local handshake implementation. Multiple
  simultaneous profile types report `mixed`, with independent per-peer details.
- The interactive menu offers native WG/AWG and HTTP/3. Explicit `quic-ip` is
  retained for earlier prerelease configurations and developer comparisons; its
  wire protocol is never silently reinterpreted as HTTP/3.

## What `chromium-h3` means

This is a **Chromium-inspired ClientHello**, not a measured fingerprint of the
current Chrome version, and not a browser/QUIC wire-equivalence claim.

The published QUIC dependency uses uTLS's QUIC handshake event API: TLS1.3-only
cipher suites, hybrid X25519MLKEM768/X25519 shares, randomized extension and
transport-parameter order, and implemented certificate compression. It preserves
all actual transport-parameter values and adds only a bounded reserved parameter.

The existing shared socket, nonzero 8-byte CID, Initial packet construction,
QUIC packet protection, BBR, bounded queues, and CONNECT-IP data plane remain.
No per-packet fake timing, fixed padding ritual, fake WebTransport capabilities,
borrowed public-domain identity, ECH claim or forced reconnect is added.

TLS exporter authentication uses the new connection-level exporter API, rather
than copying unexported crypto/tls fields. Wrong certificates/pins still fail.
The initial client adapter deliberately rejects unsupported resumption/0-RTT,
ECH or custom curve restrictions instead of silently discarding security policy.

## Selection matrix

| Local node | Authenticated remote declaration | Local TLS action | ClientHello |
|---|---|---|---|
| Ordinary | Unknown or ordinary | Dial | Standard H3 |
| Ordinary | Server | Dial | chromium-h3 |
| Server | Any | Dial | Standard H3 |
| Any | Any | Accept | Standard server TLS |

A server declaration is not a firewall rule, public certificate, fixed address,
extra user account or automatic public website. High-port H3 and private mesh
remain supported. No new user-facing fingerprint parameter is needed.

## Dependencies

```go
require github.com/LiuTangLei/wireguard-go v0.0.31
require github.com/quic-go/quic-go v0.62.0
replace github.com/quic-go/quic-go => github.com/LiuTangLei/quic-go v0.62.0-tailscale.2
```

Both are published Go modules. The QUIC fork pins uTLS v1.8.2 and retains
upstream and adaptation license notices. Release builds use neither a local
filesystem replacement nor the old source overlay.

## Compatibility and boundaries

Valid AWG 2.x+ profiles continue to use native WG/AWG, including profile downgrade
reset semantics. WG-over-QUIC remains development-only. The already-published
v1.102.3-quic.1 binaries and tag are unchanged.

The selected packet engine is still node-wide: simultaneous QUIC-to-new-peer and
native-to-old-peer operation is not implemented. First-time QUIC trust still
needs authenticated public identity provisioning; automatic Tailnet node-key
binding is not implemented by this release. Server-hint synchronization does not
mean initial key trust has become automatic.

No claim is made of indistinguishability from Chrome/Safari, public CA trust for
private origins, censorship bypass success, or every supported device having
been runtime-tested. Compile-matrix results are not signed mobile applications.
The published verification attachment records the actual tests and scope.
