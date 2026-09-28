# QUIC upstream 0.63 integration — 2026-09-22

## Source and dependency

This branch builds on `0cd94518fd67bf8767e4004992a3f457188362ab`, retaining
both the TCP MSS fix and the opt-in Linux ready-record TUN reader.

The QUIC replacement is now:

```
github.com/quic-go/quic-go v0.63.0
  => github.com/LiuTangLei/quic-go v0.63.0-tailscale.1
```

The published source tag resolves to
`658bc72e5bcd0754d38d79308f6b869cea16959e`. It merges official upstream
`v0.63.0` (`9d085cc690f7c96451e8ae5659eb0e64671da47a`) into the validated
`.4` fork (`ee8197f0b13d5680b9ded758d714c888ec92638b`). No old tag is rewritten.
The shared QUIC repository default branch, `tailscale-datagram-stability`,
was advanced by a normal fast-forward push.

The WG/TUN replacement remains the previously verified public commit
`v0.0.33-0.20260910045057-ed22747d204e`; native WG/AWG policy is unchanged.

## Compatibility

Upstream 0.63 changes HTTP/3 server request parsing: ordinary and Extended
CONNECT requests have empty URL.Scheme/URL.Host, while Request.Host retains
authority; Extended CONNECT RequestURI becomes :path. Stream errors are
wrapped as *http3.Error with support for unwrapping underlying QUIC errors.
The current connection-bound authentication uses Request.Host plus escaped
path/query, so these parser changes do not require weakening or rewriting it.
Real H3 authentication/rebind and MSS tests passed against the merged source.

All `.4` DATAGRAM batch and authenticated direct-receive APIs remain. The
separate `.5` cleanup branch came from an earlier base and omitted these
performance additions; it is not a substitute for the performance baseline.
The generic acknowledged-stream-close compatibility API also remains for the
existing Tailcat stream consumer. It is a library facility, not an application
merged into the VPN.

## Repository boundaries

The two applications stay separate:

- `LiuTangLei/tailscale`: VPN application and integration.
- `LiuTangLei/tailcat-quic`: Tailcat application and its commands/services.
- `LiuTangLei/quic-go`: reusable QUIC/HTTP3 implementation, now upstream 0.63.
- `LiuTangLei/wireguard-go`: WG/AWG and shared TUN primitives.

The September 19 `tailcat-tailscale` and `tailcat-quic-go` repositories are
whole-library mirrors created for an alternate isolation branch, not new
application repositories. At inspection time, Tailcat's default `h3-v0.6`
branch and existing `v0.6.0-h3.3` release still pin the original repositories;
only `isolate-transport-release-20260919` references the new mirrors. This
upgrade does not adopt them, delete them, archive them or rewrite their tags.
Historical branches that reference a mirror must be migrated before removal.

Tailcat still needs Tailscale's low-level library facilities. Removing that
runtime dependency entirely, or moving its custom integration into a small
separate module, would be a distinct architecture change. It is not achieved
merely by deleting a similarly named repository. No new mirror is introduced
by this upgrade.

## Verification and limits

QUIC: complete `go test -short ./...`, targeted non-short HTTP request parsing
and stream-error integration tests, race tests for congestion/ACK/handshake/H3
and custom DATAGRAM ownership/receive dispatch/browser handshake, and
`go vet ./...` all passed.

Tailscale: wgengine, quicip, wgtransport and its subpackages, transportprofile,
tstun and tsnet short suites passed with the local merged source. After the
source tag was pushed and downloaded by Go, the affected engine and transport
suites passed again with `-mod=readonly` and no local QUIC replacement.

Tailcat's complete short suite passed both with the merged local library and
with the publicly downloaded `v0.63.0-tailscale.1` tag, including its CLI and
web packages. Its existing Tailscale library pin was not redirected to a mirror.

These are source/build and protocol-compatibility results. This upgrade does
not claim a fresh WAN performance result, full browser indistinguishability,
or a new installed client release. No production daemon, node state, route,
firewall, server mode or operating-system setting was changed.

Sources:
- https://github.com/quic-go/quic-go/releases/tag/v0.63.0
- https://github.com/LiuTangLei/quic-go/commit/658bc72e5bcd0754d38d79308f6b869cea16959e
- https://github.com/LiuTangLei/tailcat-quic/blob/h3-v0.6/go.mod
- https://github.com/LiuTangLei/tailcat-quic/blob/isolate-transport-release-20260919/go.mod
