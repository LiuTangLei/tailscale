# Native IP over HTTP/3 (experimental)

This branch keeps `native` as the default. It adds real HTTP/3 CONNECT-IP framing
on the native IP engine, not WireGuard ciphertext with an `h3` ALPN label.

## Distribution modes

| Mode | Default distribution | IP engine |
| --- | --- | --- |
| `native` | Available, default | Existing Tailscale-compatible WG/AWG fork |
| `quic-ip` | Explicit opt-in | Native IP over authenticated QUIC DATAGRAM |
| `http3-ip` | Explicit experimental opt-in | Native IP over HTTP/3 CONNECT-IP |
| `quic` (WG-over-QUIC) | Rejected | Available only in `ts_dev_wg_over_quic` builds |

Both mode resolution and version-1 QUIC configuration reject WG-over-QUIC in
normal builds. An injected factory cannot bypass the mode gate. For a legacy
peer use `native`; there is no silent protocol downgrade. Development comparison
builds must explicitly use `go build -tags ts_dev_wg_over_quic` and the remote
comparison script additionally requires `--dev-wg-over-quic`.

## Actual wire behavior

HTTP/3 uses a TLS 1.3 QUIC connection, `h3` ALPN, HTTP/3 control/QPACK streams,
SETTINGS, Extended CONNECT with `:protocol=connect-ip`, and a successful response
with `Capsule-Protocol: ?1` before installing an IP session. HTTP Datagrams carry
the request stream's Quarter Stream ID, context ID 0, and the IP packet. Normal
packet transmission is unreliable DATAGRAM, not a reliable stream tunnel.

The stream also consumes DATAGRAM capsules and validates address/route capsule
syntax. Remote capsules never grant addresses or routes in the Tailnet: the
existing authenticated control plane remains authoritative. This is a direct,
preconfigured peer profile, not a general-purpose address-allocating MASQUE
proxy. It does not implement arbitrary target forwarding or HTTP proxy chains.

The optional `Connect-IP-Fragmentation: v1; context=2` header negotiates a private
bounded fragmentation extension. Context 2 is used only if both ends agree; a
standard context-0 packet remains standard CONNECT-IP. Unknown contexts are
ignored. Reassembly is bounded and shared between the DATAGRAM and capsule
receive paths. QUIC starts at 1200 bytes by default, including on mobile paths;
there is no requirement for an oversized Initial before path MTU discovery.

## Identity and authorization

A browser can open the public HTTP site without being asked for a client TLS
certificate. Native HTTP/3 peers pin the server's SPKI and authenticate the
CONNECT request with a signature made by their separately pinned identity key.
The signature covers a TLS 1.3 exporter and the exact method/protocol/authority/
request target. A signature from one TLS connection cannot be replayed on
another. This `Authorization: Peer ...` scheme is a private authorization profile,
not a claim of implementing HTTP Message Signatures.

A pinned certificate alone does not authorize packets. A profile can also enable
`auto_trust`, which authenticates active peers using the current authorized
node key instead of a manually imported pin list. Existing manual pins remain in
force as additional constraints. Admission, source-IP ownership,
expiry/deletion, and local identity are checked against current Tailscale
policy. The same longest-prefix source authorization and `tstun.Wrapper.Write`
path used by native QUIC-IP remains in effect, including ACL, jailed-peer
handling, NAT, and netstack dispatch. WG `LastHandshake` stays zero; session
status reports `http3-ip`. No WG Device is constructed.

Configuration remains immutable for a factory's lifetime. Certificate/pin
rotation requires a new factory/engine configuration; this is not automatic
certificate provisioning. Never distribute the node's private key to a peer.

## Public site and the limits of browser resemblance

HTTP/3 GET/HEAD `/` serves a small static page on the configured authority.
Unknown requests and unauthenticated CONNECT requests receive ordinary errors.
An optional HTTPS/TCP listener serves the same page and advertises HTTP/3 with
Alt-Svc. It is not a TCP fallback for the IP tunnel and it never forwards to an
arbitrary destination. Do not bind a port already used by an existing service.

This establishes real HTTP/3 interoperability and a normally readable site.
It does **not** reproduce Chrome's TLS/QUIC fingerprint, HTTP settings order,
traffic volume, packet timing, ECH behavior, or an existing site's assets.
Application data still uses the Go QUIC implementation, not Chromium's network
stack. A claim that this is indistinguishable from browser traffic is not made.

For a normally trusted browser visit, install a certificate valid for the
configured hostname, with an appropriate trusted chain. Lab certificates are
short-lived/self-signed; the isolated Chrome test trusts only their exact SPKI
and explicitly enables QUIC for the test origin. That test is interoperability,
not public PKI validation or a fingerprint equivalence test.

## Configuration example

Set `TS_EXPERIMENTAL_WG_TRANSPORT=http3-ip` and
`TS_EXPERIMENTAL_QUIC_CONFIG=/private/path/http3.json`. Clear AWG-specific prefs
and environment settings first: native IP modes reject an AWG profile.

```json
{
  "version": 2,
  "payload": "ip",
  "http3": true,
  "io": "udp",
  "listen": "0.0.0.0:8443",
  "http3_tcp_listen": "0.0.0.0:8443",
  "http3_url": "https://node-a.example:8443/.well-known/masque/ip/*/*/",
  "local_public_key": "<node-a public key, 64 hex characters>",
  "certificate": "node-a-chain.pem",
  "private_key": "node-a-key.pem",
  "peers": [{
    "public_key": "<node-b public key, 64 hex characters>",
    "spki_sha256": "<SHA-256 of node-b certificate SPKI, 64 hex characters>",
    "endpoint": "192.0.2.2:8443",
    "http3_url": "https://node-b.example:8443/.well-known/masque/ip/*/*/"
  }]
}
```

For `io=magicsock`, remove `listen`, `http3_tcp_listen`, and each peer's
`endpoint`. Existing Tailscale discovery and path selection supply transport.
STUN/disco/control-plane traffic outside this packet backend is not converted
into HTTP/3 by this feature. In magicsock mode a logical QUIC connection may be
carried by DERP; there is no native-WG bypass inside that connection.

Embedded clients can pass `wgengine.Config.Transport` (or `tsnet.Server.Transport`)
with `quicbind.NewFactoryWithCertificate`, loading identity material from
app-owned storage rather than relying on environment variables or key file
paths. The private key must remain immutable for the factory lifetime.

Android/iOS/browser builds require `io=magicsock`. Independent sockets do not yet
participate in every VPN-service protection/rebind hook and are deliberately
rejected there. Public TCP listening is rejected in those clients as well.
See `quic-platforms.md` for compile versus runtime scope.

## Tests and reproducibility

Default and explicit development builds test their separate mode gates. Real
QUIC/HTTP3 tests cover bidirectional datagrams, close/reopen, large packets,
small initial packet size, capsule ingress, wrong pins, unauthenticated public
GET versus CONNECT, TLS-exporter replay rejection, live peer revocation,
anti-spoofing, and ACL allow/deny/restore. The same source is tested through
isolated tsnet instances on SG and ZJG without replacing production daemons.

```sh
go test -mod=readonly ./wgengine/wgtransport/... ./wgengine/quicip ./wgengine
go test -race -mod=readonly ./wgengine/wgtransport/quicbind -count=2
go test -mod=readonly -tags ts_dev_wg_over_quic ./wgengine/wgtransport/... ./wgengine
python3 scripts/check-quic-platforms.py --output /tmp/http3-platform-check
```

`quicwg-remote.py` defaults to production modes only, records payload hashes,
TLS/H3 counters, IP-engine rejection counters, CPU/allocation measurements and
cleanup results. Large multi-mode runs can exceed an execution host's timeout;
run a single mode per bounded invocation. A report with `passed=false` or a
missing completed cleanup must not be reported as a full successful run.

Performance is experimental. The HTTP/3 implementation adds request/datagram
processing and can introduce receiver-side queues in its dependency. Successful
integrity tests do not imply native-WG throughput. Do not enable this mode by
default or call it production-ready based solely on these tests.
