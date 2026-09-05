# Packet engines and authenticated carriers

`wgtransport` is the carrier adapter. The higher compatibility boundary is now
`wgengine/packetengine.go`, with two real packet-engine implementations:

- Existing Tailscale-modified WG/AWG Device, unchanged library dependency.
- Native `quicip.Device`, which exchanges IP packets with the filtered TUN and
  never creates a WG Device or adds a second layer of encryption.

See `docs/quic-ip-experimental.md` for native-IP security, configuration and tests.
`docs/quic-wg-experimental.md` describes the earlier double-encapsulation baseline.

## Mode selection

| Selection | Packet payload sent to the carrier | Wire ALPN |
|---|---|---|
| zero / `native` | existing WG/AWG | not QUIC |
| `quic` | WG/AWG ciphertext | `quic-wg/1` |
| `quic-ip` | raw authorized IP | `quic-ip/1` |

Native mode returns the exact original Bind, preserving optional interfaces and
avoiding an added packet queue/copy. QUIC modes require an explicit matching
factory/config. Typos, missing configuration, wrong payload version, untrusted
certificates and unknown peers fail closed; there is no native-WG downgrade.

`Factory`, `Host`, `Backend` and optional peer/network lifecycle interfaces remain
available for compiled providers; no mutable global plugin registry is introduced.
The QUIC core stays in `quicbind`. `Host.ListenPacket` preserves host routing
protection for independent sockets. Native IP additionally needs live local/remote
identity admission, source ownership and session events; static TLS pins alone do
not grant permission. The source policy uses the current control-plane profile and
all eligible route contributors, not the outbound route-score winner alone.

## Lifetime and buffers

The WG or native-IP packet engine owns TUN reads and Bind Open/Close. Provider
final Close is idempotent and must unblock its workers independently of later
host teardown. Bind Open/Close remain repeatable; peer reset, removal and local
identity changes discard the relevant session state. Network change notification
is not proof of arbitrary QUIC path migration support.

Buffers passed to Bind.Send are borrowed for the call. Async paths must retain
an owned copy; normal established QUIC sends avoid the extra startup queue.
Preserve batch sizes, headroom, zero-size receive slots and endpoint identity.
Magicsock may require large trailing read buffers for UDP GRO before splitting;
`ReceiveBufferSizes` exposes that geometry. A logical endpoint string may be a
node key rather than IP:port. Providers must unwrap their own endpoint metadata
before passing it back to magicsock; unknown host endpoint types return an error.

Incoming QUIC-IP endpoints expose the verified TLS peer key. The IP pump then
checks current admission and source ownership before invoking the real
`tstun.Wrapper.Write`, preserving ACL, NAT, jailed filtering and netstack hooks.
`InjectInbound*` is not an alternative for untrusted network data.

## Limits

Backend choice is node-level in this experiment. Pins/endpoints are explicitly
provisioned; mixed per-peer protocol negotiation and automatic pin distribution
are not implemented. Discovery/STUN is outside the encrypted IP data path.
Neither QUIC ALPN claims HTTP/3/MASQUE or indistinguishability from web traffic.
Real-host validation uses isolated tsnet nodes, not production daemon replacement;
throughput, CPU and relay limitations must be read from the measured reports.
