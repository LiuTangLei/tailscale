# WireGuard/AWG carrier compatibility layer

`wgtransport` separates the WG/AWG cryptographic device from its outer carrier.
Native mode returns the identical host Bind: no packet wrapper, extra queue or
copy is added to the native hot path.

The experimental `quicbind` provider now implements real TLS 1.3 QUIC DATAGRAMs.
Its performance and forced-DERP release gates are **not passed**. See
[`docs/quic-wg-experimental.md`](../../docs/quic-wg-experimental.md) for the current
configuration, tests, measurements and limitations. The earlier compatibility
stage is recorded in `docs/wgtransport-experimental.md`.

## Extension boundary

The API comprises `Config`, `Factory`, `Host`, `Backend`, and optional
`PeerLifecycle` / `NetworkLifecycle`. There is no mutable global registry or
runtime plugin loader. The WG/AWG device remains the single cryptographic engine;
AWG settings are independent of the outer carrier.

A provider must preserve the exact `conn.Bind` send offset/batch semantics,
receive zero-size slots, endpoint identity and Cookie address behavior. The host
owns socket routing and discovery. Endpoint strings can be node keys rather than
IP:port. `Endpoint` forwards optional identity callbacks and `UnwrapEndpoint`
rejects nil/cyclic wrappers. Providers must unwrap before sending to magicsock;
unknown endpoint types produce an error instead of a false successful send.

On Linux, host receive batches may include large UDP GRO aggregates. Providers
must use the host's optional `ReceiveBufferSizes` geometry, or sufficiently large
buffers, rather than assuming every receive slot contains one MTU-sized packet.

`Bind.Open/Close` can repeat across WG lifecycle changes. `Backend.Close` is final,
idempotent shutdown and must unblock provider I/O. Lifecycle callbacks are
serialized with final close, can run concurrently with packet traffic, and must
not reenter the engine. Only public node identity is supplied by lifecycle hooks.
Read-only WG peer enumeration never triggers a peer-removal callback.

## Selection and safety

- The zero config / `native` preserves existing WG/AWG behavior.
- `quic` requires an explicitly linked/configured provider and trusted peer pins.
- Misspelled/unavailable modes fail clearly. No automatic downgrade to public
  native WG is performed.
- Tailscale loads `TS_EXPERIMENTAL_QUIC_CONFIG` only when QUIC is selected.
  Embedded `tsnet.Server` users can instead supply `Transport` directly.
- The QUIC adapter implements a custom application ALPN (`quic-wg/1`), **not**
  HTTP/3, browser imitation, game or DNS traffic.

## Tests

```sh
go test ./wgengine/wgtransport/... ./wgengine/magicsock ./wgengine
go test -race ./wgengine/wgtransport/...
```

The carrier seam tests use an explicitly named test provider, not simulated
QUIC masquerading as a real implementation. The `quicbind` tests use actual QUIC
connections and verify WG/AWG plaintext after encryption, bidirectional
fragmented messages, bad certificate rejection, lifecycle and reconnect cases.

Remote tests use `cmd/wgcompat-lab` and `scripts/quicwg-remote.py` in isolated
instances, without replacing production tailscaled or changing routes/DNS.
