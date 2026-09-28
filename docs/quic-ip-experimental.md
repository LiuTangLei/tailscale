# Native QUIC IP data-plane experiment

## Scope and baseline

Branch: `experimental/quic-ip-1.102.3-20260905`.
Base: `fb402b6f986ba18548084b8b37329c8bd05e51bf` (the previous WG-over-QUIC experiment), itself based on official Tailscale 1.102.3 plus this project's Tailscale/AWG integration.
The existing Tailscale-compatible WireGuard/AWG fork remains pinned to
`v0.0.31-0.20260905021413-8835972ec5d8`; QUIC remains quic-go v0.62.0.

This is a real, opt-in **IP-over-QUIC DATAGRAM** backend. It does not construct a
WireGuard `device.Device`, perform a Noise handshake, encrypt packets a second
time, or disguise its TLS handshake as HTTP/3. Default/native operation and the
legacy WG-over-QUIC backend remain available for compatibility and comparison.

## Compatibility boundary

`wgengine/packetengine.go` is the IP data-plane boundary:

- `wgPacketEngine` wraps the existing Tailscale-modified WG/AWG Device. Its lazy
  peer configuration, allowed IPs, per-destination selection, session callbacks
  and status access remain attached to the same library as before.
- `ipPacketEngine` delegates to `wgengine/quicip.Device`. It owns one batched TUN
  reader and uses the authenticated datagram carrier, never a hidden WG Device.
- `wgtransport` remains the carrier boundary. `quicbind` supports either complete
  WG messages or raw IP, with separate configuration versions and ALPNs.

Only one packet engine reads the TUN. A QUIC-IP node is selected explicitly at
startup; this milestone does not multiplex WG and QUIC-IP independently for every
peer or negotiate a transparent downgrade.

| Mode | Packet engine | Carrier | Wire application |
|---|---|---|---|
| empty / `native` | existing WG/AWG | original magicsock Bind | WG/AWG |
| `quic` | existing WG/AWG | QUIC DATAGRAM | `quic-wg/1` |
| `quic-ip` | native IP pump | QUIC DATAGRAM | `quic-ip/1` |

The default native carrier returns the exact original Bind object. It does not
pay the new QUIC/IP queue, packet parser or authorization callback costs.

## Security semantics replacing WG

**Identity:** both TLS endpoints authenticate by explicitly provisioned SPKI pins.
Each pin maps to exactly one configured Tailscale node public key. TLS verifies
possession of that certificate's private key. This is an administrator-provisioned
binding, not a claim that TLS proves possession of the former WG private key.
Pins are never learned from an unauthenticated packet, user-supplied IP address,
or certificate subject string. TLS verification cannot be disabled by config.

**Live admission:** a pin is not an authorization grant. The current control-plane
profile must still contain the local identity and remote node, and neither may
be expired. Local profile/key changes, remote removal and key rotation invalidate
admission even while a TLS connection remains open. A rejected native-IP config
clears the previous data-plane identity rather than continuing with stale state.

**Source ownership:** inbound packets must carry an authenticated carrier peer
key. `ipnlocal.peerSourceAllowed` checks live membership, rejects spoofing the local
node or another exact node address, then checks the route manager's immutable
source-prefix snapshot. Longest-prefix matching prevents an exit/default or
supernet peer from impersonating a more-specific authorized source. Equal-prefix
eligible HA subnet routers may both originate traffic; inbound permission is not
arbitrarily tied to the outbound route-score winner. The table includes *all*
control-plane peers, not just configured QUIC peers. Route preference changes,
extra allowed-IP changes, expiry, deletion and key rotation update this snapshot.

**Packet processing:** strict IPv4/IPv6 lengths, IPv4 IHL and address-family checks
run before delivery. Mapped IPv6 addresses and unsupported jumbograms are rejected.
Accepted packets go through `tstun.Wrapper.Write`, not `InjectInbound*`. Existing
Tailscale ACLs, jailed-peer filters, NAT, capture, TSMP and netstack dispatch remain
in that path. The TUN's 16 bytes of workspace headroom are not a WG wire header.

**Cryptography:** QUIC provides the only data encryption and packet replay
protection. There is no second application AEAD/counter window. 0-RTT is disabled.
DATAGRAM loss remains possible and payloads are not retransmitted by QUIC; inner
TCP retains its own recovery. Inner TCP and outer QUIC still have distinct
congestion control, so removing WG does not promise native-WG throughput.

**Bounded resources:** the carrier retains bounded queues, admission limits and
bounded/expiring fragment reassembly. The IP pump reuses batch buffers and caches
only endpoint objects, never source permission. Existing QUIC session and bind
reopen/reconnect behavior is reused. Callback publication observes current session
state rather than reporting an old connection's late event as current.

## Configuration

QUIC-IP requires an explicit version-2 file and has a different ALPN. Version 1
cannot silently switch to IP, and version 2 cannot silently carry WG messages.
A schematic configuration (replace the identity fields and paths):

```json
{
  "version": 2,
  "payload": "ip",
  "local_public_key": "nodekey:<this-node-public-key-hex>",
  "certificate": "/etc/tailscale-quic/node.crt",
  "private_key": "/etc/tailscale-quic/node.key",
  "io": "magicsock",
  "peers": [
    {
      "public_key": "nodekey:<peer-node-public-key-hex>",
      "spki_sha256": "<trusted-peer-certificate-spki-sha256-hex>"
    }
  ]
}
```

Select with `TS_EXPERIMENTAL_WG_TRANSPORT=quic-ip` and
`TS_EXPERIMENTAL_QUIC_CONFIG=/etc/tailscale-quic/config.json`.
`AmneziaWG` preferences and `TS_AMNEZIA_*` environment settings must be cleared;
nonzero AWG settings are rejected, not silently ignored. Programmatic embedding
uses `wgengine.Config.Transport` / `tsnet.Server.Transport` with a matching factory.

`io=udp` additionally requires a literal `listen` address and literal per-peer
`endpoint`. It uses the host-protected UDP listener (including platform routing
protection) and quic-go socket optimizations. `io=magicsock` shares Tailscale's
existing discovery/path selection and DERP plumbing; explicit endpoint overrides
are forbidden there. There is no automatic native-WG fallback.

Pins/addresses are immutable for a configured factory; adding peers or rotating
TLS pins currently requires an explicit configuration reload/restart. The existing
256 configured-peer limit remains. Automatic control-plane distribution of pins,
per-peer mixed backend negotiation and HTTP/3/MASQUE are outside this milestone.

## Status and diagnostics

QUIC-IP peers report `SessionProtocol=quic-ip`, their actual TLS
`LastSessionEstablished`, and generic session state. `LastHandshake` remains zero;
`PeerByKey` does not manufacture a WG peer pointer. Historical session enum names
remain aliases for API compatibility. Engine liveness understands the generic
session metadata.

The lab `/quic` endpoint reports `payload=ip`, `alpn=quic-ip/1`,
`wireguard_encryption=false`, actual QUIC/TLS counters, and native IP admission,
source-denial and malformed-packet counters. It contains no private keys or packet
contents. Source parsing and snapshot lookup are allocation-free; whole-system
performance must still be measured, not inferred from these microbenchmarks.

## Validation and reproduction

Tests cover actual QUIC transfer with no WG Device, source spoofing by an otherwise
trusted TLS peer, live source/peer revocation, ordinary ACL deny/restore through the
real TUN wrapper, node/local expiry, removal, public-key rotation, profile switches,
HA/overlap source rules, configuration rejection/recovery, truthful status merge,
IPv4/IPv6 parsing and legacy WG/AWG regressions. Carrier tests retain reconnect,
Close/Open, pin rejection and fragmentation checks. See test names under
`wgengine/quicip`, `wgengine/wgtransport/quicbind`, `wgengine`, `ipn/ipnlocal`,
`ipn/ipnstate` and `net/routemanager`.

The isolated host harness is `scripts/quicwg-remote.py`, using `cmd/wgcompat-lab`.
It does not replace production tailscaled, change system routes/firewalls, or use
production private keys. Temporary control and DERP listeners are loopback-only
and forwarded via authenticated SSH. TLS keys stay on the host that generated
them; only public pins are exchanged. Temporary test units have runtime limits
and are cleaned up with their own files.

Examples:

```sh
python3 scripts/quicwg-remote.py \
  --local-binary /path/to/macos-lab --linux-binary /path/to/linux-lab \
  --zjg root@173.249.215.87 \
  --variants native,quic-udp,quic-ip-udp,quic-ip-magicsock \
  --mib 16 --parallel 4 --output /path/to/performance.json

python3 scripts/quicwg-remote.py \
  --local-binary /path/to/macos-lab --linux-binary /path/to/linux-lab \
  --zjg root@173.249.215.87 --variants quic-ip-magicsock \
  --force-derp --proof-only --output /path/to/derp.json
```

`--ipv6-proof` adds inner IPv6 TSMP and verified file transfers. Each file probe
verifies content rather than counting discovery pings as data-plane success.
Parallel throughput uses total verified bytes divided by wall-clock duration;
CPU time, allocations, RSS and QUIC queues/loss are recorded separately. Records
made from intermediate builds are retained as diagnostics, not relabeled as final
release evidence. Final results and binary hashes belong in the artifact manifest.

A fixed upstream/debug interaction is also covered: forced DERP deliberately
turns off UDP; netcheck's expected send failures must not continually rebind UDP
and tear down a healthy relay. Normal UDP send failures still trigger recovery.

## Remaining deployment boundaries

This is an experimental, node-level native IP backend, not a claim of transparent
interoperation with unmodified WG nodes. No production daemon replacement,
Android/iOS runtime certification, arbitrary peer-relay matrix, broad Internet
anti-classification guarantee or long-duration soak is implied. A passing forced
DERP integrity test proves connectivity, not high-performance QUIC-over-TCP. The
lab's SSH-forwarded relay is intentionally not a public-DERP speed benchmark.
