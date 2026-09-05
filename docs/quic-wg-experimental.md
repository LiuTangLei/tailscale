# Experimental QUIC-WG: implementation and acceptance status

## Status

This branch contains a runnable, pinned-certificate QUIC DATAGRAM carrier for the
existing Tailscale WG/AWG engine. It is **not a performance-approved release**.
Native transport remains the default. Do not replace production tailscaled with
this experiment on the strength of the connectivity tests alone.

Base: Tailscale compatibility commit `5c345d2c1`, based on upstream 1.102.3.
WireGuard/AWG dependency: `v0.0.31-0.20260905021413-8835972ec5d8`.
QUIC dependency: `github.com/quic-go/quic-go v0.62.0`.

The earlier compatibility-only work is documented in
[wgtransport-experimental.md](wgtransport-experimental.md). Its statements about
QUIC not yet being implemented describe phase 1, not the current branch.

## Implemented

- Complete WG/AWG messages, including handshakes, are carried inside real QUIC
  DATAGRAM frames. There is no fabricated QUIC header and no reliable stream
  secretly replacing datagram semantics.
- TLS 1.3 with mutual certificate presentation and mandatory pinned-SPKI
  verification. Each TLS public-key pin maps to exactly one configured WG node
  public key. The active local WG public key must match the configuration.
- The application ALPN is `quic-wg/1`. This is **not HTTP/3 or MASQUE**, and is not
  claimed to be indistinguishable from browser traffic. STUN/discovery outside
  the WG data path remains visible.
- Native mode passes through the original Bind. Strict QUIC mode does not fall
  back to publicly exposed native WG when a peer, certificate or path fails.
- Close/Open generations, simultaneous connection establishment, deterministic
  duplicate selection, one-sided reconnects, peer reset, and endpoint refresh.
- Bounded startup queues and byte budgets, pooled small packets, established
  connection send fast path, and bounded fragment reassembly for messages that
  exceed the current QUIC datagram limit. The inner IPv6 MTU is not silently
  reduced below 1280.
- Diagnostic counters for connections, authenticated data, queue drops, send
  failures, fragmentation and QUIC connection statistics.

### Two I/O paths

`io: "udp"` uses a dedicated native UDP socket and explicit reachable peer
addresses. The Tailscale host socket factory is used for routing/namespace
integration. A native UDP socket preserves quic-go's supported socket
optimizations, including Linux batch/GSO support. It does not automatically
advertise or punch the separate QUIC port through NAT.

`io: "magicsock"` (the config default) uses the existing Bind's logical endpoints,
peer discovery and path selection. It must not interpret node-key endpoint
strings as IP addresses. Native Linux GRO aggregate receive buffers are handled
using the host's buffer geometry; a single-packet-sized aggregate buffer caused
truncation during development and has been corrected.

**Strict QUIC-over-DERP is not accepted yet.** The real-host forced-DERP test with
AWG 3.1 timed out waiting for encrypted TSMP. This mode must not be advertised as
preserving working production DERP fallback. The code does not silently bypass
QUIC to turn that failure into a false success.

## Configuration

Enable explicitly before starting an isolated process:

```sh
export TS_EXPERIMENTAL_WG_TRANSPORT=quic
export TS_EXPERIMENTAL_QUIC_CONFIG=/absolute/path/quic.json
```

A UDP configuration has this shape (replace all placeholders):

```json
{
  "version": 1,
  "io": "udp",
  "local_public_key": "nodekey:<this node's 64 hexadecimal digits>",
  "certificate": "cert.pem",
  "private_key": "key.pem",
  "listen": "0.0.0.0:42642",
  "initial_packet_size": 1200,
  "queue_packets": 256,
  "peers": [{
    "public_key": "nodekey:<peer's 64 hexadecimal digits>",
    "spki_sha256": "<SHA-256 of peer certificate SubjectPublicKeyInfo>",
    "endpoint": "<peer literal IP>:42642"
  }]
}
```

For magicsock, set `io` accordingly and omit `listen` and peer `endpoint`.
Relative certificate paths are relative to the configuration file. Pins must be
provisioned over a trusted channel; there is no trust-on-first-use mode. Restrict
private-key file permissions. The lab's identity command creates short-lived test
certificates, not a production certificate-management system.

The 1200-byte default is conservative. Raising `initial_packet_size` to 1400 was
explicitly done for the tested server path; it is not a safe universal setting
for every access network. Key rotation and config/pin changes currently require
coordinated configuration updates and process restart.

The TLS config replaces default CA/hostname checks with its mandatory SPKI
verifier. `InsecureSkipVerify` in that implementation is not an authentication
bypass: `VerifyConnection` checks the certificate, pin and expected WG identity,
and ordinary TLS verifies possession of the corresponding private key.

## Real-host experiments

Hosts: SG `96.9.212.12` and ZJG `173.249.215.87`; each reported two CPUs.
The lab runs separate tsnet processes, node state and certificates. It does not
replace production binaries, use production node keys, or edit host routes/DNS.
The test control and dedicated DERP are loopback services reached by authenticated
SSH forwards. Direct data uses the two servers' public UDP paths.

The scripts first check encrypted TSMP plus verified 1 MiB upload and download in
both directions. QUIC TLS/DATAGRAM and application counters are checked; a disco
ping by itself is never considered proof of WG data transfer.

Example reproduction:

```sh
go build -trimpath -o /tmp/quicwg-lab-local ./cmd/wgcompat-lab
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -o /tmp/quicwg-lab-linux-amd64 ./cmd/wgcompat-lab
python3 scripts/quicwg-remote.py \
  --local-binary /tmp/quicwg-lab-local \
  --linux-binary /tmp/quicwg-lab-linux-amd64 \
  --sg root@sg.yesican.top --zjg root@173.249.215.87 \
  --variants native,quic-udp,quic-magicsock \
  --mib 16 --parallel 4 --rounds 1 --output /tmp/quicwg-result.json
```

### Performance gate: NOT PASSED

Development snapshot `parallel-fastpath.json`, 4 concurrent streams, each 16 MiB
(total 64 MiB per directional benchmark), aggregate throughput measured against
wall-clock time:

| Direction | Native WG | QUIC/native UDP | QUIC/magicsock |
|---|---:|---:|---:|
| ZJG to SG | 112.02 Mbps | 70.16 Mbps | 14.79 Mbps |
| SG to ZJG | 181.92 Mbps | 77.27 Mbps | 31.90 Mbps |

Every transfer in that snapshot completed and passed content verification. That
is a correctness result, **not** proof that the performance requirement is met.
Short earlier single-stream trials were much closer; they must not be used to
hide the substantially worse sustained/concurrent results. Other runs varied.
These are isolated tsnet/gVisor measurements on this path, not kernel-TUN peak
capacity or a controlled universal benchmark.

CPU seconds, RSS, total allocations, GC and transport counters are included in
the JSON reports. CPU includes the test program's content generation/verification
and background activity. SG's pre-existing production 1.92.3 service restart loop
was observed and left unchanged; it is a source of environmental noise.

The GRO truncation, avoidable actor-queue drops, one-sided reconnect selection
and stale endpoint reuse were addressed. Remaining throughput regressions are
not fully attributed. Receiver buffering, scheduling and the interaction of
inner TCP and outer QUIC congestion control need further controlled profiling;
this report does not assert that a single suspected bottleneck explains them all.

## Remaining release gates

1. Sustained throughput/latency/CPU under controlled loss, RTT and mixed traffic;
   improve the demonstrated regressions before describing this as a performance
   or production release.
2. Passing real-host DERP/path-transition tests with an explicitly specified
   strictness policy; no implicit public native-WG fallback.
3. Dynamic authenticated peer capability/pin provisioning, certificate renewal,
   node-key rotation and mobile network switching.
4. Full platform and kernel-TUN integration tests. Cross-compilation alone is
   not Android/iOS/Windows networking validation.
5. HTTP/3/MASQUE is a separate implementation stage, not a label for this ALPN.
