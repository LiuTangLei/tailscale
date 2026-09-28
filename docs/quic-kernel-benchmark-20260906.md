# QUIC / HTTP/3 kernel TUN benchmark — 2026-09-06

## Scope

Source implementation commit: `113e051b20cb869ded34a683df608a74d76a89de`.
Branch: `experimental/quic-kernel-benchmark-20260906`.

This change adds benchmark plumbing only. SG's production process remained
PID 3887101 and J's production process remained PID 2251338 in the completed
smoke and HTTP/3 reports. Production binaries, Headscale membership, ACLs,
firewall, and route tables were not replaced or reconfigured.

The test engine still uses tsnet for its control-plane setup. Unlike the older
HTTP download benchmark, iperf3 runs in a private Linux network namespace with
only `lo` and `qbench0`. The real Linux TUN fd is owned by the test engine whose
outer magicsock UDP transport runs in the host namespace. Thus the measured
iperf TCP endpoints use Linux's TCP/IP stack, not gVisor's TCP stack. Route and
interface snapshots verify that iperf has no alternate path out of its namespace.
TUN MTU is 1280 on both machines. Traffic is encrypted QUIC-IP or HTTP/3-IP,
not nested WG-over-QUIC. Both modes use magicsock in these measurements.

## Receiver goodput, not offered rate or a QUIC stream benchmark

| Mode | Parallel TCP flows | Measurement interval (excluding 2 s warmup) | Aggregate offered cap | J -> SG | SG -> J |
|---|---:|---:|---:|---:|---:|
| QUIC-IP smoke | 1 | 5 s | 200 Mbps | 199.986 Mbps | 18.875 Mbps |
| QUIC-IP round 1 | 4 | 12 s | 500 Mbps | 28.386 Mbps | 29.625 Mbps |
| QUIC-IP round 2 | 4 | 12 s | 500 Mbps | 53.826 Mbps | 59.331 Mbps |
| QUIC-IP round 3 | 4 | 12 s | 500 Mbps | 80.615 Mbps | 85.984 Mbps |
| HTTP/3-IP | 4 | 8 s | 500 Mbps | 262.690 Mbps | 20.318 Mbps |

These tests were sequential, not simultaneous bidirectional tests. Fresh runs
create fresh test identities and sessions. Rounds within the same run reuse the
QUIC session. Limits and durations differ between the smoke, repeated QUIC and
HTTP/3 tests; these rows do not prove an intrinsic speed ranking of protocols.
The HTTP/3 >200 Mbps result is an 8-second receiver average, not a long soak.

QUIC-IP three-round observations: first direction round 1 had no new QUIC loss
and zero inner TCP retransmits while throughput was low. QUIC smoothed RTT was
about 68 ms; some inner TCP intervals reported RTT around 120–170 ms. Recorded
inner TCP congestion control was BBR. The available counters do not identify
the exact cause. Queueing/backpressure, scheduling, and interaction between
inner TCP and outer QUIC congestion control remain hypotheses to distinguish.
Do not assume that making buffers larger will fix it.

The final raw-QUIC and HTTP/3 snapshots showed zero application receive drops,
QUIC receive-queue drops, send-queue drops and handshake errors. They are not
proof that every lower network layer was loss-free.

## Completed and incomplete runs

Artifacts are under:
`/Users/lei/code/tailscale-all/artifacts/quic-kernel-speed-20260906/`

- `kernel-smoke.json`: passed=true, cleanup_errors=[], production PID snapshots unchanged.
- `kernel-h3.json`: passed=true, cleanup_errors=[], production PID snapshots unchanged.
- `kernel-quic-3round.json`: six iperf results and the completed phase checkpoint
  exist. The parent tool timed out at 270 seconds during the end of the run.
  Top-level passed is still false and hosts/final cleanup evidence is missing.
  Treat it as usable measurement samples, NOT a completed acceptance run.
- `kernel-awg31.json` was NOT created. The same-harness native/AWG control run
  was blocked before execution; previous production native numbers are not an
  equivalent control for this new fixture.

After the interrupted run, a read-only remote check found no active qbench or
quicwg service units, but found these two test namespaces:
`qbench-20260906065821-sg` and `qbench-20260906065821-j`.
The subsequent requested cleanup was blocked. Their corresponding test folders
are `/var/tmp/quicwg-lab-20260906065821-sg` and
`/var/tmp/quicwg-lab-20260906065821-j`. Do not claim they were removed. Later
successful HTTP/3 cleanup pertains only to its own separate run.

## Protocol distinction verified in source

- `quic-ip`: genuine QUIC TLS and DATAGRAM, ALPN `quic-ip/1`, private raw/fragment
  framing, pinned TLS peer identity. No HTTP application protocol.
- `http3-ip`: the same underlying QUIC implementation plus real HTTP/3 control
  streams/SETTINGS/QPACK and an Extended CONNECT `connect-ip` exchange. Normal
  payload uses HTTP Datagrams, not one HTTP request per IP packet and not a
  reliable stream carrying every IP packet. The implementation has additional
  peer-authentication and negotiated fragmentation extensions.
- Both native-IP variants have `wireguard_encryption=false`; neither adds a
  second QUIC connection or second bulk encryption layer simply by using H3.
- H3 can plausibly be categorized as HTTP/3 rather than a custom-ALPN QUIC app.
  That is not proof of browser fingerprint equivalence or resistance to GFW.
  ALPN/SNI, implementation parameters, endpoint and traffic behavior remain
  separate concerns. No censorship experiment was performed here.

## Reproduction

The existing remote lab now accepts:

```
--kernel-iperf --kernel-flows 1,4 --kernel-seconds 15 \
--kernel-mbps 500 --rounds 1
```

`--kernel-udp` is implemented for a future inner-UDP offered-load comparison;
it was NOT exercised in this turn. Default mode still uses the original tsnet
HTTP benchmark unless `--kernel-iperf` is explicitly provided. New TUN creation
is Linux-only and confined to an existing `qbench-*` namespace. The Linux thread
restores its original namespace before starting normal engine operation.

The affected lab, quicbind, and quicip packages passed tests; lab go vet passed.
Linux amd64 and macOS arm64 lab builds succeeded. This is not an RC release.
