# H3 review and BBR tuning — 2026-09-07

## Scope

The review started from the automatic-authentication branch at `3944e40ac`
and the QUIC fork at `1231045a`. The resulting fixes are included in
`v1.102.3-quic.3`, using published QUIC `v0.62.0-tailscale.3`.
The review and benchmark did not deploy changes to production nodes.

## Findings and fixes

| Priority | Trigger and previous behavior | Change |
| --- | --- | --- |
| P1 | A provisional H3 endpoint sent SETTINGS but granted no bidirectional stream credit. CONNECT opening used the generation lifetime and could pin a peer worker indefinitely. | Apply the existing 10-second CONNECT deadline to stream opening; retirement also cancels a provisional CONNECT. Established streams retain their normal lifetime. |
| P1 | Removed or rotated node keys retained peer actors. After 256 historical actors, new authorized peers were rejected even when most old actors were revoked. | Reclaim disabled actors when reaching the limit, cancel their work, drain queued buffers, and keep retired references invalid. Live actors are never evicted to make room. |
| P1 | At 1 Gbps, a 120-second ACK aggregation interval overflowed integer byte-rate × nanoseconds arithmetic and produced about 3.4 GB of false compensation. High-BDP window calculation also overflowed. | Use bounded arithmetic, reset the aggregation epoch after idle, cap compensation, and apply BDP gains before the final window cap. |
| P2 | ProbeBW ignored congestion feedback. Loss could keep flight below its probe target and leave the controller at high gain. | Latch congestion until the probe can finish, then drain and update pacing; a batch of loss callbacks cannot skip multiple phases. |
| P2 | The default `http3.Transport` uses `DialEarly`, which the Chromium profile rejected even with no session or early data. | Complete a fresh authenticated handshake on the opportunistic early-dial path. Resumption/actual 0-RTT remain disabled. The Tailscale consumer's manually opened QUIC path was not this failing entry point. |
| P2 | uTLS error conversion discarded original certificate and verification-callback errors; ECN notifications increased packet-loss counts. | Preserve TLS error causes for `errors.Is/As`; retain ECN congestion response without counting or discarding a packet as lost. |

Peer reclamation is additionally guarded against endpoint-refresh revocation,
same-key re-addition, late state notifications, a send racing shutdown, and
receiver cancellation losing ownership of a still-live QUIC connection.
Source-IP/ACL checks, node-key proofs, exporter binding and server-role handshake
selection remain in the existing authentication/data path.

## BBR behavior

This remains a **BBRv1-derived controller with selected BBRv3 ideas**, not a full
v3 port. Startup uses 2.77 pacing gain and 2x BDP window gain; drain uses 0.5;
normal pacing leaves a 1% margin. Idle restart retains the bandwidth model and
starts at the delivery rate with that margin.

ProbeRTT now targets half the BDP with a floor of four path-sized datagrams.
The previous unloaded RTT determines the drain target. A higher RTT can replace
it only after collecting a probe candidate and completing 200 ms plus a new
packet-timed round after draining. ProbeRTT can also reduce pacing before
startup reaches full bandwidth.

See the [QUIC BBR notes](https://github.com/LiuTangLei/quic-go/blob/v0.62.0-tailscale.3/BBR.md) and the
[BBRv3 draft revision 06](https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html).
The eight-phase ProbeBW cycle is retained. Full v3 inflight/bandwidth bounds,
loss-range startup exit and adaptive probing are outside this patch.

## Validation

All checks below passed against the final local source. The paired run covered
nine Tailscale packages, including the complete `tsnet` integration suite.

- QUIC fork: `GOTOOLCHAIN=go1.26.6 go test ./...`.
- QUIC focused race coverage: BBR sender/ACK handler, browser and standard
  handshakes, identity rejection, exporter, default HTTP/3 requests and reuse.
- Tailscale paired tests: `wgengine/wgtransport/...`, `wgengine/quicip`,
  `wgengine/transportprofile`, `wgengine`, `ipn/ipnlocal`, `tsnet`,
  `cmd/tailscale/cli`, and `net/tstun`.
- H3 race coverage includes actor rotation past 256 historical keys, retirement,
  pending CONNECT, revocation/re-addition and queued work.
- Linux/amd64 and Windows/amd64 Go builds cover the engine, H3 carrier, CLI and
  daemon. Cross-compilation is not device runtime verification.

The new in-process QUIC network regression uses both handshake profiles,
60 ms base RTT, separate 4 Mbps serialization in each direction and deterministic
1% short-header packet drops. It verifies exact contents of 8 MiB transfers in
both directions, then a 512 KiB reverse transfer after 12 seconds idle.
Bulk transfers run for more than 10 seconds of virtual time.

One comparison using the same harness and an overlay of the original BBR source:

| BBR source | Bulk goodput | Reverse after idle |
| --- | --- | --- |
| Original `1231045a` | 3.83–3.85 Mbps | 3.63–3.70 Mbps |
| Local tuning | 3.82 Mbps | 3.77–3.81 Mbps |

These samples show comparable bulk delivery in this particular simulated link,
not a general throughput improvement. The simulation has no competing flows,
finite queue/AQM model, real WAN variability, kernel TUN or inner TCP workload.
No new WAN throughput, browser-fingerprint equivalence or classifier-resistance
claim is made.

## 200 MiB follow-up

The subsequent long-transfer review found and fixed two additional BBR issues:
chunked writes could repeatedly mark a full startup pipe application-limited,
and an app-limited boundary ACK could skip the entire round's plateau check.
Startup now retains one check for a later unrestricted sample in that round,
and a valid 1.5-BDP full-pipe model prevents transient chunk boundaries from
continually extending the application-limited marker. Sparse traffic remains
protected. Pure ACKs also no longer debit the BBR pacer and starve flow-control
frames on a low-rate receiver.

Opt-in tests now cover 200 MiB QUIC streams with a finite bottleneck queue and
real file transfers over authenticated Chromium-profile H3 CONNECT-IP. In the
real local H3 test, with 20 Mbps / 60 ms imposed outside QUIC, original/final
forward throughput was 17.96/18.27 Mbps and reverse was 17.97/17.88 Mbps.
Reverse first-MiB time increased from 0.72 to 1.96 seconds. These results do not
establish a universal speed or ramp-up improvement; the retained v1 ProbeBW
cycle still limits how quickly a low-rate direction can discover more capacity.

## 200 Mbps / 4 GiB follow-up

The requested larger-file experiment used a 200 Mbps limit in each direction,
60 ms base RTT and a finite 6,000,000-byte FIFO. Each file contained 4 GiB
(4,294,967,296 bytes); original and final controllers each transferred it forward
and reverse, totaling 16 GiB. Files were written and then re-read for SHA-256;
all four matched. Checksum re-reading time is excluded from transfer timing.

| Direction | Original Mbps | Final Mbps | Original seconds | Final seconds |
| --- | ---: | ---: | ---: | ---: |
| Ordinary to declared server | 168.77 | 180.22 | 203.59 | 190.66 |
| Declared server to ordinary | 173.90 | 178.09 | 197.58 | 192.94 |

Forward first 10 MiB was 1.09 / 1.13 seconds and reverse was 0.94 / 2.78 seconds.
The reverse transfer reused the outer connection with different learned models;
this does not prove faster startup or a universal improvement. Each direction
has one paired sample. The shaper reported no queue drops or send errors;
QUIC still reported packet losses. Payload throughput differs from the outer
link cap because of encapsulation and acknowledgments.

This is an actual local UDP/magicsock and authenticated Chromium-profile H3
CONNECT-IP transfer with inner userspace TCP. It is not a WAN, kernel TUN,
competing-flow fairness or storage-durability benchmark. The release includes
portable results and per-10-second windows in `BENCHMARK-200MBPS-4GIB.json`.

## Published dependency and reproduction

The release pins published QUIC `v0.62.0-tailscale.3` (commit
`816406fe7b944af0a5d0ab75c303ffd762ff12c4`). Release validation uses the
checksum-verified public module, without a temporary modfile or source overlay:

```sh
GOTOOLCHAIN=go1.26.6 GOWORK=off go test -mod=readonly \
  ./wgengine/wgtransport/... ./wgengine/quicip ./wgengine/transportprofile \
  ./wgengine ./ipn/ipnlocal ./tsnet ./cmd/tailscale/cli ./net/tstun
TS_H3_BULK=1 TS_H3_BULK_SHAPE=1 TS_H3_BULK_MBPS=200 \
TS_H3_BULK_BYTES=4294967296 TS_H3_BULK_WARM_PROFILE=1 \
GOTOOLCHAIN=go1.26.6 GOWORK=off go test -mod=readonly ./tsnet \
  -run '^TestManagedH3BulkFile$' -count=1 -timeout=20m -v
```

The benchmark creates temporary files and local test nodes; it does not require
replacing a running daemon. Cross-platform binaries still require device testing.
