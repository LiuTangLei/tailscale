# Single-core H3 TUN scheduling: dependency activation and WAN evidence

Date: 2026-09-22. Branch: `perf/h3-wan-profile-20260922`.

## Result

Retain the ready-record TUN implementation by pinning its existing public
commit into the ordinary dependency graph. This is an integration correction,
not a newly invented batching algorithm. The previously committed engine call
to `SetReadBatching(true)` was optional, and the selected `wireguard-go v0.0.32`
did not implement that method. The experiment existed on a separate branch;
the released dependency silently used the one-record reader.

The new dependency is the publicly resolvable immutable version
`github.com/LiuTangLei/wireguard-go v0.0.33-0.20260910045057-ed22747d204e`.
It was first tested in an isolated worktree, then verified content-identical
to that public commit and pinned in go.mod/go.sum. No local-path replacement is
needed for normal builds. QUIC stays at `v0.62.0-tailscale.4` and benchmark builds
use Go 1.26.6. Tailcat and the original dependency checkout were not modified.

The comparison baseline is `3c687937d`: it **already contains the earlier
1200-byte-path TCP MSS fix**. The speed difference below is incremental to
that fix, not a comparison against the older fragmented data path.

## Why it helps

After the MSS fix, profiling still showed single-core US sends using one IP
packet per H3 enqueue call. An initial suspicion about expensive single-packet
batch descriptors was ruled out: `RebindingUDPConn.WriteWireGuardBatchTo`
already has a direct UDP singleton path. No redundant singleton patch was
added.

The retained TUN implementation waits only for the first record, then drains
up to 32 already-ready ordinary virtio records within one netpoll read
operation. This avoids returning through the wrapper, IP pump and QUIC queue
for every individual record. The existing H3 batch enqueue and encrypted UDP
batch path can then operate on actual vectors.

This does NOT create a kernel multi-message TUN syscall: individual TUN
records still require reads. The reduction is in runtime/transport handoffs
and subsequent per-packet UDP send overhead. There is no batching timer,
intentional sleep to accumulate packets, busy-wait on an empty descriptor,
new unbounded queue, qdisc/sysctl change, or false DF/GSO capability claim.

A GSO record encountered after smaller records is retained intact in the
existing buffer for the next read with a full output vector. Valid records
preceding an error are returned before reporting the deferred error. The
native WG/AWG default reader remains opt-out; H3 requests this capability
before starting its reader. The 1200-byte Initial, MSS correction, interface
MTU, BBR-v1, TLS/Noise authentication and wire formats are unchanged.

## Matched throughput comparisons

All listed tests use isolated Linux network namespaces, actual TUN, kernel
TCP, H3/magicsock, node-key authentication, private origins, 1200-byte Initial,
10-second transfers, no omitted warmup and a 500 Mbps aggregate offered ceiling.
The lab queue remains 2048 packets for both baseline and candidate, unlike
the managed profile's 256. This work is not a production-installation test.

| Direction | Flows | Baseline Mbps | Candidate Mbps | Sampling |
| --- | ---: | ---: | ---: | --- |
| US to SG | 4 | 117.17 / 120.11 | 249.84 / 253.88 | two unprofiled samples each, no loaded RTT sampling |
| SG to US | 4 | 161.82 / 190.38 | 174.99 / 182.50 | same two-direction runs |
| US to AU | 4 | 113.29 | 230.31 | one unprofiled sample each, loaded RTT sampling enabled |
| AU to US | 4 | 196.50 | 222.29 | same run |
| US to AU | 1 | 85.82 | 101.22 | same run |
| AU to US | 1 | 122.36 | 117.78 | same run; slight decrease, not discarded |

The US-to-SG two-sample means are 118.64 and 251.86 Mbps, approximately 2.12x.
US-to-AU P4 is approximately 2.03x. Sequential WAN observations are not a
randomized simultaneous experiment, and small reverse/single-flow differences
must not be generalized. There is no claim that every direction improved.

In the first candidate US-to-SG sample, 295772 IP packets entered 12447 batch
calls (about 23.76 packets/call), versus approximately one per call before.
The second sample averaged about 22.34. Fragmentation and the recorded
send/receive/raw queue-drop deltas remained zero in those samples.

## Final pinned-source confirmation

After adding an actual-device diagnostic flag, the final standard dependency
build was run for three samples per direction, with loaded RTT sampling:

| Direction | Round 1 | Round 2 | Round 3 | Median Mbps |
| --- | ---: | ---: | ---: | ---: |
| US to SG | 244.08 | 247.45 | 228.13 | 244.08 |
| SG to US | 186.66 | 179.16 | 164.82 | 179.16 |

Both nodes reported `tun_ready_read_batching=true`. This flag records that the
actual device accepted the opt-in, rather than assuming it from the presence
of an optional method call. It is in PacketTransportDiagnostics/the lab's
existing diagnostic endpoint, not a newly implemented `awg doctor` CLI mode.

All six final samples had zero deltas in `fragmented_packets`, `send_drops`,
`receive_drops`, `raw_drops` and `quic_receive_queue_drops`. This does not mean
that the WAN had zero loss: 1 of 180 loaded TSMP probes did not respond. The
last SG-to-US sample had connection counters increase from 2 to 3 on both
ends, with handshake-error counters still zero. It completed, but is not a
same-session steady-state sample. The configured refresh interval is 120 s;
without a retained causal event log, do not assert that refresh was the only
possible cause of the counter transition.

Every completed test also performed verified 1 MiB transfers in both
application directions from each node and authenticated rebind recovery.
No current all-direction WG-parity claim or long-duration acceptance follows.

## CPU and latency

Diagnostic-only CPU-profile runs, US-to-SG P4:

| Metric | Baseline | Candidate |
| --- | ---: | ---: |
| Receiver throughput (profiling affected) | 112.35 Mbps | 222.22 Mbps |
| US process CPU-time delta | 7.218 s | 5.414 s |
| Flat syscall CPU samples | 2.11 s / 43.60% | 1.09 s / 28.99% |

CPU-time deltas include the bounded metric collection interval. Profile sample
percentages are not syscall counts; no strace syscall-count comparison was
performed. Do not derive universal CPU limits from these short samples.

At the same **100 Mbps offered load**, AU/US P4:

| Direction | Baseline received | Candidate received | Baseline loaded p95 | Candidate loaded p95 |
| --- | ---: | ---: | ---: | ---: |
| US to AU | 97.54 Mbps | 98.12 Mbps | 187.20 ms | 189.83 ms |
| AU to US | 100.21 Mbps | 99.72 Mbps | 182.88 ms | 178.74 ms |

US sender CPU time fell from 5.256 to 3.041 seconds (about 42%). All 30 probes
per direction/run completed in this capped comparison. These small samples
show broadly similar p95, not a proof of equal latency at every percentile.

With a 500 Mbps ceiling, US-to-AU candidate throughput approximately doubled
but loaded p95 increased from 195.59 to 255.43 ms. This tradeoff is retained in
the report, not hidden by the capped test. The actual delivered load differs,
so it does not isolate a scheduling-latency regression. Final US-to-SG loaded
p95 ranged 207.51–248.35 ms. There is no claim of zero added tail latency or
zero packet loss.

## Validation and delivery

- Linux ready-read tests were executed on the actual single-core host and
  repeated 20 times: bounds/ownership, no wait-to-fill, small vectors, GSO
  retention across opt-out, deferred/async errors and close unblocking.
- Full local suites passed for wgengine, quicip, transportprofile, wgtransport,
  nodeauth, quicbind and net/tstun. Linux-only tests are not counted as having
  run on macOS.
- Focused race checks passed for quicbind and net/tstun, and the complete
  quicip race suite passed. Formatting, diff and Python syntax checks passed.
  go vet passed on the affected engine paths.
- macOS-arm64 and Linux-amd64 test lab and daemon builds completed with the
  public pinned dependency. No development dependency path is required.

The bounded test helper can now measure 30 authenticated TSMP RTTs during a
kernel transfer and records whether the sampling interval fits inside the
client-command window. It does not relabel successful byte transfer as a
latency acceptance pass. Build metadata now records selected dependency
versions and permits retaining published QUIC while testing only a TUN fork.

All production daemons retained their original PIDs and modes: AU/US native
AWG, SG H3 with server declaration off. No release, push, production daemon
restart, firewall, route or system tuning was performed. Test namespaces,
listeners, temporary directories and the separately uploaded unit-test binary
were cleaned up. An unrelated September-6 SG namespace was left untouched.
SG's remaining disk space was about 556 MiB at final inspection; this work did
not clean unrelated service data.

## Raw evidence

Private artifacts live at `<tailscale-all>/audits/h3-singlecore-20260922/`:

- `baseline-sg-us-profile.json`, `pinned-sg-us-profile.json` and CPU profiles.
- `ready32-sg-us.json`, `baseline-sg-us-unprofiled.json`: first matched pair.
- `pinned-au-us-loaded.json`, `baseline-au-us-loaded-retry.json`: P1/P4 pair.
- `baseline-au-us-100m.json`, `pinned-au-us-100m.json`: equal offered-load pair.
- `final-sg-us-loaded.json`: three-round final diagnostic build.
- `final/build.json`: source, selected modules and binary hashes.

Two initial setup failures are also retained: an AU archive-upload timeout
(`baseline-au-us-profile.json`) and an SSH banner timeout
(`baseline-au-us-loaded.json`). They contain no accepted throughput samples.
The first failed automatic cleanup after the SSH control connection stalled;
its exact owned AU namespace and partial upload directory were subsequently
removed through a fresh ordinary management connection. No production state
was altered. AU management later used SG as an SSH jump; test data continued
to use the same direct public AU/US path in both compared runs.
