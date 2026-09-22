# H3 fixed-packet-path performance investigation — 2026-09-22

## Outcome and scope

A retained MSS-negotiation change removes steady-state TCP fragmentation on the
1200-byte magicsock path. It does **not** establish all-direction 95% WireGuard
parity. Single-vCPU sending and variable WAN behavior remain material limits.
A separate single-core actor-queue experiment was slower and was reverted.

Work is based on deployed release `v1.102.4`, commit
`1f00235ed2ceaa2231755a2d2d3677c2d42438c6`, in branch
`perf/h3-wan-profile-20260922`. The published QUIC dependency remains
`v0.62.0-tailscale.4`; go.mod/go.sum were not changed. This is deliberately not
an implicit merge into the later Tailcat-isolation branch. Tailcat was not
modified. The candidate is test-only: no release, push, or production installation.

## Measured cause

The managed release starts QUIC with a 1200-byte UDP payload to avoid the
previous handshake MTU black hole. The historical remote benchmark instead
hardcoded 1400. The magicsock PacketConn does not claim DF support; quic-go
therefore does not enable its DF-dependent path-MTU discovery for this adapter.
A 1280-byte inner IP packet consequently does not fit the fixed outer path.

The deployed-source AU/US diagnostic run used P4 kernel TCP, 15 seconds per
direction, 1200-byte Initial, and CPU profiling. It measured approximately
139.58 Mbps US-to-AU and 136.05 Mbps AU-to-US. These are **profiling-affected**
samples, not unprofiled acceptance baselines.

| Sending node / direction | IP packets sent | IP packets fragmented | Packets using IP batch API |
| --- | ---: | ---: | ---: |
| US to AU | 221268 | 221155 | 113 |
| AU to US | 221845 | 221820 | 20 |

The corresponding send, receive, raw and QUIC receive-queue drop deltas were
zero. Both measured sessions were reused. This excludes those queue-drop
counters as the explanation for these particular samples; it does not exclude
network loss or other uninstrumented work.

The oversized-packet path rejects the ready batch before accepting any entry,
falls back to individual datagrams and fragments the IP packet. Fragmented
receive traffic cannot use the raw-IP direct receive path. This creates extra
packets, system calls, allocations, scheduling and reassembly work. Loss of a
fragment also prevents delivery of its whole IP packet.

CPU profiles put the flat syscall node at approximately 30–40% of samples.
The individual AES-GCM encrypt/decrypt hot functions were approximately
0.7–1.7%, not a dominant cost. On US sending, the UDP batch-write call chain
accounted for about one third of cumulative samples. Do not add percentages
across overlapping cumulative call stacks or infer that all remaining cost is
cryptography. US has one vCPU; AU and SG have two.

## Retained implementation

For H3 native-IP over magicsock, negotiate TCP MSS against the configured
fixed QUIC packet budget. The conservative 64-byte outer overhead allowance
covers the QUIC short header, AEAD tag, DATAGRAM frame, H3 stream association
and IP context. With the managed 1200-byte setting, the caps are 1096 for
ordinary IPv4/TCP and 1076 for ordinary IPv6/TCP.

Only an existing MSS option in a validated complete SYN or SYN-ACK is lowered.
The existing incremental checksum implementation is retained. A lower MSS is
never increased. Unsupported extension/fragment headers and malformed options
are not rewritten. Borrowed caller buffers are unchanged: rewriting occurs in
the carrier's owned scratch copy.

A batch containing a SYN takes the scratch-copy path **before any prefix has
been accepted**, preventing duplicate sends on fallback. Ordinary data keeps
the existing batch API. The carrier diagnostics add `tcp_mss_clamps`,
`tcp_mss_limit_ipv4` and `tcp_mss_limit_ipv6`; these are available through the
existing diagnostic snapshot/lab endpoint, not a newly added production CLI
command.

The interface MTU stays 1280 and the Initial stays 1200. Large UDP/IP payloads
retain the existing negotiated fragmentation path. There is no new timer,
unbounded queue, claimed DF/GSO capability, encryption relaxation, peer-trust
change, congestion-controller change, or wire-format change. Raw QUIC/UDP-mode
and embedded reliable-stream policies are unchanged. Existing TCP connections
need a new handshake to negotiate the smaller MSS; the change does not rewrite
already established flows.

In the first candidate AU/US kernel samples, steady-state data fragmentation
fell to zero, while each endpoint recorded five MSS clamps for the iperf
control connection and four data flows. AU's sender could again form roughly
eight-packet batches. US's single-core producer still mostly supplied one
packet per call.

## WAN results

Final retained-candidate measurements use isolated Linux network namespaces,
real TUN, kernel TCP, four flows, 10 seconds per sample, three samples per
direction, 500 Mbps aggregate offered ceiling and no omitted warmup. Both
nodes use H3 magicsock, node-key authentication, private origins, 1200-byte
Initial and BBR-v1. Each completed H3 run also checks verified 1 MiB upload and
download on each node, an authenticated rebind recovery and small idle-RTT
samples. Those checks are not a long-duration production or loaded-p99 test.

| Direction | Candidate rounds, Mbps | Candidate median | Native WG reference median | WG reference sample basis |
| --- | --- | ---: | ---: | --- |
| AU to US | 213.97 / 209.84 / 197.28 | 209.84 | 205.47 | 3 x 12 s; completed WG phase in interrupted combined run |
| US to AU | 144.23 / 139.68 / 138.03 | 139.68 | 224.60 | 3 x 12 s; completed WG phase in interrupted combined run |
| AU to SG | 283.03 / 338.88 / 264.94 | 283.03 | 399.15 | 3 x 10 s; completed independent WG run |
| SG to AU | 224.34 / 222.84 / 224.07 | 224.07 | 233.46 | 3 x 10 s; completed independent WG run |
| US to SG | 132.24 / 133.24 / 132.61 | 132.61 | 266.53 | 2 x 10 s; completed WG phase in interrupted combined run |
| SG to US | 175.57 / 121.76 / 151.34 | 151.34 | 180.03 | 2 x 10 s; completed WG phase in interrupted combined run |

WG here means this fork's standard native WireGuard mode with AWG disabled,
not a separately downloaded untouched upstream executable. Reference runs were
sequential, not simultaneous or a randomized interleaved experiment. The lab
uses a 2048-packet configured queue versus the managed profile's 256; retained
candidate and diagnostic baseline use the same lab setting. Production
conclusions must not silently ignore that distinction.

On the matching AU/SG 3 x 10-second comparison, SG-to-AU reaches about 96% of
WG, while AU-to-SG is about 71%. Different durations/sample counts elsewhere
are reference comparisons, not formal parity passes. Overall 95% acceptance
is **not passed**. One direction being at/above a reference does not compensate
for another being below it.

The earlier five-second production measurements had lower WG baselines too.
For example, old AU-to-SG H3 was around 137 Mbps, but comparing that directly
to the new 283 Mbps median does not isolate code from path/time effects. The
old SG-to-US 2.31 Mbps sample must not be used as a denominator for a claimed
performance multiplier. The final SG-to-US range remains 121.76–175.57 Mbps.

## Rejected experiment and open limits

A single-core-only change redirected one-packet carrier sends through the
existing bounded actor queue, without a timer. Its local ownership/batching
checks passed, but WAN batching was still about 1.02–1.1 packets per call and
US-to-AU measured 139.61 / 138.42 / 135.10 Mbps. It added work without a useful
speed gain. All corresponding runtime and test changes were reverted; the
`candidate2` binaries/reports are historical rejected artifacts, not the
retained build.

Next optimization should target the actual single-core TUN-to-QUIC-to-UDP
send cadence and syscall cost rather than increasing queues or weakening
cryptography. Any adapter batching/offload work must preserve packet ownership,
NAT/relay behavior, authentication and congestion/pacing constraints. Real UDP
throughput, loaded tail latency, diverse NAT paths and sustained refresh cycles
remain separate acceptance work. This TCP MSS fix does not prove improvements
for large UDP packets and does not enable true path-MTU discovery.

## Verification

The retained final tree passed:

- Full suites for quicbind, quicip and transportprofile.
- Targeted race checks for MSS, batch integrity, queues, authentication,
  revocation/retirement, lifetime and MTU-blackhole-related cases.
- `FuzzH3FixedPathSYNFilter`, 5 seconds with two workers, 125131 executions.
- `go vet` for quicbind, Go formatting/diff checks and benchmark Python syntax.
- Linux-amd64 builds of the test lab and tailscaled (not installed).

The real-H3 MSS regression covers both directions, IPv4/IPv6, SYN/SYN-ACK,
even/odd MSS alignment, checksum validity, no mutation of borrowed memory,
pre-acceptance batch fallback, already-small offers, retained fast-path data
and 4096-byte fragmented delivery. Existing malformed-input tests remain.

## Evidence and interruptions

Private raw artifacts are in the Mac audit directory `audits/h3-perf-20260922`
under the tailscale-all project root. They must not be committed to a public
repository: they contain infrastructure diagnostics and test identities.

| File | Interpretation |
| --- | --- |
| baseline-sg-us-1200-profile.json | Failed initial 1 MiB integrity probe with HTTP 502; no throughput acceptance; cleanup completed |
| baseline-au-us-1200-profile.json and four .cpu.prof files | Completed baseline diagnostics; throughput affected by CPU profiling |
| candidate-au-us.json | Interrupted combined run; WG phase completed, H3 phase incomplete |
| candidate2-au-us.json | Completed experiment, code rejected and reverted |
| candidate-sg-us.json | Interrupted combined run; WG phase completed, H3 phase incomplete |
| final-au-us.json | Completed retained-candidate 3-round H3 run |
| final-sg-us.json | Completed retained-candidate 3-round H3 run |
| final-au-sg.json | Completed retained-candidate 3-round H3 run |
| wg-au-sg.json | Completed 3-round standard native WG reference |

Two combined harness invocations exceeded the tool's execution lifetime. Their
JSON files correctly remain incomplete and must not be relabeled successful.
Their exact owned transient services and namespaces were stopped/deleted
manually; the four corresponding temporary directories were subsequently
removed after checking that their namespaces and services were inactive.
An attempted additional read-only loss/qdisc aggregation was blocked by the
tool; it was not repeated or worked around, and no results from it are claimed.

Final readback confirmed all three production daemons still active, their
before/after PIDs unchanged, no pending transport restart, AU/US still using
AWG and SG still using H3 with server declaration off. This work did not reset
production nodes or change their routes/firewall. The old SG namespace from
September 6 is unrelated and was deliberately left untouched.

Build SHA-256:

- Baseline lab: `60535fd5063840f9a2b8ab94a206bccca827dceb2823a1b92987fb1c97e095d9`
- Retained candidate lab: `b60655cdce38d42a3763cb950033a6de3ba82de5ed4a96776571b258045275ae`
- Retained candidate tailscaled: `e25d19a71d26819168f57980db386fbe1ec51c728ff472fc17c6e06f3d44e88b`
