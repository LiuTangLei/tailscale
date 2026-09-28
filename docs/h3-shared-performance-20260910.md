# Shared H3 optimization validation — 2026-09-10

This is experimental source and finite test evidence, not a new release or a
claim of universal WG throughput parity. Test addresses, node keys and
application credentials are intentionally excluded.

## Shared implementation

The shared branch combines the existing Tailcat H3 library changes with the
Tailscale performance branch. Native WG/AWG remains the default. The IP engine
still uses CONNECT-IP DATAGRAM; Tailcat's explicitly enabled TCP API still uses
separate reliable CONNECT streams. TCP stream callbacks are not silently enabled
for the system TUN. Existing native/AWG configuration handling is unchanged.

Retained changes:

- Evict the oldest incomplete fragment under the existing eight-assembly limit,
  rather than reject all new fragments until the two-second lifetime expires.
- Send connection close while the underlying magicsock is still available.
- Copy the HTTP Datagram prefix and payload directly into one owned QUIC
  buffer, avoiding the intermediate full-payload allocation.
- Batch only already-ready protected datagrams when the adapter supports it.
  No wait-to-fill timer, packet padding, claimed kernel GSO/ECN/DF capability,
  or change to current peer/source authorization is introduced.
- Pool owned 32 KiB TCP write buffers. Write still copies accepted application
  bytes; framing completion/failure returns storage, and failure closes write
  admission before draining pending owned buffers. Two-entry queues, deadlines,
  half-close and acknowledgment draining are retained.

The BBRv3 implementation is available alongside the existing BBRv1-derived
controller. It is not made the default for the Tailscale IP path. Tailcat retains
its existing BBRv3 setting. Controller comparisons change no TUN/MTU/authentication
or session lifetime setting. IP sessions retain 120 s refresh and 180 s hard
expiry; reliable-stream sessions retain their documented independent lifecycle.

## Rejected optimization

An initial shared candidate also proactively formed variable-length vectors of
up to eight protected packets before returning to the receive loop. Two Tailcat
runs showed a repeatable reverse-direction regression: 160.26/163.15 Mbps single
stream and 173.98/170.06 Mbps with four streams. The surrounding baseline runs
were 331.96/317.78 and 313.87/341.98 Mbps respectively.

That proactive scheduling path was reverted. The final candidate retains only
opportunistic coalescing of packets already present in the send queue. The
failed performance trials remain in the local evidence; a functional report's
`ok: true` is not a throughput acceptance result.

## Tailcat final same-path A/B

Two Linux amd64 hosts, A as server and B as client. Both programs use reliable
H3 TCP streams and BBRv3. Both are diagnostic builds of the same Tailcat
application source; the baseline uses its previously pinned dependencies, while
the candidate uses the shared local modules. The order is baseline/candidate,
then candidate/baseline. Each iperf measurement is 12 seconds with two seconds
omitted at startup; loaded TCP echo probes run concurrently.

| Direction / streams | Baseline 1 / 2 Mbps | Final candidate 1 / 2 Mbps |
| --- | ---: | ---: |
| B → A / 1 | 316.82 / 307.16 | 403.60 / 367.89 |
| B → A / 4 | 245.83 / 358.99 | 415.96 / 353.03 |
| A → B / 1 | 280.75 / 318.44 | 253.48 / 257.06 |
| A → B / 4 | 261.19 / 266.06 | 269.93 / 245.72 |

B → A improves in this small sequential sample. A → B single-stream remains
slower; four-stream reverse throughput is approximately similar. This is not a
claim of all-direction speedup. Candidate loaded p95 ranges from 171.42 to
351.27 ms and does not uniformly beat the baseline.

Each run checks 25,691,136 bytes with SHA-256 through both directions,
concurrent transfers and idle recovery. All four final-comparison runs passed
and recorded no cleanup errors. Candidate server peak RSS samples were
79.6/71.6 MiB versus 104.4/98.9 MiB baseline. These are process observations at
these loads, not a universal memory reduction or normalized CPU result.

The write-storage microbenchmark on the local Apple M4 changed from 1829 ns/op,
32768 B/op, one allocation to 448.2 ns/op, zero measured allocations. This does
not imply a corresponding end-to-end speed multiplier.

## Tailscale kernel-IP comparison

A separate two-host Linux test uses an isolated real TUN, MTU 1280, kernel
iperf3, four TCP streams, three 15-second rounds in both directions and a
500 Mbps aggregate offered-load ceiling. No startup interval is omitted.
Standard WG here means the same fork's native WG data plane with AWG disabled,
not a separately downloaded pristine upstream executable.

The final conservative candidate used the existing BBRv1-derived controller:

| Direction | Native WG median Mbps | H3-IP median Mbps | H3 samples Mbps |
| --- | ---: | ---: | --- |
| C → D | 386.61 | 182.56 | 182.56, 207.35, 170.11 |
| D → C | 245.01 | 255.82 | 235.14, 284.82, 255.82 |

This does not meet all-direction WG parity. A sample spanning the scheduled
session refresh is retained rather than excluded. IPv4/IPv6 encrypted probes,
content verification and network rebind recovery passed, with no cleanup errors.

An earlier same-binary controller-only diagnostic comparison, before the
proactive vector revert, measured BBRv1 medians 198.17/261.73 Mbps and BBRv3
190.19/177.94 Mbps in the two directions. It did not justify changing the IP
mode's default controller; it is not substituted for the final-candidate table.

## Relay and regression scope

- Final Tailscale forced test-DERP: both IPv4 and IPv6, bidirectional content
  verification and rebind recovery passed. The declared-server browser profile
  was verified on the appropriate client connection. No WG data plane was used.
- Final Tailcat forced DERP: receiver throughput 23.03/23.70 Mbps in separate
  five-second measurements, 5,768,192 bytes SHA-256 checked, and actual UDP API
  payload echoes 60/60 across 64, 512 and 1200 bytes. This is not a sustained
  high-rate UDP loss certification.
- Shared QUIC short suite and selected race tests passed. Tailcat full ordinary
  and full serialized race suites passed with the shared dependency setup.
- Tailscale's 19 related packages passed. Actual CLI binaries passed automatic
  no-card H3/native restart cycles and legacy manual-profile migration checks.
- TCP framing/deadline/half-close/shutdown, pool failure cleanup, KCI, revocation,
  session lifetime and packet headroom regressions were exercised. Historical
  AWG2 → v3.1 → native round trips passed five race-instrumented repetitions.
- MSS fuzzing ran 198,075 executions in eight seconds without a failure.
- Linux arm64, Windows amd64/arm64, macOS amd64, Android arm64 and iOS arm64 core
  compilation passed, in addition to the executed Linux amd64 and macOS arm64
  builds. This is not signed application delivery or mobile runtime acceptance.

## Provenance and deployment

Measured Tailscale data-plane source: `717e161699d2310d92664f5be8695cd23699397c`.
The later `70fa4208b` adds only a pooled-write failure regression.
Final shared QUIC source: `cd7e74d71080a77e24e5786b8c6a66561c38a785`.
Tailcat candidate application source: `ad864d56380ff43ecaa25ccb55322c5598374f13`.
The application functionality is unchanged from `3947c4aa1`; later changes are
candidate builders and test tooling.

Final Linux test-engine SHA-256:
`66eb65c97d46ce71580f0a090d5fee2df13b7d9518b21d1e3ed61c504a509b2a`.
Final instrumented Linux Tailcat SHA-256:
`cafc7f2bf0c78431bd17f937440678eb97c68c0128690bee9846f6b7fb54c8d6`.

Candidate manifests explicitly identify local test-only module replacements.
QUIC's recorded dirty flag reflects pre-existing untracked Finder `.DS_Store`
files; tracked source was committed and unchanged during candidate builds.
No production binaries, login state, firewall, routes or system congestion
settings were changed. Final inspection found all four original production
processes still active with their original PIDs and zero service restarts.
No new dependency tag, public release assets or prerelease were published by
this validation. Publishing later requires fixed, downloadable dependency
versions followed by final-binary validation.
