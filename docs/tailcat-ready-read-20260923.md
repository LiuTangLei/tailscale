# Tailcat bounded ready reads (2026-09-23)

This change is on top of the verified 0df273162 H3 stream close fix. It does not
change QUIC packet protection, authentication, BBRv3, stream flow-control windows,
UDP semantics, or kernel settings.

The old stream read pump allocated a fresh 32 KiB slice for each underlying
HTTP/3 Read. A backend-owned cache now reuses these blocks with at most 64 idle
blocks (2 MiB). Blocks move exclusively from pump to the existing two-entry
queue to application Read, then are cleared before reuse. Partial reads and
application deadlines retain the current block. Data returned with EOF is
consumed before EOF is surfaced.

Read also copies any additional already-ready chunks into the caller's remaining
buffer. It never waits for another chunk after obtaining data. This is passive
coalescing, not an added timer or a request to delay interactive traffic.

Full Close keeps the earlier five-second/one-MiB graceful receive drain. Its
existing read pump releases queued storage on completion; no extra worker is
created. Explicit CloseRead still cancels immediately, joins the read pump and
reclaims pending storage. Publishing pump completion and checking close state
under the same mutex prevents the EOF/Close race from skipping reclamation.

The cache concept adapts the previously unshipped e533804d0 experiment, but its
old immediate full-close behavior is not imported. Unrelated endpoint-cache and
socket changes from that historical branch are not imported either.

Validation: full quicbind suite; targeted race tests repeated three times;
read-pool/coalescing tests repeated 20 times; go vet; complete Tailcat application
and CLI tests and serialized race tests against the candidate dependency.
Tests cover fixed cache bounds and clearing, partial read/deadline ownership,
coalescing without waiting, trailing EOF, full-queue concurrent CloseRead, and
100 interleaved EOF/graceful-close races per test invocation. Existing final-byte,
reset, revocation and graceful-close regressions remain active.

The local M4 allocation microbenchmark is diagnostic only: allocating a 32 KiB
slice measured about 1831 ns/op and 32792 B/op; a warmed cache with explicit
clearing measured about 270 ns/op and zero B/op. This is not a WAN throughput
claim. Actual application comparisons and their limitations are documented by
the consuming tailcat-quic release, using normal (uninstrumented) CLI binaries.
