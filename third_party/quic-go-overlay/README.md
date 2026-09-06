# Pinned QUIC and HTTP/3 receive-queue build patches

Upstream: `github.com/quic-go/quic-go v0.62.0`, commit
`793f74d8e03368c5aded128af6f48d21dbb47f73` (MIT; license included).

Upstream `http3/state_tracking_stream.go` SHA-256:
`be09304f3946cb700489d150ffdd3a231ed05e674fa5bef240b54d2e48c014da`.

The stock HTTP Datagram stream queue holds only 32 datagrams and silently drops
new datagrams once full. A burst of ordinary GSO/GRO traffic can exceed this even
when QUIC itself successfully acknowledges the packets. For an IP tunnel the
inner TCP sees loss that QUIC's packet-loss counters do not describe.

The patch keeps the queue bounded at 256 datagrams, allocates its slots lazily,
uses a fixed ring, and clears each popped reference. It changes no QUIC or HTTP
wire format, congestion control, cryptography, or request authorization. Tests
cover capacity, FIFO order, wraparound and releasing popped payload references.

## Raw QUIC DATAGRAM reception

The connection-level DATAGRAM queue is upstream of HTTP/3 and originally holds
128 frames. During SG/J heavy-load testing, successful QUIC packet reception did
not imply delivery to the application; the old diagnostics could not report
this queue's drops. The second patch makes this queue a lazy fixed ring with
1024 slots AND a 2 MiB payload budget. It does not enlarge the 32-frame send
queue, disable pacing, retransmit unreliable payloads, or alter TLS/QUIC wire
behavior. Full-queue drops avoid allocation, and popped references are cleared.
`DatagramReceiveQueueStats` exposes queued packets/bytes and local drop count,
separately from QUIC network loss. These counters currently describe the active
connection, not cumulative losses across all prior connections.

Upstream `datagram_queue.go` SHA-256:
`0e743063200ab625b03bc416689b9783378656fdab23a913836acaa6eeb86ea0`.

Tests cover original queue behavior, receive capacity and byte limits, FIFO,
wraparound, non-retention, and zero allocations when dropping a full queue.
The queue patch is not a claim that sustained QUIC throughput is solved; compare
its real-host evidence against native and retain failed heavy-load runs.

## Building

`build_dist.sh` automatically prepares and applies this patch, along with the
`ts_http3_queue_overlay` tag. It refuses `ts_dev_wg_over_quic` builds.

For explicit builds or tests:

```sh
overlay=$(go run ./cmd/quic-overlay)
go test -modfile "$overlay.mod" -overlay "$overlay" \
  -tags ts_http3_queue_overlay ./wgengine/wgtransport/quicbind
# The same flags work with go build, GOOS/GOARCH, and mobile build wrappers.
rm -f "$overlay" "$overlay.mod" "$overlay.sum"
```

Go rejects overlays under its active GOMODCACHE. The preparer therefore downloads
the exact checksum-verified public module into a separate build cache and creates
an invocation-local alternate modfile. It changes neither the project's go.mod
nor the shared Go module cache. The overlay substitutes two source files
and adds corresponding upstream-package regression tests. Generated absolute paths
are never committed. Upgrading quic-go or changing its source checksum fails
closed until the patch is reviewed.

A regular `go build` without these flags still works with stock quic-go, and the
status explicitly reports queue capacity 32. Tagged distribution builds report
256. Setting the tag without the matching overlay fails compilation, rather than
falsely reporting an optimization. Library consumers / separate mobile build
roots must propagate the generated `-modfile`, `-overlay` and merged `-tags` flags;
a dependency's build invocation is not inherited automatically.

This is a reproducible experimental build patch, not an upstream-accepted change
or a blanket throughput guarantee. The bounded native QUIC receive queues,
network loss, congestion control and TUN/netstack scheduling remain relevant.
