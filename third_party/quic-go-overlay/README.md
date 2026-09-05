# Pinned HTTP/3 receive-queue build patch

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
nor the shared Go module cache. The overlay is a single source-file substitution
plus an additional upstream-package regression test. Generated absolute paths
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
