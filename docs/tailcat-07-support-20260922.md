# Shared H3 support for Tailcat 0.7

This source branch extends the verified `1581b88a0` QUIC-0.63 integration. It
keeps the original shared repository; no new Tailscale/Tailcat mirror is used.
It is a library change for Tailcat, not an installed VPN release.

The existing MSS negotiation, bounded DATAGRAM batch/direct-receive APIs and
Linux opt-in ready-record TUN reader remain. Tailcat's TCP forwards use real
reliable H3 streams, so the kernel-TUN speed measurements must not be presented
as Tailcat speed results. Tailcat measures its own application separately.

## Upstream compatibility backports

- Official `86b3cd5aa1a853e4fccdd98088f2d4dcf6e92d68`: standalone Android DNS.
- Official `60d9c54b6b3526bd991e3da911a471a28131164c`: Android system CA roots
  and netmon interface fallback. Both commits retain their original authors.
- Selected netstack portion of official
  `3ec674bc866559daadbb2c636975c0d7eba62834`: default RACK recovery and CUBIC,
  paired with `gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72` and the
  500-microsecond Windows clock-resolution setting. This is not a merge of
  the entire September 16 Tailscale main branch. Per-destination queue work
  and unrelated VPN features from that branch are not claimed here.

Go 1.27.1 is used, as in upstream Tailcat 0.7. Go regenerated the module graph
for the new gVisor version. The shared QUIC replacement remains the published
`v0.63.0-tailscale.1`; the WG/TUN dependency remains `ed22747d204e`.

## Listener ownership

The H3 TCP connection now exposes a receive-only `Done()` channel, closed by
full connection/session shutdown. A Tailcat listener adapter can hand ownership
to `Accept` and retain the callback lifetime until the accepted stream closes.
Returning directly from the old callback would trigger the backend's deferred
Close and prematurely close the newly accepted connection. This change adds no
payload framing, authentication exception or unbounded queue.

## Verification

Netstack and network-monitor short tests, the H3 transport suite, targeted
stream/lifetime/netstack race tests, and vet passed on macOS. Android DNS and
runtime support tests were cross-compiled and executed successfully on Linux
amd64. These are unit tests, not a claim of testing a physical Android device.
The Tailcat consumer verifies real H3 TCP/UDP listener precedence, accepted
connection lifetime, and server shutdown. Publication is a versioned source
pin; separate application performance and packaged-client checks gate release.
