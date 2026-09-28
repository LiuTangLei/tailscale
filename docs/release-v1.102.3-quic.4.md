# v1.102.3-quic.4 — 1.102.3-compatible H3 security and resource fixes

Experimental prerelease for multi-machine testing, still based on Tailscale
1.102.3. Native WG/AWG remains the default.

**Upgrade both CLI and daemon on every communicating automatic-mode H3 node.**
The new Noise IK v2 authentication intentionally rejects quic.3's older scheme;
there is no silent downgrade. Preserve existing node state and private keys.
Manual independently pinned profiles keep their existing authentication.

## Changes

- Replace static-static node proofs with channel-bound Noise IK and explicit
  encrypted confirmation in both directions. Fix the reproduced KCI weakness:
  possession of A's copied node private key no longer suffices to impersonate B
  to A in the tested cases. The server does not authorize a client from IK
  message 1 alone. Request target, TLS exporter, certificate SPKI, live policy,
  explicit pins and revocation generations remain enforced.
- Encrypt the initiating node identity and optional pin proof inside Noise.
  Reject unsupported process crypto policies as errors instead of panicking.
- Refresh active sessions with a complete new TLS/QUIC handshake after 120 s,
  retaining the old connection for a 3 s drain interval. Expire sessions at
  180 s if refresh fails; retry failed refreshes at bounded intervals. This
  provides fresh DH entropy rather than relying solely on QUIC Key Update.
- Retire actors after two minutes without IP traffic; keepalives do not prevent
  retirement. Bound provisional connections to 32 globally and four per source,
  with an eight-second post-TLS authentication deadline. Release these slots
  after authentication or close.
- Preserve 1.102.3's TUN/Bind APIs. H3 starts ordinary packet buffers at 2048
  bytes plus headroom, growing only when large IP/GSO packets require it.
  Preserve jumbo MSS segmentation, relay headroom and generation ownership.
  At batch 128, the IP pump's ordinary buffers use about 0.56 MiB instead of
  16 MiB; this is buffer geometry, not a measured whole-process RSS reduction.
- Send the existing 1.102.3 TSMP disco advertisement after authenticated session
  establishment using a bounded worker. Retain the original discovery events.
- Backport native WG AllowedIPs closure ownership/leak repair, SSSE3-only x86
  ChaCha20-Poly1305 acceleration, and iOS device queue budgets. AVX2 hardware
  keeps x/crypto's path; `TS_WG_ASM=0` remains the acceleration escape hatch.

## Scope intentionally retained

No upgrade to official Tailscale main, no migration to its new 128 KiB slab
interfaces, and no new per-peer PSK API. The magicsock bridge does not advertise
DF/GSO/ECN capabilities it cannot provide. Profile results did not justify
replacing live authorization locks with cached grants, so those checks remain.

The QUIC dependency and controller are unchanged from quic.3: a BBRv1-derived
implementation with selected v3 ideas, not full BBRv3. This prerelease does not
claim complete WireGuard security/feature parity or independent protocol audit.

## 200 Mbps / 4 GiB validation

Local userspace TCP over real H3 CONNECT-IP and QUIC DATAGRAM, 60 ms base RTT,
200 Mbps per direction, bounded 6,000,000-byte FIFO. Each run sends 4 GiB in each
direction; all file SHA-256 checks passed, including across session refreshes.

| Run | Ordinary → server | Server → ordinary |
| --- | ---: | ---: |
| Initial run with CPU profiling and concurrent validation | 181.24 Mbps | 144.38 Mbps |
| Separate repeat without CPU profiling | 179.03 Mbps | 177.50 Mbps |
| Previous quic.3 sample | 180.22 Mbps | 178.09 Mbps |

The separate repeat took 191.92 / 193.58 s. First 1 MiB took 0.77 / 0.71 s;
first 10 MiB took 1.21 / 2.80 s. Counters recorded successful fresh sessions and
no handshake errors, IP policy failures or carrier queue drops. Congestion-window
restart and inner TCP recovery still produce short dips; the 144 Mbps sample is
retained, not discarded as an established cause. These are individual local
samples, not proof of a speed increase, WAN throughput or competing-flow fairness.

## Verification and installation

Security, revocation, rotation, explicit pins, KCI in both TLS roles, replay,
provisional timeout, hard expiry, session handover, 300 historical idle actors,
large IP packets and jumbo GSO have regression coverage. Core/transport/TUN
race tests and three-node tsnet integration passed. Native WG tests passed on
macOS ARM; x86 assembly differential, tamper, dispatch, FIPS and reproducible
regeneration tests passed under Rosetta. Real old-x86 performance remains for
machine testing, including the upstream-documented AMD Bobcat regression.

Assets are standalone CLI/daemon pairs for Linux, macOS and Windows, amd64 and
arm64. Verify `SHA256SUMS`, replace both binaries using the existing service
manager, retain state/keys, and restart. macOS signatures are ad-hoc; these are
not notarized apps, signed MSI installers, APKs or IPAs. Cross-platform build
checks do not replace runtime testing on those systems.

After all communicating nodes are upgraded, existing automatic H3 profiles
continue using the new protocol. To select H3 on a native node:

```sh
tailscale awg transport --yes http3-ip
# Restart tailscaled using the existing service manager.
tailscale awg status --json
```

To revert, deliberately select `native` and restart. Transport choice remains
node-wide, not automatically negotiated per peer. No production machine was
upgraded as part of this release.

Published dependencies: `github.com/LiuTangLei/wireguard-go v0.0.32`,
`github.com/LiuTangLei/quic-go v0.62.0-tailscale.3` (replacement for quic-go),
and `github.com/flynn/noise v1.1.0`. Build assets use public checksum-verified
modules, with no local module replacement or development-only WG-over-QUIC tag.
