# v1.102.3-quic.3 — H3 automatic identity and long-transfer BBR fixes

Experimental prerelease for multi-machine testing. Native WG/AWG remains the
default. Update both `tailscale` and `tailscaled` on communicating test nodes.

## Changes since quic.2

- Selecting HTTP/3 now enables automatic authentication using the current
  Tailnet/Headscale node identity; public identity-card exchange is unnecessary.
  Proofs bind both node keys, request target, fresh nonce, TLS exporter,
  certificate SPKI and server declaration. Live authorization, explicit pins
  when configured, source-IP and ACL checks remain enforced.
- Revoked peer actors can be reclaimed at the 256-actor limit. Pending CONNECT
  attempts have a 10-second deadline, including stream-credit waiting.
  Retirement cancels queued work and provisional connections; lifecycle guards
  prevent stale notifications or revoked sessions from returning.
- Fix BBR overflow on long ACK aggregation intervals, false application-limited
  STARTUP behavior, receiver flow-control starvation from ACK-only pacing, and
  high-gain probe handling after congestion. ECN-only events no longer inflate
  packet-loss counts.
- Apply selected BBRv3 startup, drain, idle and half-BDP RTT-probe ideas. This is
  still a **BBRv1-derived controller**, not a full v3 port; `bbr-v1` in status is
  expected. The eight-phase v1 bandwidth-probing cycle remains.
- Chromium-profile HTTP/3 supports the standard opportunistic `DialEarly` path
  by finishing a fresh handshake. Actual 0-RTT/resumption remain disabled;
  certificate-error causes are preserved. The profile remains Chromium-inspired,
  without a claim of matching a current browser fingerprint.

## 200 Mbps link, 4 GiB files

Actual local authenticated H3 CONNECT-IP / QUIC DATAGRAM transfers with inner
userspace TCP, 60 ms imposed base RTT, 200 Mbps per direction and a bounded
6,000,000-byte FIFO. One paired sample per version/direction; reverse reuses the
outer connection. All four 4 GiB files matched SHA-256 (16 GiB transferred).

| Direction | Original BBR | This release BBR | Change |
| --- | ---: | ---: | ---: |
| Ordinary to declared server | 168.77 Mbps | 180.22 Mbps | +6.78% |
| Declared server to ordinary | 173.90 Mbps | 178.09 Mbps | +2.41% |

Final file times were 190.66 and 192.94 seconds; payload speed was about
22.3–22.5 MB/s. This is a 200 Mbps link experiment, not a 200 MB/s result.
Reverse first 10 MiB took 2.78 seconds versus 0.94 before; this release does not
establish faster ramp-up in every direction. These local results do not predict
WAN throughput, competing-flow fairness or all-device behavior. See the attached
benchmark data for per-10-second windows and loss counters.

## Installing on test machines

Assets provide standalone CLI and daemon binaries for Linux, macOS and Windows,
each in amd64 and arm64. Download the matching `tailscale-*` and `tailscaled-*`
pair and verify `SHA256SUMS`. Use the existing installation/service manager to
replace both binaries and restart the daemon; retain the existing state and
keys. macOS binaries have ad-hoc signatures, not notarized application packaging.
Windows binaries are not a signed MSI or GUI bundle. No mobile APK/IPA is included.

After upgrading all communicating test nodes:

```sh
tailscale awg transport --yes http3-ip
# Restart tailscaled using the machine's existing service manager.
tailscale awg status --json
```

Confirm the desired and active modes are `http3-ip` with no pending restart.
Existing profiles do not silently change authentication on binary replacement;
explicitly selecting H3 enables automatic node-key trust. All communicating H3
nodes must use a compatible authentication scheme. Older quic.2 peers cannot use this automatic-trust scheme because that release
predates node-key proofs.

For a chosen server node, optionally run `tailscale awg server on`. Only an
ordinary node dialing an authenticated declared server selects the Chromium
profile. Initial discovery and ordinary/server-to-server connections use standard
TLS. Healthy connections are not restarted solely to change ClientHello.

Transport selection remains node-wide. Native WG/AWG and H3 are not negotiated
per peer; conflicting AWG profiles are reported, not cleared automatically.
To return to native, run `tailscale awg transport --yes native` and deliberately
restart the daemon. Private transport identity/state files must remain local.

## Dependencies and verification

- `github.com/LiuTangLei/wireguard-go v0.0.31`
- `github.com/quic-go/quic-go v0.62.0` replaced by the published,
  checksum-verified `github.com/LiuTangLei/quic-go v0.62.0-tailscale.3`.
- No local source replacement, module-cache patch, old QUIC overlay or
  development-only WG-over-QUIC build tag is used in release assets.

The verification attachment records tests and exact source/dependency hashes.
The complete QUIC suite, BBR/ACK race coverage and paired H3/transport tests
passed during review; release checks also run against the published module.
Six-platform compilation and binary metadata/signature checks are build evidence;
this prerelease is ready for the user's subsequent real-machine testing.
