# v1.102.5-r1: upstream 1.102.5, AWG and QUIC correctness fixes

This fork release updates the standalone CLI and daemon to the existing upstream 1.102.5 integration, retaining AWG and the lightly tuned BBRv3 QUIC transport. It includes two independently reproduced correctness repairs.

- Preserve TCP FIN and PSH on the last GSO segment when the first output buffer aliases the input. IPv4/IPv6 segment flags, sequence numbers, checksums and the application's TUN injection path are covered. This repairs the supported overlap contract; production incidence has not been established.
- A matching STUN reply now records successful sending for the probe's address family before publishing the report, including replies arriving before SendPacket returns and replies containing a mapped address of another family.

The WireGuard dependency is the published `github.com/LiuTangLei/wireguard-go v0.0.33`. The QUIC pin remains `github.com/LiuTangLei/quic-go v0.63.0-tailscale.1.0.20260929072415-cda3ed094749`. Release binaries use public checksum-verified modules, without local source replacements or overlays.

QUIC retains its original automatic thread policy, 1200-byte Initial, inner MTU and lightly tuned BBRv3. No experimental packet grouping, global GOMAXPROCS override, automatic Initial1400 promotion or new congestion-controller choice is included. The recent configuration/latency studies showed directional tradeoffs; this release makes no universal speed, latency or CPU reduction claim.

## Validation

Local race suites cover WireGuard connection/device/TUN and application netcheck, TUN, transport, magicsock, CLI and IPN. Actual Linux overlap and application integration checks passed on AU and US1420 (256 subcases). Published-dependency checks and normal-path real-host results are recorded in RELEASE-VALIDATION.json.

Assets are standalone CLI/daemon binaries for Linux, macOS and Windows on amd64 and arm64, with SHA256SUMS and a build manifest. macOS binaries have ad-hoc signatures; these are not notarized installers, mobile applications or router packages. Cross-built architectures are build-verified; actual host execution coverage is recorded separately. No production node is upgraded by publication.
