# v1.104.1 integration

This release merges upstream Tailscale v1.104.1 (`9a522a9786c97eb7910c01ccb7bd66557b04c910`) into the existing WG/AWG and authenticated HTTP/3 IP transport fork.

## Published dependencies

- `github.com/LiuTangLei/wireguard-go v0.0.34`, commit `63cef16b88aab8b23b843beac7ac6f553b7c5fd6`, synchronizes upstream `github.com/tailscale/wireguard-go v0.0.0-20260928213032-417aef361226`.
- `github.com/quic-go/quic-go v0.63.0` is replaced by the existing published `github.com/LiuTangLei/quic-go v0.63.0-tailscale.1.0.20260929072415-cda3ed094749`.
- Release builds use checksum-verified public modules, without local replacements or source overlays.

## Integration changes

The native WG engine, QUIC IP engine and magicsock bridge now consume the upstream shared-slab packet receive API. TUN and UDP packets retain their explicit offsets and required headroom. Queued QUIC data remains owned until copied into the caller's slab; peer authorization and source-IP checks still run before TUN injection.

WG peer synchronization includes upstream pre-shared-key configuration and allowed IPs. Transport session establishment uses the upstream priority-message API for discovery. Upstream DERP region identifiers and Linux TUN multiqueue changes are retained.

WG v0.0.34 preserves AWG wire formats and bounded Linux ready-record reads. AWG packets requiring additional prefix/padding space use separately owned buffers so encryption cannot overwrite an adjacent packet in a shared slab.

## Validation and packaging

Validation covers the WG race suite, native Linux TUN and device tests on two hosts, application transport/control race tests, CLI and SSH tests, real isolated node traffic and cross-platform builds. Release notes record the final WAN measurements separately; this source upgrade alone is not a claim of a universal QUIC throughput improvement.

`scripts/build-published-prerelease.py` builds and verifies CLI and daemon binaries for Linux, macOS and Windows on amd64 and arm64. These are standalone binaries, not GUI/mobile installers. `BUILD-MANIFEST.json` and `SHA256SUMS` identify source, dependencies and every binary. The release tag and title are both `v1.104.1`.
