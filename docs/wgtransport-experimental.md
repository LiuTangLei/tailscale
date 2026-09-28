# WG/AWG transport compatibility — experimental verification

Date: 2026-09-05. Branch: `experimental/transport-compat-1.102.3-20260905`.

## Result

The native carrier integration passed genuine, two-host Tailscale-engine tests for standard WireGuard, AWG 2, AWG 3 and AWG 3.1. Standard WireGuard and AWG 3.1 also passed with direct UDP disabled and all peer traffic forced through an isolated DERP server.

This is the compatibility-layer milestone. **QUIC-WG is not implemented.** Choosing `quic` without an injected compiled provider fails explicitly instead of silently transmitting native WG.

The protocol and ownership design is documented in `wgengine/wgtransport/README.md`.

## Reproducible source baseline

| Component | Reference |
| --- | --- |
| Official Tailscale base | `v1.102.3`, `53a0d659afa51835dd7a9283873cca44261454f8` |
| Existing user Tailscale/AWG integration | `e8bda54e7164160841a991659cc4d9d2c97bd23f` |
| Latest AWG tag checked for this work | `v3.1.20260828`, `b5928efb6ca19f0153958460c3d141f04abc5c2e` |
| Updated Tailscale-compatible WG fork | `8835972ec5d8acec8e028af84261fc5be3be6648` |
| Pinned Go module | `github.com/LiuTangLei/wireguard-go v0.0.31-0.20260905021413-8835972ec5d8` |

The latest AWG padding-window semantics were already present in the fork. The missing underload/DisableCookies behavior was ported and independently tested. No local-module replacement is required to build the experimental branch.

## What was changed

`wgengine/wgtransport` provides explicit carrier selection, a compiled factory extension, lifecycle notifications and endpoint helpers. Native mode preserves the original magicsock Bind object. `wgengine/userspace.go` constructs this adapter without moving control-plane, routing, ACL, WireGuard crypto or peer lookup logic into a new engine.

AWG 3.1 `RandomTrailers` and `DisableCookies` are represented in preferences, JSON import/export, CLI display and UAPI configuration. Both default to false. Profile reset explicitly writes false so a running device cannot retain stale flags. The AWG config exchange now advertises capability level 4 for these fields; older v3 clients are not sent a profile whose new flags they would silently ignore. Existing v2/v3 formats remain supported.

Unknown magicsock endpoint implementations now fail with `conn.ErrWrongEndpointType` instead of a success return with no packet transmission.

## Two-host acceptance matrix

Each successful directional probe requires a real encrypted TSMP response, an exact-byte-verified 1 MiB HTTP download and a SHA-256-verified 1 MiB upload through `tsnet.Dial`. A successful disco ping by itself never passes the test. Both directions are exercised, with nonzero WG peer transmit/receive counters checked.

| Inner profile | Direct UDP, both directions | Forced DERP, both directions |
| --- | --- | --- |
| Standard WG | PASS | PASS |
| AWG 2 | PASS | Not separately required/run in the final DERP matrix |
| AWG 3 | PASS | Not separately required/run in the final DERP matrix |
| AWG 3.1 | PASS | PASS |

AWG 3.1 additionally passed two consecutive stop/start rounds with both directional probes. These measurements are connectivity/integrity checks, not a throughput benchmark or long-duration soak test.

A profile change to standard was applied before stopping each phase. Detailed reset semantics are asserted separately by the UAPI tests; the matrix above describes the startup-configured profiles, not an uninterrupted zero-loss live migration guarantee.

### Isolation and access

Tests ran on the two requested Linux/amd64 hosts. The second host's public hostname did not resolve; its existing Tailscale address was used for SSH after checking the remote hostname. No production node credentials were copied into the test environment.

The tests use separate userspace `tsnet` nodes with dedicated state directories, UDP ports and loopback-only administrative endpoints. Production `tailscaled`, its binaries, state, firewall, routes and DNS are not replaced. Temporary systemd units have hard runtime limits, and the runner stops/removes only its own units/directories.

Control and the test DERP are bound to Mac loopback and reached through private SSH forwarding. Public Tailscale STUN servers provide real UDP address/probe information; they are marked STUN-only and do not become relay destinations. The test DERP's self-signed TLS exception is confined to the loopback test map. The forced-DERP results therefore verify the engine's relay path, not the performance or availability of a public DERP deployment.

The existing service on the first host was already restart-looping on version 1.92.3 before testing. It was left untouched. The second host's existing 1.102.3 daemon retained its running process during the tests. Production service remediation is not part of this experiment.

### An initial test-fixture failure and its correction

The initial isolated map lacked usable STUN probes. Nodes either remained in Starting without a live relay or repeatedly reported IPv4CanSend=false and rebound UDP. One early AWG 3.1 reverse probe timed out in that environment. The test fixture was corrected to provide a live private DERP plus real STUN probes; the complete direct matrix, consecutive AWG 3.1 restarts and forced-relay cases then passed. This was not papered over with a successful disco-only result or by downgrading the AWG profile.

## Reproduction

Build from this branch using its pinned module dependencies:

```sh
go test -mod=readonly ./wgengine/wgtransport ./wgengine/wgcfg \
  ./wgengine/magicsock ./wgengine ./ipn ./disco \
  ./cmd/tailscale/cli ./cmd/wgcompat-lab

go build -mod=readonly -trimpath -ldflags='-s -w' \
  -o /path/to/artifacts/wgcompat-lab-local ./cmd/wgcompat-lab
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=readonly \
  -trimpath -ldflags='-s -w' \
  -o /path/to/artifacts/wgcompat-lab-linux-amd64 ./cmd/wgcompat-lab

python3 scripts/wgcompat-remote.py \
  --local-binary /path/to/artifacts/wgcompat-lab-local \
  --linux-binary /path/to/artifacts/wgcompat-lab-linux-amd64 \
  --sg root@SG_HOST --zjg root@ZJG_HOST \
  --profiles standard,awg2,awg3,awg31 \
  --output /path/to/artifacts/direct-results.json
```

Run a separate invocation with `--profiles standard,awg31 --force-derp` for the relay matrix. The runner intentionally verifies the two authorized hostnames before making temporary changes; adapt that explicit allowlist only for other hosts you own. It needs SSH/scp, remote systemd, curl, gzip and free test ports. It gzip-compresses build artifacts for transfer and writes a JSON report even when a test fails.

The user's local build/report directory for this work is:

```
/Users/lei/code/tailscale-all/artifacts/transport-compat-20260905/
```

`direct-final.json`, `derp-final.json` and `awg31-retest.json` record binary SHA-256, path observations, payload hashes, WG counters, test times, cleanup errors, and before/after production service observations. A passing report requires top-level `passed: true` and an empty `cleanup_errors` list. Failed preliminary reports are retained locally for diagnosis rather than rewritten as successes.

## Remaining limits

No actual QUIC/MASQUE implementation, capability negotiation for outer carriers, per-peer AWG profile support, authenticated QUIC identity binding, MTU fragmentation, direct/DERP carrier bypass, mobile handover or long-running soak test is claimed. The native real-host tests do not certify those future features. Full installation over the production daemons was intentionally not performed.
