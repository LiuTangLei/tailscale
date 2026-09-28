# v1.102.4-r1: one-step AWG / QUIC selection

This is a fork revision on the existing upstream 1.102.4 base, not an upstream
1.102.5 release. The previous v1.102.4 tag and assets remain unchanged. Upgrade
both CLI and daemon together; the new coordinated selection requires both.

## User interface

`tailscale awg set` offers AWG v3, AWG v2 and QUIC. QUIC uses the existing
HTTP/3-obfuscated native-IP implementation, not a separate raw-QUIC choice.
Human-readable mode labels use QUIC; the stored and JSON API `http3-ip` value
and the old `transport --yes http3-ip` command remain compatible.

- `tailscale awg set --yes quic` saves QUIC mode, enables automatic node-key
  authentication and clears the saved AWG profile after validation.
- Selecting/generating an AWG profile, supplying AWG JSON, or confirming
  `tailscale awg sync` while QUIC is running saves that profile and stages
  native mode in one operation. No manual native/restart/set sequence is needed.
- Restart the daemon once to activate the selected engine. Saving AWG for a
  native start does not inject AWG parameters into the still-running QUIC
  connection. Status distinguishes active mode, next mode and pending restart.
- Cancellation/EOF before confirmation does not change the configuration.
  `--yes` stages without an automatic restart. Environment/embedding overrides
  are not silently edited; remove them in their deployment configuration.

Choosing QUIC can interrupt an existing native AWG connection because its
stored AWG parameters are cleared. Retain an independent administration path.
All communicating nodes still need compatible active modes/profiles; this is
not concurrent per-peer native/QUIC fallback.

## Implementation and failure handling

The daemon's coordinated `awg` action validates the AWG profile, checks the
transport revision and ownership, stages native mode, and persists AWG before
updating in-memory preferences. A transport-save error does not change AWG; an
AWG-store error restores the previous transport selection and reports failure.
The two stores are not claimed to be one crash-atomic database transaction.

The packet engine only consumes AWG in native mode. Set/sync share the same
client operation; the LocalAPI sync endpoint also stages native when needed.
Embedded tsnet startup preserves the separately managed AWG profile instead
of overwriting it with new default preferences.

The lab's default standard profile previously reset AWG at startup. The CLI
acceptance test now uses explicit `--profile keep`, checks the saved AWG flag
after every restart, and verifies actual application traffic with nonstandard
AWG packet headers. This prevents ordinary WireGuard traffic from being
mistaken for successful AWG acceptance.

## Verification

- CLI, IPN/backend, LocalAPI and transport-profile package tests pass.
- Targeted race tests cover selection, cancellation, revision conflicts,
  state-store rollback and pending AWG isolation from a running QUIC engine.
- Two real isolated nodes complete QUIC / AWG / QUIC / AWG transitions and
  bidirectional application transfers. QUIC still carries data after staging
  AWG but before restart.
- The exact interactive sync path (select peer, confirm configuration) passes
  from a running QUIC receiver to a native AWG peer. One restart activates AWG
  and bidirectional payload checks pass.
- Real containerboot with Linux kernel TUN passes environment login, v2/v3
  disk persistence, reset, QUIC identity persistence, and v2/v3 / QUIC round trips.
- Test placeholder auth strings no longer use real Tailscale credential
  prefixes. No real credentials were involved; historical scanning alerts are
  not automatically closed by changing the current source.

No production VPN service is replaced by these tests. This revision does not
change the QUIC dependency, cryptographic protocol or congestion-controller
defaults, and does not make a new WAN throughput/latency claim.
