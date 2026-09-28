# v1.102.4-r2: QUIC connection recovery and unified AWG switching

This revision retains upstream Tailscale 1.102.4 and all r1 AWG/QUIC selection
improvements. It fixes two independently reproduced QUIC-IP connection issues.
The user-facing mode remains **QUIC**; HTTP/3 is its existing implementation,
not another choice in the setup menu.

## Fixes

### Conservative initial packets for restricted paths

The managed transport factory used a 1400-byte QUIC Initial before the path
had demonstrated support for that size. Small discovery packets could arrive
while every oversized handshake packet was discarded. Managed QUIC now starts
with a 1200-byte UDP payload, and diagnostics expose the actual initial size.
This follows RFC 9000 section 14; it does not lower the inner IP MTU below 1280.
Large inner packets retain the existing authenticated fragmentation handling.

A real-transport regression models a link that silently drops UDP payloads
larger than 1200 bytes. The old 1400-byte configuration fails to authenticate;
the fixed configuration authenticates and delivers 32-, 1280-, 2048- and
16000-byte application payloads in both directions. Three race-instrumented
runs passed, including the expected failure of the old configuration.

### Do not discard early packets during simultaneous QUIC connections

Two peers can both finish an authenticated connection before they agree which
crossed dial should remain the primary connection. The old duplicate branch
closed the losing connection immediately, potentially discarding data already
sent by the other peer. This reproduced intermittent encrypted-TSMP timeouts
in forced-DERP simultaneous startup/restart tests. TCP payload checks were also
run independently because one lost unreliable ping is not proof of a sustained
TCP outage.

The primary connection selection is unchanged. For HTTP/3 IP transport only,
one authenticated losing connection may now drain during the existing bounded
overlap interval. It never replaces the primary sending session, is closed on
expiry/reset, and retains live peer authorization and generation checks.
Reliable-stream/Tailcat mode and raw legacy QUIC are unchanged. No WireGuard
fallback, extra public port requirement, or weaker authentication was added.

A deterministic regression failed before this fix and passes afterward: a
fully authenticated crossed connection delivers its early datagram, the
original primary stays active, and the losing connection closes on schedule.

## AWG and QUIC selection (inherited from r1)

- `tailscale awg set` offers AWG v3, AWG v2 and one QUIC option.
- `tailscale awg set --yes quic` stages QUIC and clears saved AWG settings;
  the legacy `transport --yes http3-ip` command remains accepted.
- Setting or syncing AWG while QUIC is running saves the selected profile
  and stages native mode together. The current QUIC engine does not consume
  those AWG parameters. Restart the daemon once to activate native AWG.
- Transport validation happens before preference writes. Failed AWG storage
  rolls back the staged transport where possible and reports errors.
- A selection is not a live engine switch. Check active mode, desired mode
  and pending restart; do not confuse control-plane online status with
  compatible data-plane modes on both endpoints.

## Validation

`go test -race ./wgengine/wgtransport/... ./wgengine/transportprofile` passed,
as did magicsock, engine and tsnet suites. After merging r1, the CLI, daemon,
IPN, LocalAPI and transport suites passed again.

Real isolated two-node tests passed QUIC -> AWG -> QUIC -> AWG with bidirectional
payload verification; set/sync from active QUIC and traffic before restart were
also checked.

`scripts/quic-nat-smoke.py` checks real application bytes and hashes, not just
online status. The fixed transport passed all 13 phases of the forced-DERP
run: simultaneous traffic, 65 seconds idle, individual socket rebinds, normal
peer restart, forced process loss in both key-order roles, and simultaneous
restart. After r1 integration, separate 10-phase runs passed with direct UDP
required and with DERP forced. The test disables router port mapping and uses
fresh temporary identities and state; no production VPN service is restarted.

These are local controlled-path tests, not a long-duration field acceptance
across every NAT, DERP server or country. They demonstrate the two specific
fixes, not a guarantee that every reported WAN instability has one of these
causes. They make no new throughput/latency parity claim. Mobile/router builds
are still released independently; install matching compatible CLI/daemon
builds on all participating desktop/server nodes.
