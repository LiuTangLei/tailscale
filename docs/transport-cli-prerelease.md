# Native WG/AWG and QUIC transport CLI (experimental)

`tailscale awg` is the interactive entry point when stdin is a terminal. In a
pipe it prints usage and exits without making changes. `tailscale amnezia-wg`
remains an alias. Existing `get`, `set`, `sync`, `validate`, and `reset` retain
their AWG meaning; `native` preserves the configured AWG profile rather than
silently reverting to plain WireGuard.

## Modes

- `native`: the existing Tailscale-compatible WG/AWG fork; the default.
- `quic-ip`: an IP data plane using QUIC, with no inner WG Device or encryption.
- `http3-ip`: native IP over real HTTP/3 CONNECT-IP; experimental. It is not a
  Chromium fingerprint replica or a guarantee against traffic classification.

WG-over-QUIC is absent from ordinary builds. The old development build tag is
not offered by the CLI or distribution build script.

## Prepare both nodes while native connectivity still works

Update both binaries, not just the CLI. Use an out-of-band management connection
when staging transport changes. All currently communicating peers must support
the chosen node-wide data plane; there is no automatic per-peer protocol fallback.

```sh
tailscale awg status
tailscale awg identity --init
# Export the PUBLIC card from each node, and transfer it through a trusted channel:
tailscale awg identity --json
# On the other node, import that card:
tailscale awg peer add --file peer-public.json
# --yes is available for an explicit noninteractive import:
tailscale awg peer add --yes --file peer-public.json

tailscale awg peer list
tailscale awg doctor
tailscale awg transport --yes quic-ip
# Then deliberately restart the daemon/container via its platform's service manager.
tailscale awg status --json
```

With AWG preferences or environment options present, QUIC activation is refused.
Explicitly clear those first only when it is safe to interrupt AWG connectivity.
The CLI never clears them as a hidden side effect of changing mode.

## What is and is not automatic

The daemon generates its private TLS identity locally and stores it in
`packet-transport.json` under its existing private state directory, using an
atomic 0600 file. The file contains private key material: do not copy or publish
it. The identity is independent of the current public IP and does not require a
public domain/IP certificate. The first identity is valid for a year; renewal
and profile changes must be handled deliberately in this experimental release.

Only `identity` output is public. `peer add` is a trust decision: a matching
hostname is not proof. A card must belong to a currently authorized and routable
tailnet peer. Replacing a pinned TLS key requires explicit removal and re-import.
Certificates and pin configuration are validated before enabling a transport.

QUIC modes need no AWG header/padding parameter synchronization. This release
still requires the trusted identity-card exchange; it does not automatically
trust keys obtained from unauthenticated discovery. `io=magicsock` is used by
managed profiles so existing discovery, NAT traversal and relay selection are
reused. No extra UDP port or firewall rule is opened by this CLI.

The generated HTTP/3 `.invalid` authority is private and validated by its pinned
key. It is not a public website or a publicly trusted certificate. A normal
browser-facing website requires an appropriate operator-managed authority and
certificate; use the explicit advanced HTTP/3 configuration for that deployment.

## Running versus next start

`status` separates `active_mode`, `desired_mode`, and `pending_restart`. Changing
a profile does not change the running packet engine. Identity/pin removal from
the stored profile also takes effect on restart; control-plane node/route
revocation continues to be enforced by the live data plane immediately.

Writes use the status revision as a compare-and-swap precondition, preventing an
old interactive confirmation from overwriting another administrator's changes.
Environment or embedding overrides remain authoritative; managed mode changes
are refused while such an override is active. No shell/service files are edited,
no daemon is killed, and no automatic remote-disconnecting restart is performed.

To return to WG/AWG, stage `tailscale awg transport --yes native`, restart and
inspect status. The stored public identity and peer cards are retained. To get
plain WG rather than AWG, explicitly reset AWG separately.

The managed restart loader is integrated into the standalone daemon and tsnet.
Mobile/other embedders without this loader report managed CLI unavailable rather
than falsely claiming that a staged file will be loaded. Existing native APIs
and the explicit embedded transport factory remain available.

## Verification

`TestManagedTransportLifecycle` starts real tsnet nodes, invokes the actual
LocalAPI, initializes identities, imports trusted cards, stages each mode,
restarts from disk, verifies encrypted TSMP and TCP contents, and returns to
native. Unit tests cover revision conflicts, private-file permissions, secret
redaction, wrong identity, unknown mode, cancellation/EOF, parser bounds,
non-terminal input and permission guards.

`scripts/quicwg-remote.py --managed-cli <linux-cli-binary>` repeats the workflow
using a real CLI executable and private Unix sockets on isolated remote nodes.
It does not replace their production daemons. It also retains failed reports;
a blocked port or infrastructure timeout is not recorded as a passed data test.
