# H3: one node-wide server declaration

## User-facing configuration

Only one new role-related option is exposed: `server`, default `false`.

```sh
# Run only on a node that should be a browser-profile target.
tailscale awg server on

# Return to the default declaration.
tailscale awg server off

# Inspect the next-start setting and restart status.
tailscale awg server
```

`--yes` bypasses confirmation, not validation. The command stages a next-start
setting; it never restarts the daemon or changes the transport mode, AWG,
certificates/private keys, listening ports, firewall, routes or peer trust.
Normal clients need no additional role configuration. The interactive root
menu has one server on/off action. There is no `peer role` command.

This branch is based on released `0bcfa8346` and replaces the unreleased
per-peer-role prototype, rather than extending its manual policy matrix. Native
and existing experimental QUIC-IP/H3 modes continue to load the released
configuration. It does not reinterpret a saved QUIC-IP mode as H3.

## Meaning of server

`server=true` declares this node a target for a browser-style client handshake.
It does not prohibit initiating connections or require TCP/UDP 443. It is not
an access permission and is not a global TLS role.

- Default -> default: keep existing H3 mesh.
- Any node -> an authenticated declared server: eligible for a future browser
  client profile on an OUTGOING handshake.
- Any node accepting a connection: remains a normal H3 TLS server, never tries
  to emulate a browser client.
- Both declared server: retain normal deterministic mesh duplicate handling;
  neither waits forever merely because it has the server declaration.

The decision is per connection/peer, not per process or traffic direction.
No GeoIP, ISP, physical port or unauthenticated network hint selects a profile.
The current 8-byte connection IDs, BBR, datagram pacing and payload framing are
unchanged. No role-related decision or extra header is added to each IP packet.

## Authenticated automatic exchange

The node declaration is included in the public identity export and exchanged
as the `X-Transport-Server` structured boolean on authenticated H3 CONNECT
requests/responses. It is never advertised on the unauthenticated public page.

TLS pin verification, CONNECT peer proof and current host authorization must
succeed before learning the declaration. Only the current session/identity
generation can update its per-backend atomic slot. Peer removal clears the
slot; late or superseded sessions cannot restore it. Malformed/duplicate fields
are rejected. An old peer without the field remains compatible and clears a
stale assumption to unknown.

No additional identity-card exchange is necessary to update this declaration
between already trusted, communicating peers. This does NOT implement automatic
initial Tailnet TLS trust establishment; the released manual trust provisioning
requirement is unchanged.

Unknown peers start with the original H3 handshake. Successful authentication
learns their declaration for subsequent connections. Existing connections are
not recycled just to change their appearance. Hints are per-backend memory and
survive Bind close/open, not a process restart; trusted public-card hints can
seed the first connection. Idle/unconnected peers are not proactively dialed
solely to broadcast this bit. After restart they learn it when communicating.

## Fingerprint implementation status

This change implements the option, authenticated discovery and selection
boundary ONLY. uTLS/uQUIC browser ClientHello/Initial generation is not included.
Diagnostics explicitly report `browser_fingerprint: none` and
`browser_fingerprint_supported: false`; `browser_eligible_next_outbound` is an
eligibility condition, not proof that a browser handshake has been sent.

Per-peer diagnostics include learned server state and actual TLS role. When
multiple sessions are active, scalar connection metrics are not overwritten by
an arbitrary peer; metrics are reported per peer and receive queues aggregated.

## Verification performed

- Default/default, default/server, server/default, server/server, with either
  endpoint initiating, real authenticated H3 datagrams and Bind close/reopen:
  targeted tests passed three times.
- Four real H3 nodes (two declared server, two default), all six peer pairs,
  then twelve directional senders concurrently exchanging sixteen datagrams
  each; payload and endpoint identity verification: five repeated passes.
- Initially this concurrent test incorrectly expected all cold-dial datagrams
  to survive duplicate-connection replacement. That run timed out. DATAGRAM
  does not promise reliability; the final test first settles its authenticated
  sessions, then tests concurrent data and metadata isolation. It is not a
  cold-start zero-loss guarantee or a new retransmission implementation.
- Real tsnet engines + LocalAPI: stage the flag, restart, automatically learn
  it without reimporting the peer card, clear it, restart again, and return to
  native. Includes encrypted TSMP and TCP payload round trips.
- Public/unauthenticated requests cannot change learned declarations; tests
  reject malformed metadata, late sessions and declaration resurrection after
  revocation. Profile/key material stays unchanged, explicit false persists,
  cancel/EOF performs no mutation, and CAS revision checks remain mandatory.
- Full tests passed for 12 related packages: wgtransport, quicbind, quicip,
  transportprofile, wgcfg, ipn, ipnlocal, localapi, client/local, CLI, tsnet,
  disco. Scoped `go vet` passed.
- Focused race tests passed twice for quicbind, transportprofile, CLI and tsnet.

No production node was modified, no WAN throughput rerun was performed, and no
published tag/release was changed. Passing the selector tests is not browser
fingerprint conformance, a GFW experiment or a new 300 Mbps measurement.
