# QUIC RC hardening — 2026-09-06

## Status: NOT a production RC

Base: `cba520e8239f91b6f8200e79e1bc80469f375624`.
Branch: `experimental/quic-rc-hardening-20260906`.

No production binary, service unit, state file, firewall, or certificate on SG or
USX was changed during this work. The out-of-band management check was blocked
by the execution service's safety check. Before that block, read-only checks confirmed:

- `usx.yesican.top` resolved to `173.249.215.87`; Tailnet SSH at
  `100.64.0.23` reported hostname `zjg`, Tailscale `1.102.3`, old commit
  `e8bda54e7-dirty`, active service PID `3533852`.
- `sg.yesican.top` resolved to `96.9.212.12`. Local Tailnet status showed
  `sg2222` online at `100.64.0.17`. That is CONTROL-PLANE metadata, not proof
  that the new QUIC binary, subnet routing, or exit-node traffic works there.

## Fixes in this branch

1. Queued receive and transmit data now carries local-identity and peer-lifecycle
   generations. Explicit identity reset, peer removal/re-add and magicsock rebind
   invalidate old work; reauthorization does not resurrect a stale packet.
   Generations are local metadata, never wire overhead. The regression first
   reproduced old receive data crossing each of those three reset boundaries.
2. In-memory TLS certificate identities are checked against their private key
   before the carrier starts. Missing and typed-nil ECDSA keys or mismatching
   keys are rejected. A certificate at NotAfter is no longer treated as valid.
3. Managed QUIC configuration exposes `mixed_peer_support: false` and
   `unconfigured_peers` in LocalAPI. Mode changes and profile edits that would
   knowingly abandon a current routable peer without a QUIC identity are
   rejected before saving. Native mode remains available. CLI status states
   the limitation instead of implying per-peer fallback.

The third item is a GUARD, not mixed-protocol support. A configured TLS pin is
also not proof that the remote node is running the same transport.

## Verification actually executed

- Full tests passed for 17 related packages: wgtransport, quicbind, quicip,
  wgengine, transportprofile, magicsock, wgcfg, ipn, ipnlocal, localapi, ipnstate,
  client/local, CLI, tailscaled, wgcompat-lab, routemanager, tstun.
- Focused tests ran three times, including persisted profile -> restart ->
  QUIC-IP -> HTTP/3-IP -> native and real encrypted traffic through tsnet.
- Focused race tests ran three times for quicbind, tsnet and ipnlocal.
- A three-real-engine fixture keeps a third peer native-only. Staging either
  QUIC mode with only the other upgraded peer's identity is refused without a
  revision change. Bidirectional encrypted TSMP to the native peer still works.
  This is a native wire-mode fixture, NOT an old production binary test.
- HTTP/3-IP exchanged data in both directions using test certificates whose
  only EKU is serverAuth. These locally signed fixtures model the missing
  clientAuth property; they are not certificates issued by Let's Encrypt.
- Lifecycle stamp microbenchmark on Apple M4: 2.248 ns/op, 0 B/op, 0 allocs/op.
  This is NOT an end-to-end speed measurement or an anti-censorship result.

## Release blockers that remain

- Native WG/AWG and QUIC are mutually exclusive node-wide packet engines.
  Two QUIC peers cannot currently keep concurrent native sessions with old
  nodes. An actual per-peer data-plane dispatcher is still required for a
  mixed-version Tailnet, with explicit policy against unwanted downgrade.
- Automatic TLS identity binding/discovery using the already-authorized
  Tailscale node identities is not implemented. Manual pins remain necessary.
- No final-candidate production replacement, repeated WAN performance test,
  controller reconnect test, old-node mixed-mode test, subnet/exit-node/DNS/
  SSH/Taildrop full workflow test was completed here.
- No RC tag, release promotion, or production deploy should be inferred from
  the passing local tests.

## Certificates and deployment boundary

Public CA issuance is not needed for Tailnet client membership. In HTTP/3 mode,
server TLS and CONNECT node authorization are distinct. Removing clientAuth
from a public certificate does not remove serverAuth or prevent an application
from authenticating its clients separately.

Caddy can own public certificate issuance/renewal. The QUIC listener must still
be explicitly wired to the intended server certificate and its renewal; a cert
used solely by a different Caddy listener does not magically change this
carrier's TLS identity. No ACME integration or Caddy configuration was modified.

Neither a self-signed certificate nor a public certificate is an assurance about
GFW treatment. QUIC TLS 1.3 encrypts the certificate flight; observable Initial
ClientHello metadata and active probing are distinct threat models. No GFW
experiment was performed in this work.
