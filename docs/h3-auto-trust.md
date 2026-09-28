# HTTP/3 automatic Tailnet identity authentication

## Normal operation

After the node is logged into its Tailscale or Headscale network, select H3:

```sh
tailscale awg transport --yes http3-ip
# Restart the daemon deliberately using the platform's existing service manager.
tailscale awg status --json
```

The mode change atomically creates a local TLS identity when needed and selects
`authentication: node-key`. No identity-card export/import is required. A newly
joined authorized H3 peer can communicate without reconfiguring existing nodes.
The command stages the next start; it does not restart the daemon, change AWG
parameters, alter the firewall, or re-register the node.

The optional node-level declaration remains:

```sh
tailscale awg server on
tailscale awg server off
```

Only an ordinary node dialing an authenticated, declared server selects the
existing Chromium-inspired ClientHello. Two ordinary nodes, two servers and
incoming connections retain standard TLS. Unknown peers initially use ordinary
H3, learn the authenticated declaration, and use it for later connections. No
healthy connection is restarted just to change its appearance.

## Trust chain and protocol

The host owns the current X25519 node private key and current control-plane
policy. It exposes an opaque, bounded `NodeHandshake` and `NodePublic`; the
carrier never receives private key bytes. Every handshake operation rechecks
the expected local identity and current remote authorization.

Automatic authentication now uses `Noise_IK_25519_ChaChaPoly_BLAKE2s` through
`github.com/flynn/noise v1.1.0`. TLS is a provisional encrypted channel until all
of the following complete:

1. The initiator sends Noise IK message 1 in the CONNECT Authorization header.
   Its static node identity and optional separately pinned TLS-key proof are
   encrypted to the expected responder. No plaintext sender-key header is sent.
2. The responder decrypts the initiation, checks live membership, target,
   nonce, certificate SPKI and server declaration, and replies with IK message 2.
   HTTP 200 remains provisional: **IK message 1 alone does not provide the
   responder with KCI-resistant initiator authentication**.
3. The initiator validates the reply and TLS certificate binding, then sends an
   encrypted `initiator finished v2` private capsule using the IK split keys.
4. The responder verifies that capsule and the saved lifecycle stamp before
   replying with encrypted `responder finished v2`. Both sides complete this
   confirmation before installing a data session. Failed confirmation closes
   the provisional QUIC connection.

The exact authentication scheme is `TailnetNoiseIKv2`. The TLS exporter label is
`EXPORTER-HTTP3-TAILNET-NODE-AUTH-v2`; its context hashes the CONNECT method,
protocol, authority, escaped path and query. The Noise prologue is
`tailscale-h3-node-auth-v2` followed by a zero byte and this 32-byte exporter.
Encrypted metadata starts with version 2, direction, five 32-byte fields
(sender, receiver, nonce, exporter, SPKI), and a boolean server flag. Only the
request appends the optional pin proof, within the 2048-byte payload limit.
Finished capsules use type 62, a single-byte length, and at most 63 encrypted
bytes. They are consumed before the generic capsule reader starts.

The global revocation generation is captured before decrypting an anonymous
initiator identity; peer/local lifecycle stamps protect subsequent work.
Removal/re-addition invalidates attempts and queued packets even if current
policy has become permissive again. Handshake state is discarded immediately
after confirmation, with best-effort clearing of owned key buffers; Go does
not provide a general guarantee of complete heap key erasure.

Bulk packets still use one QUIC AEAD layer, source-address checks, TUN filters,
ACLs and routing. Noise is a connection-setup operation, not inner WG encryption.
This integration has regression coverage, not an independent protocol audit or
formal proof of equivalence to WireGuard. See the [Noise specification](https://noiseprotocol.org/noise.html).

## Connection and resource lifetime

The current TLS initiator starts a complete fresh QUIC/TLS connection after
120 seconds while data continues on the authenticated old session. Installation
switches new sends; the old connection has a 3-second drain interval. At 180
seconds a session expires even if refresh failed. No TLS resumption or 0-RTT is
used. This introduces fresh DH entropy; QUIC packet Key Update alone does not.
Refresh costs and congestion-window restart must be measured on real links.

Actors without IP traffic for two minutes are retired, their queues drained,
and references invalidated. A subsequent packet lazily creates a new actor.
QUIC keepalives do not count as IP activity. A bounded worker sends the existing
1.102.3 TSMP disco advertisement after each authenticated session establishment.

The existing Retry limiter and total connection limit remain. A separate gate
allows at most 32 provisional incoming connections and four per source IP (or
logical magicsock endpoint), releasing the slot on authentication or close.
After TLS completes, node authentication has an eight-second deadline. This
bounds resource usage; it does not promise immunity to distributed exhaustion.

The legacy 1.102.3 TUN/Bind APIs remain intact. H3 opts into buffers that start at
2048 bytes per slot plus headroom and grow for actual large IP/GSO packets.
Each receive closure remains bound to its original generation. Native WG keeps
its existing buffer contract; no DF, GSO or ECN capability is fabricated for the
magicsock bridge.

## Local state and identity changes

The TLS private key remains local in the private transport profile; the node
private key remains host-owned. Selecting the mode, not merely viewing status or
cancelling a prompt, creates identity state. CAS checks prevent stale interactive
confirmations overwriting another administrator's update.

A current node-key change does not require exchanging another TLS certificate.
The transport uses the active host identity and current peer policy; the public
status reflects the active node key. Peer expiry/removal invalidates sessions and
learned server hints. IP/address changes do not create a new identity.

At startup, an expired but internally consistent automatic-profile certificate
can be replaced atomically. Corrupt PEM, wrong private key, bad stored SPKI or a
future NotBefore fail explicitly without overwriting the original. This is not
an ACME client or a promise of unattended live renewal in a year-long process.
Explicit manual certificate pins remain additional constraints and have their
own renewal requirements.

## Existing configurations

Loading an existing profile that omits `auto_trust` preserves its pinned-key
behavior; replacing a binary does not silently change authentication. Explicitly
selecting H3 enables automatic trust. The advanced LocalAPI can explicitly retain
pinned authentication, and legacy raw QUIC profiles continue to use their pins.

Existing explicit pins, if retained on an automatic profile, are enforced in
addition to the node proof, including possession of the pinned client's TLS key.
Communicating nodes must support and enable `TailnetNoiseIKv2`. Automatic-mode
nodes running `v1.102.3-quic.3` use the vulnerable older scheme and must be
upgraded together; there is deliberately no automatic downgrade.
Missing or invalid proof fails closed; it never retries with weaker trust or
switches the data plane behind the user's back.

Native WG/AWG configuration is unchanged. Public web certificates, browser trust,
packet fingerprints and Tailnet node membership remain separate concerns.

## Validation in this branch

Automated tests cover fresh no-card staging, late peer joining, three-way data,
server flag combinations, rebind, node-key rotation, current authorization,
explicit pin constraints, proof replay/reflection, request and certificate
binding, KCI in both TLS roles (including a valid forged IK initiation),
Finished confirmation, identity privacy, session refresh and idle retirement,
mid-proof revocation/re-addition, certificate lifecycle and old manual
profile loading. The real-CLI test accepts `--auto-trust` to exercise fresh local
processes without `identity` or `peer add` calls.

The three-node TCP echo test services each accepted connection concurrently:
tsnet's unbuffered listener has a one-second handoff timeout. The test also closes
listeners after client failure, so failed dials do not leave the harness hung.

Local tests do not certify production deployment, WAN throughput, all-device
runtime coverage, or resistance to any particular network classifier.
