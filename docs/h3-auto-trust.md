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

The host already has the current private node key and a control-plane-authorized
peer policy. It exposes bounded `NodeSeal`, `NodeOpen` and `NodePublic` callbacks,
not private key bytes. Authentication uses the existing `NodePrivate.SealTo` /
`OpenFrom` primitives. The callbacks require the caller's expected local public
key, check the same live peer authorization before and after the operation, and
reject a concurrent key change.

TLS provides a provisional encrypted channel. For automatically authorized
peers without an explicit certificate pin, its certificate is not by itself the
peer's identity. No IP session is installed until the CONNECT authentication
checks pass:

1. The client sends a node-key-authenticated encrypted proof, addressed to the
   expected server node key, in the encrypted CONNECT Authorization header.
2. The proof binds the protocol version, direction, both full node public keys,
   a fresh 32-byte nonce, TLS exporter for the exact CONNECT request target,
   certificate SPKI and the node's server declaration.
3. The server validates the proof against its current local key and live policy,
   then returns a separately domain/direction-bound proof carrying the same
   nonce and exporter, plus its actual TLS certificate SPKI and server flag.
4. The client checks the reply against the current TLS connection, expected node
   and request. A certificate alone, a copied proof from another TLS connection,
   a reflected request or an unsigned server hint cannot complete this step.

The `TailnetNode` authentication scheme uses CONNECT request/response headers;
it introduces no unauthenticated side socket or prerequisite native data path.
The TLS exporter label is `EXPORTER-HTTP3-TAILNET-NODE-AUTH-v1`. The fixed proof is
163 bytes before NaCl box framing. No arbitrary hostname or TLS certificate is
learned as trusted on first use.

A pre-authentication actor lookup is bounded and must match a currently
routable peer, but is NOT itself authentication. Incoming and outgoing attempts
capture peer/local lifecycle generations before verification. Revocation and
re-addition invalidate old in-flight attempts as well as queued packets.

After connection setup, IP packets follow the unchanged QUIC DATAGRAM path,
source-address authorization, TUN filter, ACL and routing pipeline. The node-key
proof is not repeated per packet and does not add inner WG encryption. Dynamic
peer-origin construction is restricted to actor creation, not the packet path.

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
Communicating nodes must support and enable the same authentication scheme.
Missing or invalid proof fails closed; it never retries with weaker trust or
switches the data plane behind the user's back.

Native WG/AWG configuration is unchanged. Public web certificates, browser trust,
packet fingerprints and Tailnet node membership remain separate concerns.

## Validation in this branch

Automated tests cover fresh no-card staging, late peer joining, three-way data,
server flag combinations, rebind, node-key rotation, current authorization,
explicit pin constraints, proof replay/reflection, request and certificate
binding, mid-proof revocation/re-addition, certificate lifecycle and old manual
profile loading. The real-CLI test accepts `--auto-trust` to exercise fresh local
processes without `identity` or `peer add` calls.

The three-node TCP echo test services each accepted connection concurrently:
tsnet's unbuffered listener has a one-second handoff timeout. The test also closes
listeners after client failure, so failed dials do not leave the harness hung.

Local tests do not certify production deployment, WAN throughput, all-device
runtime coverage, or resistance to any particular network classifier.
