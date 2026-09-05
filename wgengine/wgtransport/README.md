# Experimental WireGuard transport boundary

This package is the Tailscale-specific adapter between the existing WireGuard/AWG device and its packet carrier. It does **not** implement QUIC or replace the WireGuard cryptographic engine.

## Baseline and scope

- Official Tailscale `v1.102.3`, commit `53a0d659afa51835dd7a9283873cca44261454f8`, is an ancestor of this branch.
- The existing Tailscale/AWG integration is retained from `e8bda54e7164160841a991659cc4d9d2c97bd23f`.
- The WG module is pinned to `github.com/LiuTangLei/wireguard-go v0.0.31-0.20260905021413-8835972ec5d8`, not a local `replace` directive.
- That fork incorporates the semantics of AWG `v3.1.20260828` / `b5928efb6ca19f0153958460c3d141f04abc5c2e`, preserving the fork's Tailscale interfaces and immutable AWG configuration. It is not a byte-identical checkout of the AWG repository.

The inner protocol profile and the outer carrier are separate:

```
Tailscale routes, ACLs, control plane and configuration
                       |
           existing WireGuard / AWG Device
                       |
           wgtransport factory and lifecycle
                       |
            existing magicsock conn.Bind
                       |
               UDP / DERP / peer relay
```

AWG configuration remains device-wide. This phase does not introduce per-peer AWG profiles or automatic carrier negotiation.

## Selection and extension

A zero `wgengine.Config.Transport` selects `native`. The native manager returns the **identical original Bind**: no packet queues, no packet copies, no endpoint wrappers, and no loss of optional Bind interfaces are introduced in the native packet path.

`TS_EXPERIMENTAL_WG_TRANSPORT=native` explicitly selects that carrier. Selecting `quic` without a compiled provider fails at the start of engine construction, before that constructor allocates network or TUN resources. Embedding callers remain responsible for any resources they allocated before calling it. Unknown values fail too. There is no automatic fallback to native.

An embedding application may set `wgengine.Config.Transport` with an explicit `Mode` and a compiled `Factory`. Explicit mode takes precedence over the environment. Carrier choice is startup-only in this phase; changing it requires recreating the engine. Existing AWG profile updates remain separate.

The extension API consists of `Factory`, `Host`, `Backend`, and optional `PeerLifecycle` / `NetworkLifecycle`. A future reusable QUIC implementation should remain independent of Tailscale; its adapter implements this interface. There is no global mutable registry or runtime plugin loading.

## Ownership and safety contract

- The host supplies a borrowed `conn.Bind`. Its endpoint string can be a node key, not an IP address. Its physical route can change below this interface.
- The WG device owns its normal Bind/TUN lifecycle. `Bind.Close` must unblock receivers; later `Bind.Open` must remain possible. Final `Backend.Close` is distinct, idempotent, and releases all provider resources without waiting for later host cleanup.
- Send buffers are borrowed only until `Send` returns. A backend that retains packets must copy them. Preserve batch size, send offset/headroom and zero-size receive slots.
- Preserve `InitiationAwareEndpoint`, `PeerAwareEndpoint`, and cookie address identity. `Endpoint` forwards those callbacks; `UnwrapEndpoint` rejects nil or cyclic/excessive wrappers. Providers must unwrap before passing an endpoint to magicsock. Unknown endpoint types now return an error rather than silently dropping a send.
- Only public identity is sent to lifecycle callbacks. Peer removal/reset invalidates corresponding carrier state. Read-only peer enumeration does not signal removal.
- Lifecycle calls and final close are serialized. Callbacks must return promptly, must not reenter the engine/manager, and must synchronize with concurrent Bind traffic themselves.
- Network notification is not a per-peer path-selection API and is not proof that QUIC connection migration works.

## Work deliberately deferred to QUIC-WG

No QUIC handshake, DATAGRAM framing, HTTP/3, MASQUE, protocol camouflage or packet-prefix simulation is implemented here. The tests' injectable counting provider is a test double, not a QUIC implementation.

Before enabling a real provider, implement and test peer/certificate authentication, simultaneous dialing, bounded queues, packet-size/fragmentation handling, reconnects, and node/network lifecycle. Per-peer capability negotiation and fallback policy also remain outstanding.

A generic Bind wrapper cannot distinguish a UDP send from a DERP send when magicsock chooses the route later. Direct-only QUIC with native DERP bypass therefore needs a path-aware magicsock adapter. STUN/disco are outside WG's encrypted-data Bind and are not automatically camouflaged by this boundary.

## Verification

The package tests cover native identity/reopen behavior, fail-closed selection, factory failure cleanup, callback forwarding, cycle rejection, and real localhost UDP WG/AWG handshakes with bidirectional byte equality through an injected test carrier. Engine tests cover early rejection, public identity updates, removal notifications, status enumeration and final cleanup.

The AWG 3.1 application integration separately tests JSON aliases, CLI export, config capability gating, and resetting the two new flags. They default to false. UAPI writes accept booleans and readback uses `0` / `1`.

Real two-host results and reproduction instructions are in `docs/wgtransport-experimental.md` and the local artifact directory described there. Cross-compilation is not a substitute for platform runtime validation.
