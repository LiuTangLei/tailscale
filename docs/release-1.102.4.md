# Tailscale AWG / H3 v1.102.4

## Upstream and transport integration

Based on upstream Tailscale v1.102.4, including its netmap-delta fixes and
Kubernetes ProxyGroup service-handler fix. Retains historical AWG v2/v3
profiles and default native WireGuard behavior. HTTP/3 is explicitly enabled
with `tailscale awg transport --yes http3-ip` followed by a daemon restart;
upgrading does not automatically change a node's active mode.

Integrates the current H3 native-IP receive and batching work through
`be27ef48798cca63e502de7f60fa9825e4e4b079`. The QUIC dependency is the published,
checksum-verified `github.com/LiuTangLei/quic-go v0.62.0-tailscale.4`, source
`ee8197f0b13d5680b9ded758d714c888ec92638b`; builds require no local replacements
or source overlays. The wireguard-go dependency remains v0.0.32.

H3 carries IP directly rather than encapsulating WireGuard. It retains
node-key authentication, managed identities, explicit node-wide transport
selection and server declarations. This release does not change congestion
controller defaults and makes no universal WAN throughput, latency, browser
fingerprint or censorship-resistance guarantee. Mobile/router packages remain
separate releases.

## Installer issue #18: verified cause and fix

There are two functional problems and a separate misleading log message:

1. The old installer Compose file replaced the image's `containerboot` command
   with `tailscaled`, bypassing interpretation of `TS_AUTHKEY`, `TS_EXTRA_ARGS`
   and other wrapper environment settings. Restore the default command and
   set `TS_STATE_DIR`, `TS_SOCKET` and `TS_USERSPACE` in Compose.
2. With the wrapper restored, `tailscale awg set` DOES update live preferences
   and the on-disk state. A later container restart runs `tailscale up` again.
   The full `Start(UpdatePrefs)` path (for example with an auth key) generated
   default preferences without the separately managed AWG profile, overwriting
   it. `updatePrefs` now carries the current AWG profile through this path.
   `up --reset` only resets its own flag settings; disable AWG explicitly with
   `tailscale awg reset`.
3. `MaskedPrefs.Pretty` looked up preference fields by ordinal index. The
   unmasked `Persist` field shifted AWG's index, producing the misleading
   `AmneziaWG=<nil>` line. Field lookup now uses names and the AWG log is
   redacted to `configured` / `disabled`, never printing its shared key.

This is not a `--statedir` path-resolution failure. Merely removing the Compose
command override is insufficient on older binaries. `TS_AUTH_ONCE=true` avoids
repeating login after successful authentication, but the code fix also covers
`TS_AUTH_ONCE=false` and ordinary `tailscale up` usage.

The registry's old `latest` at diagnosis contained 1.102.2, source
`36f560220bfb381b2850ed7ed934e473b1958d86`, even though GitHub had a later stable
release. Upgrade the Docker image and Compose together, preserving the entire
state directory. Do not share a live state directory between host and container
daemons. No real user state, VPN services or production routes were modified
for these tests.

## Verification

- Published QUIC dependency: full `go test -short ./...`; targeted race tests
  for datagrams, batching, browser handshake, stream drain and BBRv3.
- Integrated Tailscale: CLI, daemon, IPN, LocalAPI, transport profiles, H3,
  node authentication, magicsock, engine, dialing and upstream control-client
  package suites; H3/identity/profile race tests and focused vet.
- AWG regression: 15 cases cover v2/v3/disabled profiles across auth-key start,
  Starting state, reauthentication, reset of up flags and masked edits, plus
  JSON round trips and redacted log tests.
- `scripts/docker-state-smoke.py`: the old registry image and the pre-fix
  candidate both fail across restart. The fixed candidate passes real
  containerboot environment login, v2/v3 disk and restart checks, AWG reset,
  and H3 mode/identity persistence. Tested in both userspace and Linux kernel
  TUN modes with isolated local test control; no external networking.
- `scripts/transport-cli-smoke.py --auto-trust`: two real isolated tsnet nodes
  pass H3/native/H3/native transitions, automatic authentication, staged
  activation and bidirectional application-data checks in every phase.

The Docker test reads LocalAPI's historical uppercase `JC` JSON field, not the
lowercase generator input alias. An initial test assertion used the wrong
case; it was corrected before determining the cause or accepting the fix.
Cross-compilation is not a substitute for testing installed Windows or macOS
system services; those live installation workflows are outside this run.
