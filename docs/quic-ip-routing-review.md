# Source-ownership review for the native IP backend

Implemented authority: `net/routemanager.RouteManager.SourceAllowed` publishes an
immutable longest-prefix table of every eligible contributor, independently of
outbound next-hop scoring. More-specific node/subnet ownership shadows defaults
and supernets; equal-prefix HA contributors remain valid. Commit updates the
snapshot for routing preferences, expiry, removal, extras and key changes.

Host gates: `ipn/ipnlocal/packetpolicy.go` checks both the active local identity and
remote identity in one current nodeBackend snapshot. Source checks additionally
deny the local node's addresses and another exact node's addresses. Holding
`nodeBackend.mu` pairs membership with route-manager Commit publication;
SourceAllowed itself is allocation-free and does not take a mutex. Callers must
not re-enter the engine from these policy functions.

Delivery: `wgengine/quicip.Device.receive` accepts only an authenticated carrier
endpoint, validates the complete IP packet, applies admission/source checks, and
then uses `tstun.Wrapper.Write`. This preserves the existing inbound ACL, NAT,
netstack, jailed-peer and capture paths. It never substitutes InjectInbound* for
normal network delivery.

Regression coverage lives in `ipn/ipnlocal/packetpolicy_test.go`, route-manager
source tests and `quicbind/native_ip_acl_test.go`. These include source spoofing,
HA overlap, live revocation, local/remote key changes, profile changes and a real
QUIC packet denied by the existing Tailscale inbound ACL.

Deployment limits and the exact implementation contract are documented in
`docs/quic-ip-experimental.md`; test reports are separate build-specific artifacts.
