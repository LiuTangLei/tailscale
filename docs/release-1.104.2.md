# v1.104.2

This release merges upstream Tailscale v1.104.2 and retains WG/AWG and
HTTP/3 CONNECT-IP transport. QUIC is based on v0.64.1; the checksum-pinned fork
commit `10dfe69b6d4ca273c4284ec48d786206af62286e` includes exact duplicate
tracking for the most recent 8192 packet numbers. Reordered, previously unseen
DATAGRAM packets inside that window can be delivered after ACK history pruning;
wire formats are unchanged. uTLS is pinned to
`7effde6a93dc68c3535eaa590b6d28c503e18ff6` (v1.8.2 plus profiled QUIC resumption).

Authenticated H3 reconnects can use single-use 0-RTT tickets. Only the tunnel
request uses early data; business traffic waits for TLS completion and admission.
Missing or rejected tickets fall back to full authentication. Existing H3 peers
remain compatible; both peers must support the new ticket scheme for 0-RTT.

Production retains 1200-byte Initial packets, lightly tuned BBRv3 and TCP repair
disabled by default. No FEC or path-MTU policy change is included. Local reordering
results do not establish a universal throughput improvement or WAN acceptance.

## Validation

- Published dependency graph only, `GOWORK=off`, Go 1.27.3; module verification.
- QUIC full short race suite; application transport, node authentication,
  quicip, transport profiles, magicsock, DNS and testcontrol race tests.
- H3 interoperability uses separate v1.104.1 and v1.104.2 processes, each with
  its own pinned QUIC dependency: new-to-old, old-to-new and new-to-new over
  direct UDP and magicsock, plus magicsock browser-profile configurations.
  All nine cases pass three connections and bidirectional 64/1200/2048/16000-byte
  payload checks with a 1200-byte Initial. Mixed versions use no early data;
  new-to-new reconnects exercise real TLS resumption and 0-RTT.
- Existing tests cover single-use tickets, wire replay, revocation, journal loss,
  bounded full-handshake fallback and withholding business traffic until Finished.
- Static analysis includes a test-only fix to initialize a peer map directly,
  avoiding a pre-existing copy-of-lock warning. Production magicsock is unchanged.

Release binaries are standalone CLI/daemon builds for Linux, macOS and Windows
on amd64 and arm64. macOS binaries are ad-hoc signed. Cross-compilation does not
constitute live Windows/Linux or public-network acceptance. Build metadata and
checksums are supplied with the release.
