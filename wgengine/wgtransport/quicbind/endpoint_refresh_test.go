// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestRemovedPeerRefreshesHostEndpoint(t *testing.T) {
	pair := newTestPair(t, "magicsock")
	pair.open(t)
	b := pair.backends[0]
	k := pair.keys[1].Public().Raw32()
	g := b.active.Load()
	p, err := g.peer(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	old := p.ep.Load()
	pair.bases[0].setRemote("127.0.0.1:43210")
	b.PeerRemoved(k)
	updated, err := g.peer(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if updated != p {
		t.Fatal("peer actor unexpectedly replaced")
	}
	if updated.ep.Load() == old || updated.ep.Load().DstToString() != "127.0.0.1:43210" {
		t.Fatal("recreated peer retained its obsolete host endpoint")
	}
}

func TestWrongCertificateRejectedOnWire(t *testing.T) {
	pair := newTestPair(t, "udp")
	// Remove the configured server pin before starting any QUIC handshakes.
	// The transport must not deliver a single plaintext packet to WG.
	pair.backends[0].factory.byPin = map[[32]byte][32]byte{}
	pair.open(t)
	k := pair.keys[1].Public().Raw32()
	ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(k[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.backends[0].Bind().Send([][]byte{{1, 2, 3}}, ep, 0); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for pair.backends[0].counters.HandshakeErrors.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pair.backends[0].counters.HandshakeErrors.Load() == 0 {
		t.Fatal("wrong certificate did not fail the actual TLS handshake")
	}
	for _, b := range pair.backends {
		if b.counters.ReceivedPackets.Load() != 0 {
			t.Fatal("untrusted TLS connection delivered WG data")
		}
	}
}
