// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"tailscale.com/wgengine/wgtransport/nodeauth"
	"testing"
)

type revokingHandshake struct {
	nodeauth.Handshake
	after func([32]byte)
}

func (h revokingHandshake) Read(p []byte) ([]byte, error) {
	out, err := h.Handshake.Read(p)
	if err == nil {
		h.after(h.Peer())
	}
	return out, err
}

func TestAutoTrustCannotCrossRevocationDuringProof(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	server := pair.backends[1]
	original := server.host.NodeHandshake
	server.host.NodeHandshake = func(local, remote [32]byte, initiator bool, binding []byte) (nodeauth.Handshake, error) {
		h, err := original(local, remote, initiator, binding)
		if err != nil {
			return nil, err
		}
		return revokingHandshake{h, func(remote [32]byte) { server.PeerRemoved(remote); _, _ = server.active.Load().peer(remote, nil) }}, nil
	}
	pair.open(t)
	peer, err := pair.backends[0].active.Load().peer(pair.keys[1].Public().Raw32(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.getSession(); err == nil {
		t.Fatal("old proof survived revocation/re-add")
	}
	for _, b := range pair.backends {
		if b.counters.Connections.Load() != 0 {
			t.Fatal("old authenticated session installed")
		}
	}
}
