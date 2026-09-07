// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import "testing"

func TestAutoTrustCannotCrossRevocationDuringProof(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	server := pair.backends[1]
	originalOpen := server.host.NodeOpen
	server.host.NodeOpen = func(local, remote [32]byte, ciphertext []byte) ([]byte, error) {
		cleartext, err := originalOpen(local, remote, ciphertext)
		if err != nil {
			return nil, err
		}
		// Reproduce a control-plane revoke/re-add during an in-flight proof. The
		// current policy is permissive again, but the old attempt must not survive.
		server.PeerRemoved(remote)
		if _, err := server.active.Load().peer(remote, nil); err != nil {
			return nil, err
		}
		return cleartext, nil
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
