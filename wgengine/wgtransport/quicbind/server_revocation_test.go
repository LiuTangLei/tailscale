// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import "testing"

func TestServerHintRejectsLateSessionsAndClearsOnRevocation(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock")
	pair.open(t)
	b := pair.backends[0]
	remote := pair.keys[1].Public().Raw32()
	p, err := b.active.Load().peer(remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	p.rememberServerHint(s, serverYes)
	if !b.browserProfileEligible(remote, true) {
		t.Fatal("authenticated server declaration not accepted")
	}
	stale := &session{q: s.q, stamp: s.stamp}
	p.rememberServerHint(stale, serverNo)
	if !b.browserProfileEligible(remote, true) {
		t.Fatal("superseded session changed server declaration")
	}
	p.rememberServerHint(s, serverNo)
	if b.browserProfileEligible(remote, true) {
		t.Fatal("authenticated flag withdrawal was ignored")
	}
	p.rememberServerHint(s, serverYes)
	p.rememberServerHint(s, serverUnknown) // authenticated legacy peer omits extension
	if b.peerServerHint(remote) != serverUnknown {
		t.Fatal("legacy metadata retained stale server declaration")
	}
	p.rememberServerHint(s, serverYes)
	b.PeerRemoved(remote)
	p.rememberServerHint(s, serverYes)
	if b.peerServerHint(remote) != serverUnknown {
		t.Fatal("revoked peer restored server eligibility")
	}
}
