// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"testing"
	"time"

	"tailscale.com/wgengine/wgtransport"
)

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

func TestRemovalCannotDeleteAReplacementServerHintSlot(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock")
	pair.open(t)
	b := pair.backends[0]
	k := pair.keys[1].Public().Raw32()
	p, err := b.active.Load().peer(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.getSession(); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	b.host.SessionChanged = func(_ [32]byte, state wgtransport.SessionState) {
		if state == wgtransport.SessionExpired {
			close(entered)
			<-release
		}
	}
	removed := make(chan struct{})
	go func() { b.PeerRemoved(k); close(removed) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("removal did not reach host notification")
	}
	if _, err := b.active.Load().peer(k, nil); err != nil {
		t.Fatal(err)
	}
	b.serverHintsMu.RLock()
	newHint := b.serverHints[k]
	b.serverHintsMu.RUnlock()
	if newHint == nil {
		t.Fatal("revival did not recreate the server hint slot")
	}
	newHint.Store(serverYes)
	release <- struct{}{}
	<-removed
	b.serverHintsMu.RLock()
	currentHint := b.serverHints[k]
	b.serverHintsMu.RUnlock()
	if currentHint != newHint || b.peerServerHint(k) != serverYes {
		t.Fatal("late removal cleanup erased the replacement server hint")
	}
}
