// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package ipnlocal

import (
	"fmt"
	"net/netip"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus"
	"testing"
)

func TestPacketPolicyLiveOwnership(t *testing.T) {
	mk := func(id tailcfg.NodeID, extras ...string) *tailcfg.Node {
		n := &tailcfg.Node{ID: id, StableID: tailcfg.StableNodeID(fmt.Sprintf("node-%d", id)), Key: key.NewNode().Public(), HomeDERP: 1,
			Addresses: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", id)), netip.MustParsePrefix(fmt.Sprintf("fd00::%d/128", id))}}
		n.AllowedIPs = append(n.AllowedIPs, n.Addresses...)
		for _, s := range extras {
			n.AllowedIPs = append(n.AllowedIPs, netip.MustParsePrefix(s))
		}
		return n
	}
	self := mk(42)
	wide := mk(1, "0.0.0.0/0", "::/0", "10.0.0.0/8")
	narrow := mk(2, "10.2.0.0/16")
	redundant := mk(3, "10.2.0.0/16")
	nb := newNodeBackend(t.Context(), t.Logf, eventbus.New())
	nb.SetNetMap(&netmap.NetworkMap{SelfNode: self.View(), Peers: []tailcfg.NodeView{wide.View(), narrow.View(), redundant.View()}})
	nb.updateRouteManagerPrefs(routePrefs{RouteAll: true, ExitNodeID: wide.StableID, ExitNodeSelected: true})
	b := &LocalBackend{}
	b.currentNodeAtomic.Store(nb)
	check := func(k key.NodePublic, ip string, want bool) {
		t.Helper()
		if got := b.peerSourceAllowed(k, netip.MustParseAddr(ip)); got != want {
			t.Errorf("source %s from %s: got %v want %v", ip, k.ShortString(), got, want)
		}
	}
	if !b.peerDataPlaneAllowed(wide.Key) || b.peerDataPlaneAllowed(self.Key) || b.peerDataPlaneAllowed(key.NewNode().Public()) {
		t.Fatal("node admission incorrect")
	}
	check(wide.Key, "100.64.0.1", true)
	check(wide.Key, "100.64.0.42", false) // local address must shadow exit route
	check(wide.Key, "fd00::42", false)
	check(wide.Key, "100.64.0.2", false) // exact node must shadow exit route
	check(wide.Key, "fd00::2", false)
	check(wide.Key, "10.1.1.1", true)
	check(wide.Key, "10.2.1.1", false) // accepted more-specific subnet shadows /8
	check(narrow.Key, "10.2.1.1", true)
	check(redundant.Key, "10.2.1.1", true) // legitimate equal-prefix HA
	check(wide.Key, "8.8.8.8", true)
	check(wide.Key, "::ffff:100.64.0.1", false)

	// A committed preference delta is authoritative before any session timeout.
	nb.updateRouteManagerPrefs(routePrefs{})
	check(wide.Key, "8.8.8.8", false)
	check(wide.Key, "10.1.1.1", false)
	check(narrow.Key, "10.2.1.1", false)
	check(narrow.Key, "100.64.0.2", true)

	// Replacing a public key must revoke the old TLS-to-node binding immediately.
	oldKey := narrow.Key
	replacement := narrow.Clone()
	replacement.Key = key.NewNode().Public()
	if _, ok := nb.UpdateNetmapDelta([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: replacement.View()}}); !ok {
		t.Fatal("key rotation delta rejected")
	}
	if b.peerDataPlaneAllowed(oldKey) || !b.peerDataPlaneAllowed(replacement.Key) {
		t.Fatal("key rotation kept old admission")
	}
	check(oldKey, "100.64.0.2", false)
	check(replacement.Key, "100.64.0.2", true)
	expired := replacement.Clone()
	expired.Expired = true
	nb.UpdateNetmapDelta([]netmap.NodeMutation{netmap.NodeMutationUpsert{Node: expired.View()}})
	if b.peerDataPlaneAllowed(expired.Key) {
		t.Fatal("expired node remained admitted")
	}
	check(expired.Key, "100.64.0.2", false)
	nb.UpdateNetmapDelta([]netmap.NodeMutation{netmap.MakeNodeMutationRemove(wide.ID)})
	if b.peerDataPlaneAllowed(wide.Key) {
		t.Fatal("removed node remained admitted")
	}

	// A profile switch must use the new nodeBackend, not cached old callbacks.
	next := newNodeBackend(t.Context(), t.Logf, eventbus.New())
	next.SetNetMap(&netmap.NetworkMap{SelfNode: self.View()})
	b.currentNodeAtomic.Store(next)
	if b.peerDataPlaneAllowed(redundant.Key) {
		t.Fatal("previous profile admission survived switch")
	}
	check(redundant.Key, "100.64.0.3", false)
	// Same remote key in another profile does not authorize the old local key.
	nextSelf := self.Clone()
	nextSelf.Key = key.NewNode().Public()
	next.SetNetMap(&netmap.NetworkMap{SelfNode: nextSelf.View(), Peers: []tailcfg.NodeView{redundant.View()}})
	if b.peerIdentityAllowed(self.Key, redundant.Key) || b.peerIdentitySourceAllowed(self.Key, redundant.Key, netip.MustParseAddr("100.64.0.3")) {
		t.Fatal("paired policy mixed an old local identity with a new profile's remote grant")
	}
	if !b.peerIdentityAllowed(nextSelf.Key, redundant.Key) || !b.peerIdentitySourceAllowed(nextSelf.Key, redundant.Key, netip.MustParseAddr("100.64.0.3")) {
		t.Fatal("new profile's actual identity pair was not admitted")
	}
	b.currentNodeAtomic.Store(nb)
	expiredSelf := self.Clone()
	expiredSelf.Expired = true
	nb.SetNetMap(&netmap.NetworkMap{SelfNode: expiredSelf.View(), Peers: []tailcfg.NodeView{redundant.View()}})
	if b.peerDataPlaneAllowed(redundant.Key) {
		t.Fatal("expired local identity still admitted peers")
	}
}
