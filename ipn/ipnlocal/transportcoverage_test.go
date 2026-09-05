// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/transportprofile"
)

func TestTransportPeerCoverageUsesLiveRoutablePeers(t *testing.T) {
	pinned, legacy, expired, unroutable := key.NewNode().Public(), key.NewNode().Public(), key.NewNode().Public(), key.NewNode().Public()
	peers := []tailcfg.NodeView{
		(&tailcfg.Node{Key: pinned, Name: "pinned.test."}).View(),
		(&tailcfg.Node{Key: legacy, Name: "native-only.test."}).View(),
		(&tailcfg.Node{Key: expired, Expired: true}).View(),
		(&tailcfg.Node{Key: unroutable}).View(),
	}
	profile := transportprofile.Profile{Peers: []ipn.TransportPeer{{PublicKey: pinned.String()}}}
	allowed := func(k key.NodePublic) ([]netip.Prefix, bool) { return nil, k != unroutable }
	missing := unconfiguredTransportPeers(profile, peers, allowed)
	if len(missing) != 1 || missing[0].PublicKey != legacy.String() {
		t.Fatalf("missing=%+v", missing)
	}
	profile.Peers = append(profile.Peers, ipn.TransportPeer{PublicKey: legacy.String()})
	if got := unconfiguredTransportPeers(profile, peers, allowed); len(got) != 0 {
		t.Fatalf("configured peer still missing: %+v", got)
	}
}
