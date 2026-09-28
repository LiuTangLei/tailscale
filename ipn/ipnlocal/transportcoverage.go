// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/transportprofile"
)

// Current QUIC selection is node-wide, not a per-peer fallback. Refuse a
// managed configuration known to discard other routable peers. Having a pin is
// only a necessary condition: it does not prove the other end enabled QUIC.
func unconfiguredTransportPeers(p transportprofile.Profile, peers []tailcfg.NodeView, allowed func(key.NodePublic) ([]netip.Prefix, bool)) []ipn.TransportUnconfiguredPeer {
	pins := make(map[string]bool, len(p.Peers))
	for _, p := range p.Peers {
		pins[strings.TrimPrefix(p.PublicKey, "nodekey:")] = true
	}
	var missing []ipn.TransportUnconfiguredPeer
	for _, peer := range peers {
		if !peer.Valid() || peer.Expired() || peer.Key().IsZero() {
			continue
		}
		if _, ok := allowed(peer.Key()); !ok {
			continue
		}
		if pins[strings.TrimPrefix(peer.Key().String(), "nodekey:")] {
			continue
		}
		missing = append(missing, ipn.TransportUnconfiguredPeer{PublicKey: peer.Key().String(), Name: peer.Name()})
	}
	slices.SortFunc(missing, func(a, b ipn.TransportUnconfiguredPeer) int { return strings.Compare(a.PublicKey, b.PublicKey) })
	return missing
}

func (b *LocalBackend) transportPeerCoverage(p transportprofile.Profile) []ipn.TransportUnconfiguredPeer {
	nb := b.currentNode()
	return unconfiguredTransportPeers(p, nb.Peers(), nb.PeerAllowedIPs)
}

func (b *LocalBackend) checkTransportPeerCoverage(p transportprofile.Profile) error {
	if p.Mode == "native" || p.AutoTrust {
		return nil
	}
	if missing := b.transportPeerCoverage(p); len(missing) != 0 {
		return fmt.Errorf("cannot activate %s: %d routable peers have no trusted QUIC identity; this build cannot use native for old peers while QUIC is active. No configuration saved. Inspect 'tailscale awg status --json' and retain native for a mixed-version tailnet", p.Mode, len(missing))
	}
	return nil
}
