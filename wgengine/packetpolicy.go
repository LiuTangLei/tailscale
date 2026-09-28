// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"net/netip"
	"tailscale.com/types/key"
)

type packetPolicy struct {
	peer   func(local, peer key.NodePublic) bool
	source func(local, peer key.NodePublic, src netip.Addr) bool
}

// SetPeerPolicyFuncs installs live authorization independently of the carrier.
// Both identities are checked against ONE current control-plane snapshot, so a
// profile switch cannot combine the old local grant with a new peer grant.
func (e *userspaceEngine) SetPeerPolicyFuncs(peer func(key.NodePublic, key.NodePublic) bool, source func(key.NodePublic, key.NodePublic, netip.Addr) bool) {
	e.packetPolicy.Store(&packetPolicy{peer: peer, source: source})
	e.packet.SetPolicy(e.peerCurrentlyAllowed, func(k key.NodePublic, src netip.Addr) bool {
		p := e.packetPolicy.Load()
		local := e.packetIdentity.Load()
		return p != nil && local != nil && p.source != nil && p.source(*local, k, src)
	})
}
func (e *userspaceEngine) peerCurrentlyAllowed(k key.NodePublic) bool {
	p := e.packetPolicy.Load()
	local := e.packetIdentity.Load()
	return p != nil && local != nil && p.peer != nil && p.peer(*local, k)
}
