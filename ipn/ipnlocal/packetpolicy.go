// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"tailscale.com/types/key"
)

// The engine passes both local and remote identity. One current nodeBackend
// lock pairs identity checks with route-manager publication across profile
// switches; an old local grant cannot combine with a new profile's peer grant.
func (b *LocalBackend) peerIdentityAllowed(local, remote key.NodePublic) bool {
	nb := b.currentNode()
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.packetLocalAllowedLocked(local) && nb.packetPeerAllowedLocked(remote)
}
func (b *LocalBackend) peerIdentitySourceAllowed(local, remote key.NodePublic, src netip.Addr) bool {
	nb := b.currentNode()
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.packetLocalAllowedLocked(local) && nb.packetSourceAllowedLocked(remote, src)
}
func (nb *nodeBackend) packetLocalAllowedLocked(k key.NodePublic) bool {
	if k.IsZero() || nb.netMap == nil {
		return false
	}
	self := nb.netMap.SelfNode
	return self.Valid() && !self.Expired() && self.Key() == k
}
func (nb *nodeBackend) packetPeerAllowedLocked(k key.NodePublic) bool {
	if nb.netMap == nil {
		return false
	}
	self := nb.netMap.SelfNode
	if !self.Valid() || self.Expired() || self.Key() == k {
		return false
	}
	id, ok := nb.nodeByKey[k]
	if !ok {
		return false
	}
	p, ok := nb.peers[id]
	return ok && p.Valid() && !p.Expired() && p.Key() == k
}

// Source ownership differs from outbound next-hop selection. All eligible
// contributors at the most-specific prefix are allowed (including equal-prefix
// HA routers); a broad/default route cannot impersonate more-specific peers.
// The source table includes every netmap peer, not only QUIC-pinned peers.
func (nb *nodeBackend) packetSourceAllowedLocked(k key.NodePublic, src netip.Addr) bool {
	if !nb.packetPeerAllowedLocked(k) || !src.IsValid() || src.Is4In6() {
		return false
	}
	for _, pfx := range nb.netMap.SelfNode.Addresses().All() {
		if pfx.Contains(src) {
			return false
		}
	}
	if owner, ok := nb.nodeByAddr[src]; ok {
		id, known := nb.nodeByKey[k]
		if !known || owner != id {
			return false
		}
	}
	return nb.routeMgr.SourceAllowed(k, src)
}

// These focused accessors also support source-policy regression tests; packet
// engines use the paired-identity checks above, not independent calls to these.
func (b *LocalBackend) localDataPlaneAllowed(k key.NodePublic) bool {
	nb := b.currentNode()
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.packetLocalAllowedLocked(k)
}
func (b *LocalBackend) peerDataPlaneAllowed(k key.NodePublic) bool {
	nb := b.currentNode()
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.packetPeerAllowedLocked(k)
}
func (b *LocalBackend) peerSourceAllowed(k key.NodePublic, src netip.Addr) bool {
	nb := b.currentNode()
	nb.mu.Lock()
	defer nb.mu.Unlock()
	return nb.packetSourceAllowedLocked(k, src)
}
