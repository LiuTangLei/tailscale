// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"errors"
	"tailscale.com/wgengine/wgtransport/nodeauth"
)

var errTransportNodeAuth = errors.New("H3 node identity is unavailable or no longer authorized")

func (e *userspaceEngine) transportNodePublic() [32]byte {
	p := e.packetIdentity.Load()
	if p == nil || p.IsZero() {
		return [32]byte{}
	}
	return p.Raw32()
}

func (e *userspaceEngine) transportNodeHandshake(local, peer [32]byte, initiator bool, binding []byte) (nodeauth.Handshake, error) {
	k := e.packetPrivate.Load()
	if k == nil {
		return nil, errTransportNodeAuth
	}
	valid := func(remote [32]byte) bool {
		return e.packetPrivate.Load() == k && !k.IsZero() && e.transportNodePublic() == local && k.Public().Raw32() == local &&
			(remote == ([32]byte{}) || (remote != local && e.peerCurrentlyAllowed(keyFromRaw(remote))))
	}
	return nodeauth.New(*k, peer, initiator, binding, valid)
}
