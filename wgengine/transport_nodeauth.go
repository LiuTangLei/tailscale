// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"errors"
	"tailscale.com/types/key"
)

var errTransportNodeAuth = errors.New("H3 node identity is unavailable or no longer authorized")

func (e *userspaceEngine) transportNodePublic() [32]byte {
	p := e.packetIdentity.Load()
	if p == nil || p.IsZero() {
		return [32]byte{}
	}
	return p.Raw32()
}

// Take a snapshot of the host key without exposing it to the transport. Check
// the current public identity and policy before and after each cryptographic
// operation. Bind/TLS shutdown may run concurrently with this cold path.
func (e *userspaceEngine) transportAuthKey(local, peer [32]byte) (*key.NodePrivate, error) {
	k := e.packetPrivate.Load()
	if local == ([32]byte{}) || peer == ([32]byte{}) || peer == local || k == nil || k.IsZero() || e.transportNodePublic() != local || k.Public().Raw32() != local || !e.peerCurrentlyAllowed(keyFromRaw(peer)) {
		return nil, errTransportNodeAuth
	}
	return k, nil
}
func (e *userspaceEngine) transportNodeSeal(local, peer [32]byte, msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg) > 1024 {
		return nil, errTransportNodeAuth
	}
	k, err := e.transportAuthKey(local, peer)
	if err != nil {
		return nil, err
	}
	out := k.SealTo(keyFromRaw(peer), msg)
	if current, err := e.transportAuthKey(local, peer); err != nil || current != k {
		clear(out)
		return nil, errTransportNodeAuth
	}
	return out, nil
}
func (e *userspaceEngine) transportNodeOpen(local, peer [32]byte, msg []byte) ([]byte, error) {
	if len(msg) < 40 || len(msg) > 1064 {
		return nil, errTransportNodeAuth
	}
	k, err := e.transportAuthKey(local, peer)
	if err != nil {
		return nil, err
	}
	out, ok := k.OpenFrom(keyFromRaw(peer), msg)
	if !ok {
		return nil, errTransportNodeAuth
	}
	if current, err := e.transportAuthKey(local, peer); err != nil || current != k {
		clear(out)
		return nil, errTransportNodeAuth
	}
	return out, nil
}
