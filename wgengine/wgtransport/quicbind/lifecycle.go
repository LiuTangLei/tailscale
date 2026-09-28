// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

// lifecycleStamp is carried with queued work, not on the wire. A node or Peer
// becoming allowed again must not resurrect packets from before its reset.
// Rechecks are atomic and allocate nothing on the data path.
type lifecycleStamp struct {
	identity uint64
	peer     uint64
}

func (p *peer) lifecycleStamp() lifecycleStamp {
	return lifecycleStamp{identity: p.g.b.identityEpoch.Load(), peer: p.epoch.Load()}
}

// stampCurrent is only an atomic queue-admission check. It is NOT permission
// to deliver IP data: dequeue and the IP engine must still call stampValid /
// current peer and source policy before releasing data to the TUN.
func (p *peer) stampCurrent(s lifecycleStamp) bool {
	b := p.g.b
	return b.identityOK.Load() && !p.disabled.Load() && !p.retired.Load() && s.identity == b.identityEpoch.Load() && s.peer == p.epoch.Load()
}

func (p *peer) stampValid(s lifecycleStamp) bool {
	return p.stampCurrent(s) && p.g.b.peerAllowed(p.cfg.key)
}
