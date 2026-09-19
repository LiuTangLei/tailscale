// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"time"

	"tailscale.com/wgengine/wgtransport"
)

type sessionTiming struct{ refresh, expire, overlap, idle, tick, authTimeout time.Duration }

func defaultSessionTiming() sessionTiming {
	return sessionTiming{120 * time.Second, 180 * time.Second, 3 * time.Second, 2 * time.Minute, time.Second, 8 * time.Second}
}
func (p *peer) touch() { p.lastActivity.Store(time.Now().UnixNano()) }

// A complete new QUIC/TLS handshake supplies fresh DH entropy. Packet key
// updates alone cannot do that. Only the current TLS initiator refreshes;
// ordinary sends keep using the authenticated old connection during the dial.
func (g *generation) maintainSessions() {
	defer g.workers.Done()
	t := time.NewTicker(g.b.timing.tick)
	defer t.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case now := <-t.C:
			g.maintainAt(now)
		}
	}
}
func (g *generation) maintainAt(now time.Time) {
	g.peersMu.Lock()
	var peers, retired []*peer
	for k, p := range g.peers {
		p.queueMu.Lock()
		p.mu.Lock()
		idle := now.Sub(time.Unix(0, p.lastActivity.Load())) >= g.b.timing.idle && len(p.tx) == 0 && !p.connectingPacket.Load() && p.dialing == nil
		if idle && !p.retired.Load() {
			p.retired.Store(true)
			p.epoch.Add(1)
			p.cancel()
			delete(g.peers, k)
			retired = append(retired, p)
			g.b.forgetServerHint(k)
		} else {
			peers = append(peers, p)
		}
		p.mu.Unlock()
		p.queueMu.Unlock()
	}
	g.peersMu.Unlock()
	for _, p := range retired {
		g.b.eventMu.Lock()
		g.peersMu.Lock()
		absent := g.peers[p.cfg.key] == nil
		g.peersMu.Unlock()
		if absent && g.ctx.Err() == nil {
			g.b.notify(p.cfg.key, wgtransport.SessionNone)
		}
		g.b.eventMu.Unlock()
	}
	for _, p := range peers {
		p.mu.Lock()
		s := p.session
		dialing := p.dialing != nil
		p.mu.Unlock()
		if s == nil || s.q.Context().Err() != nil {
			continue
		}
		age := now.Sub(s.created)
		if age >= g.b.timing.expire {
			s.q.CloseWithError(0, "session key lifetime reached")
			continue
		}
		if s.outgoing && !dialing && age >= g.b.timing.refresh && now.UnixNano() >= s.nextRefresh.Load() {
			s.nextRefresh.Store(now.Add(5 * time.Second).UnixNano())
			g.workers.Add(1)
			go func() { defer g.workers.Done(); _, _ = p.getSessionReplacing(s) }()
		}
	}
}
