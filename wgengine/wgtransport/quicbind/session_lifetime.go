// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"net/http"
	"time"

	"tailscale.com/wgengine/wgtransport"
)

// sessionLifetimeHeader lets both ends agree to keep one QUIC connection for
// hours instead of replacing it every two minutes. A peer that does not echo
// it keeps the original short lifetime, which it still enforces on its side.
const sessionLifetimeHeader = "Tailnet-Session-Lifetime"
const sessionLifetimeLong = "long"

// earlyDataHeader is sent by a responder that accepts tunnel packets in the
// first flight of a resumed connection.
const earlyDataHeader = "Tailnet-Early-Data"

func wantsLongSession(h http.Header) bool {
	return h.Get(sessionLifetimeHeader) == sessionLifetimeLong && len(h.Values(sessionLifetimeHeader)) == 1
}

// refresh and expire are the lifetime every peer understands. longRefresh and
// longExpire apply to a session whose two ends both asked for a long lifetime;
// zero keeps the short values.
type sessionTiming struct {
	refresh, expire, overlap, idle, tick, authTimeout time.Duration
	longRefresh, longExpire                           time.Duration
}

// Replacing the whole connection every two minutes discards the congestion
// and path state of a busy tunnel, reorders packets across the handover, and
// shows an observer a fresh handshake between the same two addresses at a
// fixed period. TLS 1.3 key updates already rotate the packet keys of a
// long connection, so a negotiated session lives for hours. The periodic
// replacement that remains also renews the resumption ticket, which is valid
// for a day.
func defaultSessionTiming() sessionTiming {
	return sessionTiming{
		refresh: 120 * time.Second, expire: 180 * time.Second, overlap: 3 * time.Second,
		idle: 2 * time.Minute, tick: time.Second, authTimeout: 8 * time.Second,
		longRefresh: 8 * time.Hour, longExpire: 8*time.Hour + 30*time.Minute,
	}
}

// lifetime returns the refresh and expiry ages that apply to s.
func (t sessionTiming) lifetime(s *session) (refresh, expire time.Duration) {
	if s.longLived.Load() && t.longRefresh > 0 && t.longExpire > 0 {
		return t.longRefresh, t.longExpire
	}
	return t.refresh, t.expire
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
		activeStreams := p.session != nil && p.session.tcpActive.Load() > 0
		idle := now.Sub(time.Unix(0, p.lastActivity.Load())) >= g.b.timing.idle && len(p.tx) == 0 && !p.connectingPacket.Load() && p.dialing == nil && !activeStreams
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
		p.notePacketSize(s, now)
		if g.b.factory.cfg.TCPStreams {
			// Reliable streams cannot migrate to a replacement QUIC connection.
			// Embedded CONNECT proxies use QUIC's ordinary packet-key updates
			// and peer-revocation handling, not the IP tunnel's periodic full
			// TLS connection replacement (which would truncate live SSH/files).
			continue
		}
		age := now.Sub(s.created)
		refresh, expire := g.b.timing.lifetime(s)
		if age >= expire {
			s.q.CloseWithError(0, "session key lifetime reached")
			continue
		}
		if s.outgoing && !dialing && age >= refresh && now.UnixNano() >= s.nextRefresh.Load() {
			s.nextRefresh.Store(now.Add(5 * time.Second).UnixNano())
			g.workers.Add(1)
			go func() { defer g.workers.Done(); _, _ = p.getSessionReplacing(s) }()
		}
	}
}
