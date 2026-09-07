// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// This is encrypted HTTP/3 connection metadata, not a TLS extension or public
// discovery protocol. Learn it only AFTER authenticating the exact Tailnet peer.
// Old peers omit it and continue using the unmodified H3 mesh handshake.
const serverHintHeader = "X-Transport-Server"

const (
	serverUnknown uint32 = iota
	serverNo
	serverYes
)

func serverHintValue(server bool) string {
	if server {
		return "?1"
	}
	return "?0"
}

func parseServerHint(h http.Header) (uint32, error) {
	values := h.Values(serverHintHeader)
	if len(values) == 0 {
		return serverUnknown, nil
	}
	if len(values) != 1 {
		return serverUnknown, errors.New("duplicate HTTP/3 server declaration")
	}
	switch values[0] {
	case "?0":
		return serverNo, nil
	case "?1":
		return serverYes, nil
	default:
		return serverUnknown, errors.New("invalid HTTP/3 server declaration")
	}
}

// serverHints is per-backend, not shared mutable Factory state. Slots are
// added only when a live authorized peer actor is created; the map is bounded.
func (b *Backend) initServerHints() {
	b.serverHints = make(map[[32]byte]*atomic.Uint32, len(b.factory.peers))
	for k, p := range b.factory.peers {
		h := new(atomic.Uint32)
		if p.server {
			h.Store(serverYes)
		}
		b.serverHints[k] = h
	}
}

func (b *Backend) peerServerHint(k [32]byte) uint32 {
	b.serverHintsMu.RLock()
	defer b.serverHintsMu.RUnlock()
	if h := b.serverHints[k]; h != nil {
		return h.Load()
	}
	return serverUnknown
}

func (b *Backend) forgetServerHint(k [32]byte) {
	b.serverHintsMu.Lock()
	defer b.serverHintsMu.Unlock()
	delete(b.serverHints, k)
}

func (b *Backend) ensureServerHint(k [32]byte) {
	b.serverHintsMu.Lock()
	defer b.serverHintsMu.Unlock()
	if b.serverHints[k] == nil && len(b.serverHints) < maxPeers {
		b.serverHints[k] = new(atomic.Uint32)
	}
}

// Browser profile selection is gated by the local node declaration as well as
// the authenticated remote declaration. A declared local server does not emit a
// browser-style ClientHello, and incoming connections are never treated as
// browser clients. Eligibility is only a future-dial condition, not proof that a
// browser TLS stack is actually in use.
func (b *Backend) browserProfileEligible(k [32]byte, outgoing bool) bool {
	return b.factory.cfg.HTTP3 && !b.factory.cfg.Server && outgoing && b.peerServerHint(k) == serverYes
}

func (b *Backend) browserProfileForPeer(k [32]byte, outgoing bool) string {
	if !b.browserProfileEligible(k, outgoing) {
		return ""
	}
	return "chromium-h3"
}

func http3ClientHelloServerName(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.TrimSuffix(strings.TrimSpace(u.Hostname()), ".")
	if host == "" || net.ParseIP(host) != nil || strings.HasSuffix(strings.ToLower(host), ".invalid") {
		return ""
	}
	return host
}

// Remember an authenticated CONNECT's declaration only if it still belongs to
// the current peer session and identity generation. Late/superseded responses
// cannot overwrite a fresh connection's metadata. Removal clears the hint.
func (p *peer) rememberServerHint(s *session, hint uint32) {
	if hint > serverYes || p.g.ctx.Err() != nil || p.g.b.active.Load() != p.g {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.session != s || !p.stampValid(s.stamp) || s.q.Context().Err() != nil {
		return
	}
	p.g.b.serverHintsMu.RLock()
	defer p.g.b.serverHintsMu.RUnlock()
	if h := p.g.b.serverHints[p.cfg.key]; h != nil && !p.retired.Load() {
		h.Store(hint)
	}
}
