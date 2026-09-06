// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"errors"
	"net"
	"time"
)

// ConnectionRole describes the LOCAL endpoint's handshake policy for one peer,
// not its traffic direction, physical location, NAT type or Tailnet permission.
// Mesh preserves the existing bidirectional, on-demand connection behavior.
// Client proactively establishes an authenticated HTTP/3 tunnel, even if the
// first inner IP packet will be sent by the remote application. Server waits
// for that connection and NEVER silently initiates the opposite TLS role.
// Peers must be configured with complementary client/server policies, or mesh.
// A node can be a client of A, a server for B, and a mesh peer of C at once.
type ConnectionRole string

const (
	RoleMesh   ConnectionRole = "mesh"
	RoleClient ConnectionRole = "client"
	RoleServer ConnectionRole = "server"
)

var (
	ErrConnectionRole = errors.New("HTTP/3 peer handshake role conflicts with local policy")
	ErrAwaitingClient = errors.New("HTTP/3 server role is waiting for the peer to initiate; verify its client role and connectivity")
)

func normalizeRole(r ConnectionRole) (ConnectionRole, error) {
	switch r {
	case "", RoleMesh:
		return RoleMesh, nil
	case RoleClient, RoleServer:
		return r, nil
	default:
		return "", errors.New("connection_role must be mesh, client or server (local perspective)")
	}
}

func (r ConnectionRole) permits(outgoing bool) bool {
	return r == "" || r == RoleMesh || (r == RoleClient && outgoing) || (r == RoleServer && !outgoing)
}

func (f *Factory) needsListener() bool {
	for _, p := range f.peers {
		if p.role.permits(false) {
			return true
		}
	}
	return false
}

// signalSessionLocked wakes a waiter on either successful authentication or
// reset. A wakeup is not authorization: waitForIncoming rechecks live policy.
func (p *peer) signalSessionLocked() {
	if p.sessionChanged != nil {
		close(p.sessionChanged)
	}
	p.sessionChanged = make(chan struct{})
}

func (p *peer) waitForIncoming() (*session, error) {
	ctx, cancel := context.WithTimeout(p.g.ctx, 10*time.Second)
	defer cancel()
	for {
		if !p.g.b.identityOK.Load() {
			return nil, ErrIdentity
		}
		if p.disabled.Load() || !p.g.b.peerAllowed(p.cfg.key) {
			return nil, ErrUnknownPeer
		}
		p.mu.Lock()
		s := p.session
		if s != nil && s.q.Context().Err() == nil {
			p.mu.Unlock()
			return s, nil
		}
		if p.sessionChanged == nil {
			p.sessionChanged = make(chan struct{})
		}
		changed := p.sessionChanged
		p.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			if p.g.ctx.Err() != nil {
				return nil, net.ErrClosed
			}
			return nil, ErrAwaitingClient
		}
	}
}

// maintainClients does not probe arbitrary hosts or open an extra socket. Only
// explicitly configured client-role peers that remain authorized by the host
// are warmed. Default mesh peers remain lazy. One backend timer schedules the
// existing per-peer actors; a global semaphore bounds concurrent TLS work.
func (g *generation) maintainClients() {
	defer g.workers.Done()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	// Let the host finish installing the initial peer/path map before the
	// first warmup. This is a control-path delay, not per-packet padding.
	select {
	case <-g.ctx.Done():
		return
	case <-tick.C:
	}
	for {
		if g.b.identityOK.Load() && g.b.networkUp.Load() {
			for k, cfg := range g.b.factory.peers {
				if cfg.role != RoleClient || !g.b.peerAllowed(k) {
					continue
				}
				p, err := g.peer(k, nil)
				if err != nil {
					continue
				}
				select {
				case p.maintain <- struct{}{}:
				default:
				}
			}
		}
		select {
		case <-g.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (p *peer) maintainClient() {
	if p.cfg.role != RoleClient || !p.g.b.identityOK.Load() || !p.g.b.networkUp.Load() || p.disabled.Load() || !p.g.b.peerAllowed(p.cfg.key) {
		return
	}
	p.mu.Lock()
	live := p.session != nil && p.session.q.Context().Err() == nil
	next := p.nextMaintain
	p.mu.Unlock()
	if live || time.Now().Before(next) {
		return
	}
	_, err := p.getSession()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		p.maintainFailures = 0
		p.nextMaintain = time.Time{}
		return
	}
	p.maintainFailures = min(p.maintainFailures+1, 5)
	// Bounded exponential backoff plus stable per-peer jitter; no synchronized
	// global reconnect storm and no fingerprint-dependent data-path delay.
	delay := time.Second*time.Duration(1<<p.maintainFailures) + time.Millisecond*time.Duration(p.cfg.key[0])*4
	p.nextMaintain = time.Now().Add(delay)
}
