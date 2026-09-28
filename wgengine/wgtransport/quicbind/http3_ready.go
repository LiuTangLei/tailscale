// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"time"

	quic "github.com/quic-go/quic-go"
)

// HTTP/3 runs requests concurrently. A client can receive CONNECT-IP's final
// authentication bytes and open a TCP stream before its server handler has
// installed the session. Wait only for an already admitted CONNECT-IP on this
// exact connection; an arbitrary unauthenticated CONNECT must not park here.
// Readiness is not authorization: the caller must still look up the installed
// session and check its current lifecycle stamp and target policy.
func (g *generation) waitHTTPTunnel(ctx context.Context, q *quic.Conn) bool {
	g.h3.mu.Lock()
	ready := g.h3.tunnels[q]
	g.h3.mu.Unlock()
	if ready == nil {
		return false
	}
	timer := time.NewTimer(g.b.timing.authTimeout)
	defer timer.Stop()
	select {
	case <-ready:
		return ctx.Err() == nil && g.ctx.Err() == nil
	case <-ctx.Done():
	case <-g.ctx.Done():
	case <-timer.C:
	}
	return false
}
