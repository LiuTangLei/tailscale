// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type admissionContextKey struct{}
type admissionGate struct {
	mu                      sync.Mutex
	total, limit, perSource int
	sources                 map[string]int
}
type admissionTicket struct {
	gate     *admissionGate
	source   string
	once     sync.Once
	mu       sync.Mutex
	released bool
	timer    *time.Timer
}

func newAdmissionGate(limit, perSource int) *admissionGate {
	return &admissionGate{limit: limit, perSource: perSource, sources: make(map[string]int)}
}
func admissionSource(a net.Addr) string {
	if u, ok := a.(*net.UDPAddr); ok {
		return u.IP.String()
	}
	return a.Network() + ":" + a.String() // magicsock uses the original logical endpoint
}
func (g *admissionGate) acquire(source string) *admissionTicket {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.total >= g.limit || g.sources[source] >= g.perSource {
		return nil
	}
	g.total++
	g.sources[source]++
	return &admissionTicket{gate: g, source: source}
}
func (t *admissionTicket) release() {
	t.once.Do(func() {
		t.mu.Lock()
		t.released = true
		if t.timer != nil {
			t.timer.Stop()
		}
		t.mu.Unlock()
		g := t.gate
		g.mu.Lock()
		g.total--
		g.sources[t.source]--
		if g.sources[t.source] == 0 {
			delete(g.sources, t.source)
		}
		g.mu.Unlock()
	})
}
func releaseAdmission(q *quic.Conn) {
	if t, ok := q.Context().Value(admissionContextKey{}).(*admissionTicket); ok {
		t.release()
	}
}
func armAdmissionDeadline(q *quic.Conn, d time.Duration) {
	t, ok := q.Context().Value(admissionContextKey{}).(*admissionTicket)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.released {
		return
	}
	t.timer = time.AfterFunc(d, func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if !t.released {
			q.CloseWithError(1, "node authentication deadline")
		}
	})
}
