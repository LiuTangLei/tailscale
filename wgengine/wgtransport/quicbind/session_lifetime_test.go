// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"context"
	"encoding/hex"
	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/types/key"
	"testing"
	"time"
)

func TestAutoTrustSessionRefreshKeepsTraffic(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	for _, b := range pair.backends {
		b.timing = sessionTiming{120 * time.Millisecond, 2 * time.Second, 100 * time.Millisecond, time.Minute, 10 * time.Millisecond, time.Second}
	}
	fns := pair.open(t)
	remote := pair.keys[1].Public().Raw32()
	p, err := pair.backends[0].active.Load().peer(remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	old, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		data := bytes.Repeat([]byte{byte(i)}, 800)
		if err := pair.backends[0].Bind().Send([][]byte{data}, ep, 0); err != nil {
			t.Fatal(err)
		}
		if got := readOne(t, fns[1]); !bytes.Equal(got, data) {
			t.Fatal("refresh corrupted datagram")
		}
		time.Sleep(20 * time.Millisecond)
	}
	now, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	if now.q == old.q {
		t.Fatal("no fresh full TLS session")
	}
	select {
	case <-old.q.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("old session retained past overlap")
	}
	for _, b := range pair.backends {
		if b.counters.Connections.Load() < 2 {
			t.Fatal("refresh did not authenticate on both sides")
		}
	}
}
func TestAutoTrustIdleHistoryBeyondPeerLimit(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	pair.open(t)
	g := pair.backends[0].active.Load()
	for range maxPeers + 44 {
		pub := key.NewNode().Public().Raw32()
		base, err := pair.bases[0].Bind.ParseEndpoint("127.0.0.1:9")
		if err != nil {
			t.Fatal(err)
		}
		p, err := g.peer(pub, base)
		if err != nil {
			t.Fatal(err)
		}
		stamp := p.lifecycleStamp()
		p.lastActivity.Store(time.Now().Add(-3 * time.Minute).UnixNano())
		g.maintainAt(time.Now())
		if !p.retired.Load() || p.stampValid(stamp) {
			t.Fatal("idle actor references can be revived")
		}
		select {
		case <-p.done:
		case <-time.After(time.Second):
			t.Fatal("idle actor worker leaked")
		}
	}
	g.peersMu.Lock()
	n := len(g.peers)
	g.peersMu.Unlock()
	if n != 0 {
		t.Fatalf("retained %d idle actors", n)
	}
}
func TestAdmissionBudgetReleaseAndFairness(t *testing.T) {
	g := newAdmissionGate(3, 2)
	a, b := g.acquire("one"), g.acquire("one")
	if a == nil || b == nil || g.acquire("one") != nil {
		t.Fatal("per-source budget")
	}
	c := g.acquire("two")
	if c == nil || g.acquire("three") != nil {
		t.Fatal("global budget")
	}
	a.release()
	a.release()
	d := g.acquire("three")
	if d == nil {
		t.Fatal("authenticated slot not released")
	}
	b.release()
	c.release()
	d.release()
	if g.total != 0 || len(g.sources) != 0 {
		t.Fatal("admission identities retained")
	}
}

func TestAutoTrustProvisionalTLSExpires(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	pair.backends[1].timing.authTimeout = 100 * time.Millisecond
	pair.open(t)
	a := pair.backends[0]
	remote := pair.keys[1].Public().Raw32()
	p, err := a.active.Load().peer(remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	q, err := a.active.Load().transport.Dial(ctx, &bindAddr{ep: p.ep.Load().Endpoint}, a.tlsConfig(&remote), a.quicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer q.CloseWithError(0, "test complete")
	select {
	case <-q.Context().Done():
	case <-ctx.Done():
		t.Fatal("TLS-only client retained a provisional connection")
	}
	if pair.backends[1].counters.Connections.Load() != 0 {
		t.Fatal("TLS-only connection authorized")
	}
}
func TestAutoTrustSessionHardExpiry(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	for _, b := range pair.backends {
		b.timing.refresh = time.Hour
		b.timing.expire = 100 * time.Millisecond
		b.timing.tick = 10 * time.Millisecond
	}
	pair.open(t)
	p, err := pair.backends[0].active.Load().peer(pair.keys[1].Public().Raw32(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.q.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("old traffic secret used past lifetime without fresh TLS")
	}
	next, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	if next.q == s.q {
		t.Fatal("expired session reused")
	}
}
func TestGrowingReceivePreservesHeadroomAndGeneration(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	pair.open(t)
	b := pair.backends[0]
	g := b.active.Load()
	p, err := g.peer(pair.keys[1].Public().Raw32(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte{7}, 60000)
	g.rxBytes.Add(int64(len(want)))
	g.rx <- received{data: want, peer: p, ep: p.ep.Load(), stamp: p.lifecycleStamp()}
	bufs := [][]byte{bytes.Repeat([]byte{0xaa}, 2064)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := g.receivePackets(bufs, sizes, eps, 16, true)
	if err != nil || n != 1 || !bytes.Equal(bufs[0][16:16+sizes[0]], want) {
		t.Fatal("large inner datagram truncated", err)
	}
	if len(bufs[0]) != 16+len(want) {
		t.Fatal("missing TUN headroom")
	}
	if err := b.Bind().Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.bind.OpenIP(0, 16); err != nil {
		t.Fatal(err)
	}
	if _, err := g.receivePackets(bufs, sizes, eps, 16, true); err == nil {
		t.Fatal("old receive function crossed generation boundary")
	}
}
