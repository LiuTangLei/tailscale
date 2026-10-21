// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/quic-go/quic-go/quicvarint"
	"tailscale.com/wgengine/wgtransport/nodeauth"
)

// Withhold only client Handshake packets. Real 0-RTT and 1-RTT application
// packets still reach the server, so the test exercises its admission gate.
type holdTLSFinishedSocket struct {
	net.PacketConn
	mu          sync.Mutex
	hold        bool
	pending     [][]byte
	destination net.Addr
}

func (s *holdTLSFinishedSocket) WriteTo(data []byte, a net.Addr) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hold {
		return s.PacketConn.WriteTo(data, a)
	}
	var forward []byte
	for rest := data; len(rest) > 0; {
		if rest[0]&0x80 == 0 {
			forward = append(forward, rest...)
			break
		}
		r := bytes.NewReader(rest)
		r.Seek(5, 0)
		dl, e := r.ReadByte()
		if e != nil {
			return 0, e
		}
		r.Seek(int64(dl), 1)
		sl, e := r.ReadByte()
		if e != nil {
			return 0, e
		}
		r.Seek(int64(sl), 1)
		kind := (rest[0] >> 4) & 3
		if kind == 0 {
			token, e := quicvarint.Read(r)
			if e != nil {
				return 0, e
			}
			r.Seek(int64(token), 1)
		}
		length, e := quicvarint.Read(r)
		if e != nil {
			return 0, e
		}
		n := len(rest) - r.Len() + int(length)
		if n > len(rest) {
			return 0, io.ErrUnexpectedEOF
		}
		if kind == 2 {
			s.pending = append(s.pending, bytes.Clone(rest[:n]))
			s.destination = a
		} else {
			forward = append(forward, rest[:n]...)
		}
		rest = rest[n:]
	}
	if len(forward) > 0 {
		if _, e := s.PacketConn.WriteTo(forward, a); e != nil {
			return 0, e
		}
	}
	return len(data), nil
}
func (s *holdTLSFinishedSocket) release() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hold = false
	for _, p := range s.pending {
		if _, e := s.PacketConn.WriteTo(p, s.destination); e != nil {
			return e
		}
	}
	s.pending = nil
	return nil
}

func TestZeroRTTBusinessWaitsForClientFinished(t *testing.T) {
	pair := newTestPair(t, "http3-udp")
	client, server := pair.backends[0], pair.backends[1]
	var gate *holdTLSFinishedSocket
	original := client.host.ListenPacket
	client.host.ListenPacket = func(ctx context.Context, n, a string) (net.PacketConn, error) {
		pc, e := original(ctx, n, a)
		if e != nil {
			return nil, e
		}
		gate = &holdTLSFinishedSocket{PacketConn: pc}
		return gate, nil
	}
	fns := pair.open(t)
	remote := pair.keys[1].Public().Raw32()
	p, e := client.active.Load().peer(remote, nil)
	if e != nil {
		t.Fatal(e)
	}
	first, e := p.getSession()
	if e != nil {
		t.Fatal(e)
	}
	waitTicket(t, client.clientSessionCache(remote))
	gate.mu.Lock()
	gate.hold = true
	gate.mu.Unlock()
	defer gate.release()
	resumed, e := p.getSessionContext(t.Context(), first)
	if e != nil {
		t.Fatal(e)
	}
	if !resumed.q.ConnectionState().Used0RTT {
		t.Fatal("test did not use real early data")
	}
	ep, e := client.Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte("business must wait for client Finished")
	if e := client.Bind().Send([][]byte{payload}, ep, 0); e != nil {
		t.Fatal(e)
	}
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, maxPacket)
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		if _, e := receiveTestSlots(fns[1], [][]byte{buf}, sizes, eps); e == nil {
			got <- bytes.Clone(buf[:sizes[0]])
		}
	}()
	select {
	case <-got:
		t.Fatal("business was delivered before TLS Finished")
	case <-time.After(80 * time.Millisecond):
	}
	if server.counters.ZeroRTTAccepted.Load() != 0 || server.counters.HTTP3Tunnels.Load() != 1 {
		t.Fatal("server admitted early tunnel before TLS Finished")
	}
	gate.mu.Lock()
	held := len(gate.pending)
	gate.mu.Unlock()
	if held == 0 {
		t.Fatal("test did not withhold client Finished")
	}
	if e := gate.release(); e != nil {
		t.Fatal(e)
	}
	select {
	case data := <-got:
		if !bytes.Equal(data, payload) {
			t.Fatal("business changed after admission")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("business not released after TLS Finished")
	}
}

type ticketRecordingSocket struct {
	net.PacketConn
	mu        sync.Mutex
	recording bool
	packets   [][]byte
}

func (s *ticketRecordingSocket) WriteTo(p []byte, a net.Addr) (int, error) {
	s.mu.Lock()
	if s.recording {
		s.packets = append(s.packets, bytes.Clone(p))
	}
	s.mu.Unlock()
	return s.PacketConn.WriteTo(p, a)
}

func TestZeroRTTRestartAndWireReplay(t *testing.T) {
	pair := newTestPair(t, "http3-udp")
	var recorder *ticketRecordingSocket
	original := pair.backends[0].host.ListenPacket
	pair.backends[0].host.ListenPacket = func(ctx context.Context, n, a string) (net.PacketConn, error) {
		pc, e := original(ctx, n, a)
		if e != nil {
			return nil, e
		}
		recorder = &ticketRecordingSocket{PacketConn: pc}
		return recorder, nil
	}
	pair.open(t)
	b := pair.backends[0]
	remote := pair.keys[1].Public().Raw32()
	p, e := b.active.Load().peer(remote, nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	first, e := p.getSessionContext(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	cache := b.clientSessionCache(remote)
	waitTicket(t, cache)
	restart := func() {
		old := pair.backends[1]
		if e := old.Close(); e != nil {
			t.Fatal(e)
		}
		next, e := old.factory.New(old.host)
		if e != nil {
			t.Fatal(e)
		}
		server := next.(*Backend)
		pair.backends[1] = server
		t.Cleanup(func() { server.Close() })
		server.LocalIdentityChanged(remote)
		if _, _, e := server.Bind().Open(0); e != nil {
			t.Fatal(e)
		}
	}
	restart() // Unused, authorized tickets survive a full backend restart.
	recorder.mu.Lock()
	recorder.recording = true
	recorder.mu.Unlock()
	resumed, e := p.getSessionContext(ctx, first)
	if e != nil {
		t.Fatal(e)
	}
	if !resumed.q.ConnectionState().Used0RTT {
		t.Fatal("durable ticket did not resume after restart")
	}
	waitTicket(t, cache)
	recorder.mu.Lock()
	recorder.recording = false
	captured := recorder.packets
	recorder.mu.Unlock()
	if len(captured) == 0 {
		t.Fatal("no wire packets captured")
	}
	restart() // The same captured ticket is now durably consumed.
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	dst, e := net.ResolveUDPAddr("udp", pair.backends[1].factory.cfg.Listen)
	if e != nil {
		t.Fatal(e)
	}
	for range 2 {
		for _, data := range captured {
			if _, e := pc.WriteTo(data, dst); e != nil {
				t.Fatal(e)
			}
		}
	}
	time.Sleep(200 * time.Millisecond)
	server := pair.backends[1]
	if server.counters.HTTP3Tunnels.Load() != 0 || server.counters.ReceivedPackets.Load() != 0 || server.counters.ZeroRTTAccepted.Load() != 0 {
		t.Fatal("captured 0-RTT authorized a tunnel or delivered business packets after restart")
	}
	// The next unused replacement ticket remains usable despite rejected replay.
	again, e := p.getSessionContext(ctx, resumed)
	if e != nil {
		t.Fatal(e)
	}
	if !again.q.ConnectionState().Used0RTT {
		t.Fatal("wire replay damaged the next unused ticket")
	}
}

func waitTicket(t testing.TB, cache *peerSessionCache) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cache.mu.Lock()
		ready := cache.ticket != nil
		cache.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("authenticated ticket was not received")
}

func TestZeroRTTRevocationDuringPSKUnwrap(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	b, server := pair.backends[0], pair.backends[1]
	entered, release := make(chan struct{}), make(chan struct{})
	var once, armed atomic.Bool
	// Pause the live-policy check inside UnwrapSession, then remove/re-add the
	// peer. A cached identity may not acquire the new authorization epoch.
	original := server.host.PeerAllowed
	server.host.PeerAllowed = func(k [32]byte) bool {
		if armed.Load() && once.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return original(k)
	}
	pair.open(t)
	remote := pair.keys[1].Public().Raw32()
	p, e := b.active.Load().peer(remote, nil)
	if e != nil {
		t.Fatal(e)
	}
	first, e := p.getSession()
	if e != nil {
		t.Fatal(e)
	}
	waitTicket(t, b.clientSessionCache(remote))
	armed.Store(true)
	done := make(chan error, 1)
	go func() { _, e := p.getSessionContext(t.Context(), first); done <- e }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("resumption did not reach policy check")
	}
	oldEpoch := server.authEpoch.Load()
	revoked := make(chan struct{})
	go func() { server.PeerRemoved(pair.keys[0].Public().Raw32()); close(revoked) }()
	for server.authEpoch.Load() == oldEpoch {
		time.Sleep(time.Millisecond)
	}
	close(release)
	<-revoked
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revocation reconnect timed out")
	}
	if server.counters.ResumeAuthRejected.Load() != 1 || b.counters.ZeroRTTAccepted.Load() != 0 || b.counters.ZeroRTTRejected.Load() != 1 {
		t.Fatal("pre-revocation PSK acquired new authorization")
	}
}

func TestAuthenticatedZeroRTTAndRejectionReconnect(t *testing.T) {
	for _, browser := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard", true: "chromium"}[browser], func(t *testing.T) {
			index := 0
			pair := newTestPair(t, "http3-magicsock", func(c *Config) {
				c.AutoTrust, c.Peers = true, nil
				c.Server = browser && index == 1
				index++
			})
			var handshakes atomic.Int32
			for _, b := range pair.backends {
				original := b.host.NodeHandshake
				b.host.NodeHandshake = func(l, r [32]byte, i bool, binding []byte) (nodeauth.Handshake, error) {
					handshakes.Add(1)
					return original(l, r, i, binding)
				}
			}
			pair.open(t)
			b := pair.backends[0]
			remote := pair.keys[1].Public().Raw32()
			p, err := b.active.Load().peer(remote, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			first, err := p.getSessionContext(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			cache := b.clientSessionCache(remote)
			waitTicket(t, cache)
			calls := handshakes.Load()
			if calls != 2 {
				t.Fatalf("initial full authentication calls: %d", calls)
			}
			resumed, err := p.getSessionContext(ctx, first)
			if err != nil {
				t.Fatal(err)
			}
			if resumed == first || !resumed.q.ConnectionState().Used0RTT || !resumed.q.ConnectionState().TLS.DidResume {
				t.Fatal("replacement did not use real TLS 0-RTT")
			}
			if handshakes.Load() != calls {
				t.Fatal("resumption unexpectedly repeated Noise authentication")
			}
			if browser && resumed.q.ConnectionState().ClientHelloProfile != "chromium-h3" {
				t.Fatal("resumption lost browser profile")
			}
			waitTicket(t, cache)
			// Losing the server journal must reject early data and perform one fresh
			// full authentication, rather than replay the failed request or payload.
			pair.backends[1].tickets.Load().revoke([32]byte{})
			before := b.counters.HandshakeAttempts.Load()
			full, err := p.getSessionContext(ctx, resumed)
			if err != nil {
				t.Fatal(err)
			}
			if full.q.ConnectionState().Used0RTT || handshakes.Load() != calls+2 {
				t.Fatal("rejected ticket did not reconnect with full node authentication")
			}
			if b.counters.HandshakeAttempts.Load()-before != 2 || b.counters.ZeroRTTRejected.Load() != 1 {
				t.Fatal("rejection did not use exactly one bounded reconnect")
			}
			if b.counters.ZeroRTTAccepted.Load() != 1 {
				t.Fatal("missing successful 0-RTT diagnostic")
			}
			waitTicket(t, cache)
			again, err := p.getSessionContext(ctx, full)
			if err != nil {
				t.Fatal(err)
			}
			if !again.q.ConnectionState().Used0RTT || handshakes.Load() != calls+2 {
				t.Fatal("full reconnect failed to replenish its authenticated ticket")
			}
		})
	}
}

func TestJournalFailureKeepsAuthenticatedUDPUsable(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	fns := pair.open(t)
	client, server := pair.backends[0], pair.backends[1]
	remote := pair.keys[1].Public().Raw32()
	p, e := client.active.Load().peer(remote, nil)
	if e != nil {
		t.Fatal(e)
	}
	first, e := p.getSession()
	if e != nil {
		t.Fatal(e)
	}
	cache := client.clientSessionCache(remote)
	waitTicket(t, cache)
	store := server.tickets.Load()
	store.mu.Lock()
	if store.file == nil {
		store.mu.Unlock()
		t.Skip("durable journals unsupported on this filesystem")
	}
	store.file.Close()
	store.mu.Unlock()
	full, e := p.getSessionContext(t.Context(), first)
	if e != nil {
		t.Fatal(e)
	}
	if full.q.ConnectionState().TLS.DidResume {
		t.Fatal("failed durable consumption accepted a PSK")
	}
	store.mu.Lock()
	disabled := store.disabled
	store.mu.Unlock()
	if !disabled {
		t.Fatal("failed journal remains enabled")
	}
	ep, e := client.Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
	if e != nil {
		t.Fatal(e)
	}
	payload := []byte("UDP after journal failure")
	if e := client.Bind().Send([][]byte{payload}, ep, 0); e != nil {
		t.Fatal(e)
	}
	if got := readOne(t, fns[1]); !bytes.Equal(got, payload) {
		t.Fatal("journal failure affected authenticated UDP")
	}
	// No unusable ticket should be replenished after the failure. The next
	// connection is a direct full handshake, with no failed early detour.
	before := client.counters.HandshakeAttempts.Load()
	if _, e := p.getSessionContext(t.Context(), full); e != nil {
		t.Fatal(e)
	}
	if client.counters.HandshakeAttempts.Load()-before != 1 {
		t.Fatal("disabled journal caused another rejected early detour")
	}
}
