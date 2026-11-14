// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"tailscale.com/wgengine/wgtransport/nodeauth"
)

// resumablePair returns an established pair whose client holds a ticket and
// whose server no longer holds a session: the state after an idle period.
func resumablePair(t *testing.T, options ...func(*Config)) (pair *testPair, p *peer, send func([]byte), receive func() []byte) {
	t.Helper()
	pair = newTestPair(t, "http3-magicsock", options...)
	fns := pair.open(t)
	client, server := pair.backends[0], pair.backends[1]
	local, remote := pair.keys[0].Public().Raw32(), pair.keys[1].Public().Raw32()
	p, err := client.active.Load().peer(remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.getSession(); err != nil {
		t.Fatal(err)
	}
	waitTicket(t, client.clientSessionCache(remote))
	p.closeSession("idle")
	serverPeer, err := server.active.Load().peer(local, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "server kept the closed session", func() bool { return !serverPeer.hasLiveSession() })
	ep, err := client.Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
	if err != nil {
		t.Fatal(err)
	}
	send = func(packet []byte) {
		t.Helper()
		if err := client.Bind().Send([][]byte{packet}, ep, 0); err != nil {
			t.Fatal(err)
		}
	}
	return pair, p, send, func() []byte { t.Helper(); return readOne(t, fns[1]) }
}

func TestEarlyTunnelCarriesLargePacketAndBecomesLongLived(t *testing.T) {
	pair, p, send, receive := resumablePair(t)
	// Larger than one datagram: uses the fragmentation extension the peer
	// agreed to before, without waiting for it to agree again.
	packet := bytes.Repeat([]byte{0x45}, 3000)
	send(packet)
	if got := receive(); !bytes.Equal(got, packet) {
		t.Fatal("first-flight packet changed")
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	if s.dgram.(*http3Channel).confirmed == nil {
		t.Fatal("resumption waited for the answer")
	}
	waitEstablished(t, s)
	client := pair.backends[0]
	if !s.q.ConnectionState().Used0RTT || client.counters.ZeroRTTAccepted.Load() != 1 || client.counters.ZeroRTTRejected.Load() != 0 {
		t.Fatal("test did not use accepted early data")
	}
	if !s.longLived.Load() {
		t.Fatal("resumed session lost the long lifetime")
	}
	if s.dgram.(*http3Channel).flightOpen.Load() || s.dgram.(*http3Channel).flight != nil {
		t.Fatal("confirmed tunnel still retains its first flight")
	}
}

// A refused resumption costs no inner retransmission timeout: the full
// handshake starts at once and carries the first packets again.
func TestEarlyTunnelRefusedResendsFirstFlight(t *testing.T) {
	pair, p, send, receive := resumablePair(t)
	client, server := pair.backends[0], pair.backends[1]
	server.tickets.Load().revoke([32]byte{}) // the server lost its ticket state
	before := client.counters.HandshakeAttempts.Load()
	first, second := []byte("first packet of a refused flight"), []byte("second packet of a refused flight")
	send(first)
	send(second)
	if got := receive(); !bytes.Equal(got, first) {
		t.Fatalf("refused flight was not sent again in order: %q", got)
	}
	if got := receive(); !bytes.Equal(got, second) {
		t.Fatalf("refused flight was not sent again in order: %q", got)
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	if s.q.ConnectionState().Used0RTT || s.dgram.(*http3Channel).confirmed != nil {
		t.Fatal("refused resumption did not fall back to a full handshake")
	}
	if got := client.counters.HandshakeAttempts.Load() - before; got != 2 {
		t.Fatalf("handshake attempts after refusal: %d, want 2", got)
	}
	if client.counters.ZeroRTTRejected.Load() != 1 || client.counters.ZeroRTTAccepted.Load() != 0 || client.counters.EarlyPacketsResent.Load() != 2 {
		t.Fatal("refusal diagnostics", client.counters.ZeroRTTRejected.Load(), client.counters.EarlyPacketsResent.Load())
	}
	// The full handshake replenished the ticket; the next resumption is early.
	waitTicket(t, client.clientSessionCache(pair.keys[1].Public().Raw32()))
}

type blockedEarlyBatch struct {
	datagramChannel
	accepted, returning chan struct{}
}

func (b blockedEarlyBatch) SendDatagramsWithPrefix(_ []byte, packets [][]byte) (int, error) {
	// The queue accepted the packets, but the sender has not returned to
	// record their replay copies yet.
	close(b.accepted)
	<-b.returning
	return len(packets), nil
}

func TestEarlyFlightRejectionWaitsForAcceptedBatch(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock")
	pair.open(t)
	p, err := pair.backends[0].active.Load().peer(pair.keys[1].Public().Raw32(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	live := s.dgram.(*http3Channel)
	accepted, returning := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(returning) })
	defer release()
	channel := newEarlyHTTP3Channel(p.g, s.q, blockedEarlyBatch{live.stream, accepted, returning}, nil, true)
	candidate := &session{q: s.q, stamp: s.stamp, dgram: channel}
	packets := [][]byte{[]byte("first request"), []byte("second request")}
	sent := make(chan error, 1)
	go func() {
		p.sendMu.Lock()
		defer p.sendMu.Unlock()
		handled, err := p.sendIPBatch(candidate, packets, 0)
		if !handled && err == nil {
			err = errors.New("batch was not handled")
		}
		sent <- err
	}()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("batch was not accepted")
	}
	rejected := make(chan [][]byte, 1)
	go func() { rejected <- p.takeRejectedEarlyFlight(channel) }()
	select {
	case <-rejected:
		t.Fatal("rejection took the flight before the accepted batch was recorded")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case err := <-sent:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sender did not finish")
	}
	select {
	case flight := <-rejected:
		if len(flight) != len(packets) {
			t.Fatalf("accepted %d packets, retained %d", len(packets), len(flight))
		}
		for i := range packets {
			if !bytes.Equal(flight[i], packets[i]) {
				t.Fatal("retained batch changed or reordered")
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rejection did not finish after the sender returned")
	}
}

// A responder that does not announce first-flight support (an older build)
// keeps the exchange it understands: request, answer, then packets.
func TestEarlyTunnelRequiresResponderSupport(t *testing.T) {
	pair, p, send, receive := resumablePair(t)
	cache := pair.backends[0].clientSessionCache(pair.keys[1].Public().Raw32())
	if !cache.early.Load() {
		t.Fatal("current responder did not announce first-flight support")
	}
	cache.early.Store(false)
	packet := []byte("packet for an older responder")
	send(packet)
	if got := receive(); !bytes.Equal(got, packet) {
		t.Fatal("packet changed")
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	if s.dgram.(*http3Channel).confirmed != nil || !s.q.ConnectionState().Used0RTT {
		t.Fatal("older responder did not get the waiting resumption")
	}
	if !cache.early.Load() {
		t.Fatal("answer of a current responder was not recorded")
	}
}

func TestEarlyFlightRetentionIsBounded(t *testing.T) {
	c := new(http3Channel)
	c.retainEarly([]byte("ignored before the flight opens"))
	if c.flight != nil {
		t.Fatal("ordinary channel retained a packet")
	}
	c.flightOpen.Store(true)
	source := []byte("caller owns this buffer")
	c.retainEarly(source)
	source[0] = 'X'
	for range 2 * earlyFlightPackets {
		c.retainEarly(make([]byte, 1400))
	}
	if len(c.flight) != earlyFlightPackets || c.flightSize > earlyFlightBytes {
		t.Fatal("retention bound", len(c.flight), c.flightSize)
	}
	flight := c.takeEarly()
	if string(flight[0]) != "caller owns this buffer" {
		t.Fatal("retained packet aliases the caller's buffer or lost the oldest packet")
	}
	c.retainEarly([]byte("late"))
	if c.flight != nil || c.takeEarly() != nil {
		t.Fatal("packet retained after the flight was taken")
	}
	c.flightOpen.Store(true)
	c.retainEarly(make([]byte, earlyFlightBytes+1))
	if len(c.flight) != 0 {
		t.Fatal("oversized packet retained")
	}
}

// gatedHandshake lets a test hold back or corrupt the responder's closing
// node confirmation.
type gatedHandshake struct {
	nodeauth.Handshake
	release <-chan struct{}
	corrupt bool
}

func (h gatedHandshake) Write(plain []byte) ([]byte, error) {
	if string(plain) != "responder finished v2" {
		return h.Handshake.Write(plain)
	}
	<-h.release
	out, err := h.Handshake.Write(plain)
	if err == nil && h.corrupt {
		out[len(out)-1] ^= 1
	}
	return out, err
}

func gateResponderConfirmation(pair *testPair, corrupt bool) (release func()) {
	gate := make(chan struct{})
	original := pair.backends[1].host.NodeHandshake
	pair.backends[1].host.NodeHandshake = func(l, r [32]byte, initiator bool, binding []byte) (nodeauth.Handshake, error) {
		hs, err := original(l, r, initiator, binding)
		if err != nil || initiator {
			return hs, err
		}
		return gatedHandshake{hs, gate, corrupt}, nil
	}
	return sync.OnceFunc(func() { close(gate) })
}

// A full handshake does not spend a round trip waiting for the responder's
// closing confirmation: the reply it already verified authenticates the
// responder. The confirmation is still read and checked when it arrives.
func TestFullHandshakeDoesNotWaitForResponderConfirmation(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust, c.Peers = true, nil })
	release := gateResponderConfirmation(pair, false)
	defer release()
	fns := pair.open(t)
	remote := pair.keys[1].Public().Raw32()
	p, err := pair.backends[0].active.Load().peer(remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	s, err := p.getSessionContext(ctx, nil)
	if err != nil {
		t.Fatal("session waited for the responder confirmation:", err)
	}
	if pair.backends[1].counters.HTTP3Tunnels.Load() != 0 {
		t.Fatal("test did not hold the responder confirmation")
	}
	ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte("sent before the responder confirmation")
	if err := pair.backends[0].Bind().Send([][]byte{packet}, ep, 0); err != nil {
		t.Fatal(err)
	}
	release()
	if got := readOne(t, fns[1]); !bytes.Equal(got, packet) {
		t.Fatal("packet changed")
	}
	// The confirmation was consumed as the stream's preamble; the connection
	// and its ticket are intact.
	waitTicket(t, pair.backends[0].clientSessionCache(remote))
	if err := s.q.Context().Err(); err != nil {
		t.Fatal("valid responder confirmation closed the session:", context.Cause(s.q.Context()))
	}
	if !s.longLived.Load() {
		t.Fatal("full handshake did not negotiate the long lifetime")
	}
}

func TestInvalidResponderConfirmationClosesSession(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust, c.Peers = true, nil })
	release := gateResponderConfirmation(pair, true)
	defer release()
	pair.open(t)
	p, err := pair.backends[0].active.Load().peer(pair.keys[1].Public().Raw32(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-s.q.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session survived an invalid responder confirmation")
	}
}

// The preamble is consumed before, and never as, a capsule.
func TestCapsulePreambleOrder(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock")
	pair.open(t)
	p, err := pair.backends[0].active.Load().peer(pair.keys[1].Public().Raw32(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	preamble := []byte("PREAMBLE")
	wire := append(bytes.Clone(preamble), 0x00, 0x04, 0x00, 'a', 'b', 'c') // DATAGRAM capsule: context 0 + "abc"
	reader, writer := io.Pipe()
	defer writer.Close() // ends the capsule reader
	c := newHTTP3Channel(p.g, s.q, nil, reader, false)
	c.preamble = func(r io.Reader) error {
		got := make([]byte, len(preamble))
		if _, err := io.ReadFull(r, got); err != nil {
			return err
		}
		if !bytes.Equal(got, preamble) {
			return errors.New("preamble changed")
		}
		return nil
	}
	delivered := make(chan []byte, 1)
	c.StartCapsules(func(frame []byte) { delivered <- bytes.Clone(frame) })
	go writer.Write(wire)
	select {
	case frame := <-delivered:
		if !bytes.Equal(frame, []byte{frameRaw, 'a', 'b', 'c'}) {
			t.Fatalf("capsule after preamble: %q", frame)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("capsule after preamble was not delivered")
	}
}
