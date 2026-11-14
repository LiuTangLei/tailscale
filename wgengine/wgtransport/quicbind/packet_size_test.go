// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"tailscale.com/types/key"
)

func TestPacketSizeHeader(t *testing.T) {
	for _, tc := range []struct {
		values      []string
		max, proven uint16
	}{
		{nil, 0, 0}, // an older peer
		{[]string{"1320"}, 1320, 0},
		{[]string{"1320,1320"}, 1320, 1320},
		{[]string{"1400,1320"}, 1400, 1320},
		{[]string{"1320,1400"}, 1320, 0}, // cannot have reached more than it tries
		{[]string{"1320,banana"}, 1320, 0},
		{[]string{"1199"}, 0, 0},
		{[]string{"1453"}, 0, 0},
		{[]string{"99999999999"}, 0, 0},
		{[]string{"-1320"}, 0, 0},
		{[]string{""}, 0, 0},
		{[]string{"1320", "1320"}, 0, 0}, // ambiguous
	} {
		h := http.Header{}
		for _, v := range tc.values {
			h.Add(packetSizeHeader, v)
		}
		if max, proven := parsePacketSize(h); max != tc.max || proven != tc.proven {
			t.Errorf("%q: got %d,%d want %d,%d", tc.values, max, proven, tc.max, tc.proven)
		}
	}
	h := http.Header{}
	h.Set(packetSizeHeader, packetSizeValue(1320, 1320))
	if max, proven := parsePacketSize(h); max != 1320 || proven != 1320 {
		t.Fatal("value does not round trip")
	}
	h.Set(packetSizeHeader, packetSizeValue(1320, 0))
	if max, proven := parsePacketSize(h); max != 1320 || proven != 0 {
		t.Fatal("value without a proven size does not round trip")
	}
}

func TestMaxPacketSizeConfig(t *testing.T) {
	for _, tc := range []struct {
		initial, max uint16
		want         uint16 // zero: rejected
	}{
		{0, 0, 1320}, {1200, 0, 1320}, {1400, 0, 1400}, {1200, 1200, 1200}, {1200, 1400, 1400},
		{1300, 1250, 0}, {1200, 1401, 0},
	} {
		var got uint16
		f, err := testFactoryForPacketSize(t, tc.initial, tc.max)
		if err == nil {
			got = f.cfg.MaxPacketSize
		}
		if (err != nil) != (tc.want == 0) || got != tc.want {
			t.Errorf("initial %d max %d: got %d, %v; want %d", tc.initial, tc.max, got, err, tc.want)
		}
	}
}

func testFactoryForPacketSize(t *testing.T, initial, max uint16) (*Factory, error) {
	t.Helper()
	local, remote := key.NewNode().Public().Raw32(), key.NewNode().Public().Raw32()
	cert, private, _ := testIdentity(t)
	_, _, pin := testIdentity(t)
	const url = "https://quic-ip.test/.well-known/masque/ip/*/*/"
	return NewFactory(Config{
		Version: 2, Payload: "ip", LocalPublicKey: hex.EncodeToString(local[:]), Certificate: cert, PrivateKey: private,
		IO: "magicsock", InitialPacketSize: initial, MaxPacketSize: max, QueuePackets: 256, HTTP3: true, HTTP3URL: url,
		Peers: []PeerConfig{{PublicKey: hex.EncodeToString(remote[:]), SPKISHA256: pin, HTTP3URL: url}},
	})
}

// smallInitial makes a test pair start at the default initial packet size, as
// deployed nodes do; the test fixture otherwise starts at 1400.
func smallInitial(c *Config) { c.InitialPacketSize = 1200 }

// pumpUntil keeps a trickle of tunnel packets flowing until ok. QUIC sends
// its packet size probes alongside other traffic, as it would in use.
func pumpUntil(t *testing.T, what string, exchange func(), ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		exchange()
		time.Sleep(time.Millisecond)
	}
}

// sessionsOf returns the established session of each end towards the other.
func sessionsOf(t *testing.T, pair *testPair) (peers [2]*peer, sessions [2]*session) {
	t.Helper()
	for i := range 2 {
		other := pair.keys[i^1].Public().Raw32()
		g := pair.backends[i].active.Load()
		waitFor(t, "session was not established", func() bool {
			g.peersMu.Lock()
			p := g.peers[other]
			g.peersMu.Unlock()
			if p == nil {
				return false
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			peers[i], sessions[i] = p, p.session
			return p.session != nil
		})
	}
	return peers, sessions
}

// On a path that carries it, both ends grow to max_packet_size after the
// handshake. New TCP connections then negotiate segments that fill it, and a
// full tunnel packet travels in one datagram.
func TestPacketSizeGrowsAndMSSFollows(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", smallInitial)
	fns := pair.open(t)
	local, remote := pair.keys[0].Public().Raw32(), pair.keys[1].Public().Raw32()
	ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
	if err != nil {
		t.Fatal(err)
	}
	send := func(packet []byte) []byte {
		t.Helper()
		if err := pair.backends[0].Bind().Send([][]byte{packet}, ep, 0); err != nil {
			t.Fatal(err)
		}
		return readOne(t, fns[1])
	}
	send([]byte{1, 2, 3})
	peers, sessions := sessionsOf(t, pair)
	back, err := pair.backends[1].Bind().ParseEndpoint(hex.EncodeToString(local[:]))
	if err != nil {
		t.Fatal(err)
	}
	pumpUntil(t, "packet size did not grow on a path that carries it", func() {
		send([]byte{1, 2, 3})
		if err := pair.backends[1].Bind().Send([][]byte{{3, 2, 1}}, back, 0); err != nil {
			t.Fatal(err)
		}
		readOne(t, fns[0])
	}, func() bool {
		return sessions[0].q.PacketSize() == defaultMaxPacketSize && sessions[1].q.PacketSize() == defaultMaxPacketSize
	})
	for i := range 2 {
		if got := peers[i].tcpPacketSize(sessions[i]); got != defaultMaxPacketSize {
			t.Fatalf("end %d assumes packet size %d for new TCP connections", i, got)
		}
	}
	syn, off := mssPacketForTest(false, false, 1460)
	want := bytes.Clone(syn)
	if !clampTCPMSS(want, defaultMaxPacketSize-h3TCPDatagramHeadroom-40) {
		t.Fatal("invalid fixture")
	}
	if got := send(syn); !bytes.Equal(got, want) || checksumForTest(got[off:]) != 0 {
		t.Fatal("SYN was not clamped to the packet size in use")
	}
	before := pair.backends[0].counters.FragmentedPackets.Load()
	full := bytes.Repeat([]byte{0x45}, 1280)
	if got := send(full); !bytes.Equal(got, full) {
		t.Fatal("full tunnel packet changed")
	}
	if pair.backends[0].counters.FragmentedPackets.Load() != before {
		t.Fatal("a full tunnel packet still needed two datagrams")
	}

	// A peer that states no packet size is an older build that stays at the
	// initial size: TCP connections through it keep the small segments.
	sessions[0].peerPacketSize.Store(0)
	if got := peers[0].tcpPacketSize(sessions[0]); got != 1200 {
		t.Fatalf("assumed %d for a peer that states no packet size", got)
	}
}

// The size a connection reached is remembered for the peer. The next
// connection, typically the one opened by the first SYN after an idle period,
// assumes it at once on both ends instead of holding that TCP connection to
// small segments for its whole life.
func TestProvenPacketSizeCarriesToNextConnection(t *testing.T) {
	pair, p, send, receive := resumablePair(t, smallInitial)
	client := pair.backends[0]
	remote := pair.keys[1].Public().Raw32()
	cache := client.clientSessionCache(remote)
	if cache.packetSize.Load() != 0 {
		t.Fatal("a size was remembered before any connection reached it")
	}
	send([]byte{1})
	receive()
	peers, sessions := sessionsOf(t, pair)
	pumpUntil(t, "packet size did not grow", func() { send([]byte{1}); receive() }, func() bool {
		return sessions[0].q.PacketSize() == defaultMaxPacketSize
	})
	client.active.Load().maintainAt(time.Now())
	if got := cache.packetSize.Load(); got != defaultMaxPacketSize {
		t.Fatalf("remembered packet size %d", got)
	}
	p.closeSession("idle")
	waitFor(t, "server kept the closed session", func() bool { return !peers[1].hasLiveSession() })

	syn, _ := mssPacketForTest(false, false, 1460)
	want := bytes.Clone(syn)
	clampTCPMSS(want, defaultMaxPacketSize-h3TCPDatagramHeadroom-40)
	send(syn)
	if got := receive(); !bytes.Equal(got, want) {
		t.Fatal("first SYN of the next connection was held to the initial packet size")
	}
	_, sessions = sessionsOf(t, pair)
	if got := sessions[1].provenPacketSize.Load(); got != defaultMaxPacketSize {
		t.Fatalf("server learned proven packet size %d", got)
	}
	if got := peers[1].tcpPacketSize(sessions[1]); got != defaultMaxPacketSize {
		t.Fatalf("server assumes %d for the answering SYN", got)
	}
}

// On a path that does not carry the larger size nothing changes: packets and
// TCP segments keep the initial size, and a stale memory is dropped.
func TestPacketSizeStaysOnSmallPath(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", smallInitial)
	var links [2]*mtuLimitedBind
	for i := range pair.bases {
		links[i] = &mtuLimitedBind{Bind: pair.bases[i].Bind}
		links[i].limit.Store(1200)
		pair.bases[i].Bind = links[i]
	}
	fns := pair.open(t)
	remote := pair.keys[1].Public().Raw32()
	ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.backends[0].Bind().Send([][]byte{{1, 2, 3}}, ep, 0); err != nil {
		t.Fatal(err)
	}
	readOne(t, fns[1])
	peers, sessions := sessionsOf(t, pair)
	pumpUntil(t, "the larger size was never probed", func() {
		if err := pair.backends[0].Bind().Send([][]byte{{1, 2, 3}}, ep, 0); err != nil {
			t.Fatal(err)
		}
		readOne(t, fns[1])
	}, func() bool { return links[0].drops.Load() >= 3 })
	if got := sessions[0].q.PacketSize(); got != 1200 {
		t.Fatalf("packet size %d on a 1200-byte path", got)
	}
	if got := peers[0].tcpPacketSize(sessions[0]); got != 1200 {
		t.Fatalf("assumed %d on a 1200-byte path", got)
	}
	// A size remembered from another path is assumed only briefly...
	cache := pair.backends[0].clientSessionCache(remote)
	cache.packetSize.Store(defaultMaxPacketSize)
	sessions[0].provenPacketSize.Store(defaultMaxPacketSize)
	if got := peers[0].tcpPacketSize(sessions[0]); got != defaultMaxPacketSize {
		t.Fatalf("fresh connection assumed %d, not the proven size", got)
	}
	sessions[0].created = sessions[0].created.Add(-provenPacketGrace)
	if got := peers[0].tcpPacketSize(sessions[0]); got != 1200 {
		t.Fatalf("assumed %d after the grace period", got)
	}
	// ...and forgotten once this connection has shown otherwise.
	pair.backends[0].active.Load().maintainAt(time.Now().Add(2 * provenPacketGrace))
	if got := cache.packetSize.Load(); got != 0 {
		t.Fatalf("stale packet size %d kept", got)
	}
}
