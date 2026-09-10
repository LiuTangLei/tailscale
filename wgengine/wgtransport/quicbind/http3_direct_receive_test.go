// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestDirectHTTPDatagramRoutingAndBorrowing(t *testing.T) {
	c := &http3Channel{g: &generation{b: &Backend{}}}
	var received []byte
	handler := c.directIPDatagramHandler(3, func(b []byte) { received = bytes.Clone(b) })
	packet := []byte{0x45, 1, 2, 3}
	encoded := append([]byte{3, 0}, packet...)
	before := bytes.Clone(encoded)
	if !handler(encoded) || !bytes.Equal(received, packet) || !bytes.Equal(encoded, before) {
		t.Fatal("direct dispatch changed HTTP framing or borrowed QUIC data")
	}
	clear(encoded)
	if !bytes.Equal(received, packet) {
		t.Fatal("retained data depends on reused transport buffer")
	}
	for _, raw := range [][]byte{nil, {3}, {2, 0, 0x45}, {3, 2, 1, 2}, {3, 1, 1}, {3, 0}} {
		if handler(raw) {
			t.Fatalf("intercepted malformed, unrelated, fragmented or unsupported context: %x", raw)
		}
	}
	// Nonminimal QUIC varints are legal and must not corrupt context stripping.
	long := quicvarint.AppendWithLen(nil, 3, 2)
	long = quicvarint.AppendWithLen(long, 0, 2)
	long = append(long, packet...)
	if !handler(long) || !bytes.Equal(received, packet) {
		t.Fatal("nonminimal varint changed IP payload")
	}
}

func TestDirectHTTPReceiveStillUsesLiveDequeuePolicy(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	var allowed atomic.Bool
	allowed.Store(true)
	pair.backends[1].host.PeerAllowed = func([32]byte) bool { return allowed.Load() }
	fns := pair.open(t)
	peerKey := pair.keys[1].Public().Raw32()
	ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(peerKey[:]))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x45, 1, 2, 3}, 256)
	if err := pair.backends[0].Bind().Send([][]byte{payload}, ep, 0); err != nil {
		t.Fatal(err)
	}
	if got := readOne(t, fns[1]); !bytes.Equal(got, payload) {
		t.Fatal("authenticated data mismatch")
	}
	p, err := pair.backends[0].active.Load().peer(peerKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	s := p.session
	p.mu.Unlock()
	if _, ok := any(s.q).(datagramReceiveSetter); !ok {
		t.Skip("optional direct receiver dependency not selected")
	}
	deadline := time.Now().Add(2 * time.Second)
	for pair.backends[1].counters.DirectReceiveConnections.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("authenticated session never installed direct receiver")
		}
		time.Sleep(time.Millisecond)
	}
	for i := range 8 {
		payload[1] = byte(i)
		if err := pair.backends[0].Bind().Send([][]byte{payload}, ep, 0); err != nil {
			t.Fatal(err)
		}
		if got := readOne(t, fns[1]); !bytes.Equal(got, payload) {
			t.Fatal("direct payload mismatch")
		}
	}
	if pair.backends[1].counters.DirectReceiveDatagrams.Load() < 8 {
		t.Fatal("data bypassed the new receive path")
	}
	// Do not change the session epoch: exercise the live policy at dequeue,
	// not only cache invalidation or connection closure.
	allowed.Store(false)
	if err := pair.backends[0].Bind().Send([][]byte{payload}, ep, 0); err != nil {
		t.Fatal(err)
	}
	buffers := [][]byte{make([]byte, 2048)}
	sizes, endpoints := make([]int, 1), make([]conn.Endpoint, 1)
	timer := time.AfterFunc(3*time.Second, func() { pair.backends[1].Close() })
	defer timer.Stop()
	n, err := fns[1](buffers, sizes, endpoints)
	if err != nil || n != 1 || sizes[0] != 0 || endpoints[0] != nil {
		t.Fatalf("revoked policy released queued bytes: n=%d size=%d err=%v", n, sizes[0], err)
	}
}
