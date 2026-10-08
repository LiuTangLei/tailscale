// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/wgengine/wgtransport"
)

type noncomparableEndpoint struct {
	conn.Endpoint
	body []byte
}

func TestBindAddressCachePreservesIdentityAndCustomEndpoints(t *testing.T) {
	var cache bindAddressCache
	first, second := &endpoint{}, &endpoint{}
	a := cache.address(first)
	if a == nil || cache.address(first) != a || a.ep != first {
		t.Fatal("same endpoint wrapper not reused")
	}
	b := cache.address(second)
	if a == b || a.ep != first || b.ep != second {
		t.Fatal("old wrapper was mutated for a different peer")
	}
	custom := noncomparableEndpoint{Endpoint: first, body: []byte{1}}
	if cache.address(custom) == nil || cache.address(custom) == nil {
		t.Fatal("custom endpoint rejected")
	}
	if cache.address(first).ep != first || cache.address(nil) != nil {
		t.Fatal("endpoint identity changed")
	}
	// A comparable struct type may contain an interface holding a slice.
	// Type.Comparable alone is not sufficient to make interface == safe.
	nested := struct{ conn.Endpoint }{custom}
	if cache.address(nested) == nil || cache.address(nested) == nil {
		t.Fatal("nested custom endpoint rejected")
	}
}

func TestReadHostReusesAddressWithoutChangingEndpoint(t *testing.T) {
	g := &generation{b: &Backend{host: wgtransport.Host{Bind: &recordingBatchBind{batch: 1}}}, ctx: context.Background()}
	g.bridge = newBindPacketConn(g)
	first, second := &endpoint{}, &endpoint{}
	endpoints := []conn.Endpoint{first, first, second, second}
	call := 0
	g.workers.Add(1)
	g.readHost(func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		if call == len(endpoints) {
			return 0, net.ErrClosed
		}
		clear(slab[:21])
		slab[0], slab[20] = 0x40, byte(call)
		packets[0].Size, packets[0].Endpoint = 21, endpoints[call]
		call++
		return 1, nil
	})
	var addresses []*bindAddr
	for i, ep := range endpoints {
		buf := make([]byte, 32)
		n, addr, err := g.bridge.ReadFrom(buf)
		if err != nil || n != 21 || buf[20] != byte(i) || addr.(*bindAddr).ep != ep {
			t.Fatalf("packet %d: n=%d addr=%v err=%v", i, n, addr, err)
		}
		addresses = append(addresses, addr.(*bindAddr))
	}
	if addresses[0] != addresses[1] || addresses[2] != addresses[3] || addresses[0] == addresses[2] {
		t.Fatal("readHost did not reuse immutable per-endpoint address wrappers")
	}
}

func TestClosedPacketConnDoesNotDeliverQueuedData(t *testing.T) {
	c := newBindPacketConn(&generation{})
	for range 16 {
		c.rx <- rawPacket{packet: acquirePacket([]byte{1}), addr: &bindAddr{ep: &endpoint{}}}
	}
	c.Close()
	for range 16 {
		if n, _, err := c.ReadFrom(make([]byte, 32)); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("closed connection delivered queued data: n=%d err=%v", n, err)
		}
	}
	// Cleanup occurs after all host producers and QUIC workers have joined.
	c.drainReceiveQueue()
	if len(c.rx) != 0 {
		t.Fatal("closed raw receive queue retained packets")
	}
}

func TestBackendCloseDrainsRawReceiveQueue(t *testing.T) {
	pair := newTestPair(t, "magicsock")
	b := pair.backends[0]
	if _, _, err := b.Bind().Open(0); err != nil {
		t.Fatal(err)
	}
	g := b.active.Load()
	// Stop only QUIC's consumer. Host producers are still joined by Close.
	if err := g.transport.Close(); err != nil {
		t.Fatal(err)
	}
	for range 16 {
		g.bridge.rx <- rawPacket{packet: acquirePacket([]byte{1}), addr: &bindAddr{ep: &endpoint{}}}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if len(g.bridge.rx) != 0 {
		t.Fatal("Backend.Close retained raw receive buffers")
	}
}

func TestOwnedReceiveStorageReleasedOnDeliveryDenialAndShutdown(t *testing.T) {
	for _, mode := range []string{"deliver", "denied", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			backend := &Backend{host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return mode != "denied" }}}
			backend.identityOK.Store(true)
			g := &generation{b: backend, ctx: context.Background(), rx: make(chan received, 1)}
			p := &peer{g: g, cfg: peerConfig{key: [32]byte{1}}}
			ep := &endpoint{key: p.cfg.key}
			data := []byte{0x45, 1, 2, 3}
			storage := acquirePacket(data)
			g.rxBytes.Store(int64(len(data)))
			g.rx <- received{data: storage.data, owned: storage, ep: ep, peer: p, stamp: p.lifecycleStamp()}
			if mode == "shutdown" {
				g.drainIPReceiveQueue()
			} else {
				buffers := [][]byte{make([]byte, 64)}
				sizes, endpoints := make([]int, 1), make([]conn.Endpoint, 1)
				n, err := g.receive(buffers, sizes, endpoints)
				if err != nil || n != 1 {
					t.Fatal("receive", n, err)
				}
				if mode == "deliver" && (!bytes.Equal(buffers[0][:sizes[0]], data) || endpoints[0] != ep) {
					t.Fatal("delivery changed")
				}
				if mode == "denied" && (sizes[0] != 0 || endpoints[0] != nil) {
					t.Fatal("denied data released")
				}
			}
			if g.rxBytes.Load() != 0 || len(g.rx) != 0 {
				t.Fatal("queue ownership/accounting leaked")
			}
		})
	}
}

var benchmarkBindAddress net.Addr

func BenchmarkBindAddressWrapper(b *testing.B) {
	for _, cached := range []bool{false, true} {
		name := "per-packet"
		if cached {
			name = "one-entry-cache"
		}
		b.Run(name, func(b *testing.B) {
			ep := &endpoint{}
			var cache bindAddressCache
			cache.address(ep)
			b.ReportAllocs()
			for b.Loop() {
				if cached {
					benchmarkBindAddress = cache.address(ep)
				} else {
					benchmarkBindAddress = &bindAddr{ep: ep}
				}
			}
		})
	}
}
