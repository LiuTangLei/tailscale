// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"context"
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
