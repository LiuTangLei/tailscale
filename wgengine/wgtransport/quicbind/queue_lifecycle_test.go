// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"testing"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/wgengine/wgtransport"
)

// Leave packets in the carrier receive queue while control-plane state changes.
// A valid peer after a remove/re-add is NOT permission to deliver buffered data
// accepted under the old local identity or the old peer lifecycle.
func TestQueuedPacketsAcrossIdentityAndPeerReset(t *testing.T) {
	for _, reset := range []string{"unchanged", "local-identity", "peer-remove-readd", "network-rebind"} {
		t.Run(reset, func(t *testing.T) {
			local, remote := [32]byte{1}, [32]byte{2}
			b := &Backend{factory: &Factory{local: local, cfg: Config{IO: "magicsock"}}, host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return true }}}
			b.identityOK.Store(true)
			g := &generation{b: b, ctx: context.Background(), rx: make(chan received, 1), peers: make(map[[32]byte]*peer)}
			p := &peer{g: g, cfg: peerConfig{key: remote}}
			p.ep.Store(&endpoint{b: b, key: remote})
			g.peers[remote] = p
			b.active.Store(g)
			g.rxBytes.Store(4)
			g.rx <- received{data: []byte{0x45, 0, 0, 20}, ep: p.ep.Load(), peer: p, stamp: p.lifecycleStamp()}
			if len(g.rx) != 1 {
				t.Fatal("fixture did not queue packet")
			}
			switch reset {
			case "local-identity":
				b.LocalIdentityChanged([32]byte{3})
				b.LocalIdentityChanged(local)
			case "peer-remove-readd":
				b.PeerRemoved(remote)
				p.disabled.Store(false) // same peer key becomes routable again
			case "network-rebind":
				b.NetworkChanged(true, true)
			}
			bufs := [][]byte{make([]byte, 64)}
			sizes, eps := make([]int, 1), make([]conn.Endpoint, 1)
			n, err := g.receive(bufs, sizes, eps)
			if err != nil || n != 1 {
				t.Fatalf("receive=%d %v", n, err)
			}
			if reset == "unchanged" {
				if sizes[0] != 4 || eps[0] == nil {
					t.Fatal("valid packet was lost")
				}
			} else if sizes[0] != 0 || eps[0] != nil {
				t.Fatal("buffered packet crossed a revoked identity/session boundary")
			}
			if g.rxBytes.Load() != 0 {
				t.Fatal("dropped packet leaked queue accounting")
			}
		})
	}
}
