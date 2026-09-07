// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"context"
	"net/http"
	"tailscale.com/wgengine/wgtransport"
	"testing"
)

func TestAutomaticOriginPreservesLegacyPathEncoding(t *testing.T) {
	u := automaticPeerURL([32]byte{1})
	if u.EscapedPath() != "/.well-known/masque/ip/*/*/" {
		t.Fatalf("legacy CONNECT target changed: %s", u.EscapedPath())
	}
	parsed, err := parseHTTP3URL(u.String())
	if err != nil {
		t.Fatal(err)
	}
	r := &http.Request{URL: parsed, Host: parsed.Host}
	if !sameHTTP3Target(r, u) {
		t.Fatal("stored and automatic target differ")
	}
}
func BenchmarkAutoTrustExistingPeer(b *testing.B) {
	k := [32]byte{1}
	backend := &Backend{factory: &Factory{cfg: Config{AutoTrust: true}, peers: make(map[[32]byte]peerConfig)}, host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return true }}}
	g := &generation{b: backend, ctx: context.Background(), peers: make(map[[32]byte]*peer)}
	p := &peer{g: g, cfg: peerConfig{key: k}}
	g.peers[k] = p
	b.ReportAllocs()
	for b.Loop() {
		got, err := g.peer(k, nil)
		if err != nil || got != p {
			b.Fatal(err)
		}
	}
}
