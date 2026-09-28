// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"sync/atomic"
	"testing"

	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgtransport/nodeauth"
)

func TestAutoTrustFollowsNodeKeyRotationWithoutNewCertificate(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	var keys [2]atomic.Pointer[key.NodePrivate]
	for i := range 2 {
		current := pair.keys[i]
		keys[i].Store(&current)
	}
	for i, b := range pair.backends {
		b.host.NodePublic = func() [32]byte { return keys[i].Load().Public().Raw32() }
		b.host.PeerAllowed = func(remote [32]byte) bool { return remote == keys[i^1].Load().Public().Raw32() }
		b.host.NodeHandshake = func(local, remote [32]byte, initiator bool, binding []byte) (nodeauth.Handshake, error) {
			own := keys[i].Load()
			return nodeauth.New(*own, remote, initiator, binding, func(remote [32]byte) bool {
				return own == keys[i].Load() && own.Public().Raw32() == local && (remote == ([32]byte{}) || remote == keys[i^1].Load().Public().Raw32())
			})
		}
	}
	fns := pair.open(t)
	originalCert := bytes.Clone(pair.backends[0].factory.cert.Certificate[0])
	for round := range 3 {
		if round > 0 {
			old := keys[0].Load().Public().Raw32()
			pair.backends[0].LocalIdentityChanged([32]byte{})
			pair.backends[1].PeerRemoved(old)
			next := key.NewNode()
			keys[0].Store(&next)
			pub := next.Public().Raw32()
			pair.bases[1].mu.Lock()
			pair.bases[1].key = hex.EncodeToString(pub[:])
			pair.bases[1].mu.Unlock()
			pair.backends[0].LocalIdentityChanged(pub)
			if _, err := pair.backends[1].Bind().ParseEndpoint(hex.EncodeToString(old[:])); err == nil {
				t.Fatal("old node key remained routable")
			}
		}
		for i := range 2 {
			remote := keys[i^1].Load().Public().Raw32()
			p, err := pair.backends[i].active.Load().peer(remote, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.getSession(); err != nil {
				t.Fatal(err)
			}
			ep, err := pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Repeat([]byte{byte(i), byte(round)}, 512)
			if err := pair.backends[i].Bind().Send([][]byte{want}, ep, 0); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, readOne(t, fns[i^1])) {
				t.Fatal("rotation data mismatch")
			}
		}
	}
	if !bytes.Equal(originalCert, pair.backends[0].factory.cert.Certificate[0]) {
		t.Fatal("node rotation unexpectedly changed TLS identity")
	}
}
