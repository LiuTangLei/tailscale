// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"errors"
	"testing"

	"tailscale.com/wgengine/wgtransport"
)

type lifecycleDatagrams struct{ sent int }

func (d *lifecycleDatagrams) SendDatagram([]byte) error { d.sent++; return nil }
func (*lifecycleDatagrams) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("not used by test")
}

func TestOldSessionCannotSendAfterReset(t *testing.T) {
	b := &Backend{factory: &Factory{local: [32]byte{1}}, host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return true }}}
	b.identityOK.Store(true)
	g := &generation{b: b, ctx: context.Background(), peers: make(map[[32]byte]*peer)}
	p := &peer{g: g, cfg: peerConfig{key: [32]byte{2}}}
	g.peers[p.cfg.key] = p
	b.active.Store(g)
	datagrams := &lifecycleDatagrams{}
	s := &session{dgram: datagrams, stamp: p.lifecycleStamp()}
	if err := p.sendPacket(s, []byte{1, 2, 3}, p.scratch[:]); err != nil {
		t.Fatal(err)
	}
	b.PeerRemoved(p.cfg.key)
	p.disabled.Store(false)
	if err := p.sendPacket(s, []byte{4, 5, 6}, p.scratch[:]); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("old session send: %v", err)
	}
	if datagrams.sent != 1 {
		t.Fatal("old session sent data after reset")
	}
	s.stamp = p.lifecycleStamp() // a newly authenticated session belongs to the new lifecycle
	if err := p.sendPacket(s, []byte{7, 8, 9}, p.scratch[:]); err != nil {
		t.Fatal(err)
	}
	if datagrams.sent != 2 {
		t.Fatal("current lifecycle did not send")
	}
}

func BenchmarkPeerLifecycleStamp(b *testing.B) {
	backend := &Backend{host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return true }}}
	backend.identityOK.Store(true)
	p := &peer{g: &generation{b: backend}}
	stamp := p.lifecycleStamp()
	b.ReportAllocs()
	for b.Loop() {
		if !p.stampValid(stamp) {
			b.Fatal("unexpected stale stamp")
		}
	}
}
