// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestH3BBRv3(t *testing.T) {
	index := 0
	pair := newTestPair(t, "http3-magicsock", func(c *Config) {
		c.AutoTrust = true
		c.Peers = nil
		c.BBRv3 = true
		c.Server = index == 1
		index++
	})
	fns := pair.open(t)
	for _, b := range pair.backends {
		if got := b.quicConfig().CongestionControlName(); got != "bbr-v3" {
			t.Fatalf("configured %s", got)
		}
	}
	remote := pair.keys[1].Public().Raw32()
	p, err := pair.backends[0].active.Load().peer(remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.getSession()
	if err != nil {
		t.Fatal(err)
	}
	if s.q.ConnectionStats().CongestionControl != "bbr-v3" {
		t.Fatal("actual QUIC session not configured as BBRv3")
	}
	for i := range 2 {
		peer := pair.keys[i^1].Public().Raw32()
		ep, err := pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(peer[:]))
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.Repeat([]byte{0x45, byte(i), 0x37}, 8192)
		if err := pair.backends[i].Bind().Send([][]byte{want}, ep, 0); err != nil {
			t.Fatal(err)
		}
		if got := readOne(t, fns[i^1]); !bytes.Equal(got, want) {
			t.Fatal("authenticated fragmented H3 payload mismatch")
		}
	}
}
