// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestH3ApplicationCredentialAndBBRv3(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		name := "matching-secret"
		if wrong {
			name = "wrong-secret"
		}
		t.Run(name, func(t *testing.T) {
			index := 0
			pair := newTestPair(t, "http3-magicsock", func(c *Config) {
				c.AutoTrust = true
				c.Peers = nil
				c.BBRv3 = true
				c.Server = index == 1
				c.AuthenticationSecret = [32]byte{9, 7, 5, 3, 1}
				if index == 1 && wrong {
					c.AuthenticationSecret[0] ^= 1
				}
				index++
			})
			fns := pair.open(t)
			for _, b := range pair.backends {
				if got := b.quicConfig().CongestionControlName(); got != "bbr-v3" {
					t.Fatalf("configured %s", got)
				}
				j, err := json.Marshal(b.factory.cfg)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(j, []byte("AuthenticationSecret")) {
					t.Fatal("credential serialized into public profile")
				}
			}
			remote := pair.keys[1].Public().Raw32()
			p, err := pair.backends[0].active.Load().peer(remote, nil)
			if err != nil {
				t.Fatal(err)
			}
			s, err := p.getSession()
			if wrong {
				if err == nil {
					t.Fatal("wrong application credential admitted a data session")
				}
				for _, b := range pair.backends {
					if b.counters.Connections.Load() != 0 {
						t.Fatal("unauthenticated session installed")
					}
				}
				return
			}
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
		})
	}
}
