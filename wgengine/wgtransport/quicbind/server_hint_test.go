// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerHintParsingAndClientOnlySelection(t *testing.T) {
	for _, tc := range []struct {
		values []string
		want   uint32
		fail   bool
	}{
		{nil, serverUnknown, false}, {[]string{"?0"}, serverNo, false}, {[]string{"?1"}, serverYes, false},
		{[]string{"true"}, 0, true}, {[]string{""}, 0, true}, {[]string{"?1, ?0"}, 0, true}, {[]string{"?1", "?1"}, 0, true},
	} {
		h := http.Header{}
		for _, v := range tc.values {
			h.Add(serverHintHeader, v)
		}
		got, err := parseServerHint(h)
		if (err != nil) != tc.fail || got != tc.want {
			t.Fatalf("parse %q=%d,%v", tc.values, got, err)
		}
	}
	k := [32]byte{2}
	b := &Backend{factory: &Factory{cfg: Config{HTTP3: true}}, serverHints: map[[32]byte]*atomic.Uint32{k: new(atomic.Uint32)}}
	for _, hint := range []uint32{serverUnknown, serverNo, serverYes} {
		b.serverHints[k].Store(hint)
		for _, localServer := range []bool{false, true} {
			b.factory.cfg.Server = localServer
			if b.browserProfileEligible(k, false) {
				t.Fatal("inbound TLS server selected a browser profile")
			}
			if b.browserProfileEligible(k, true) != (hint == serverYes) {
				t.Fatal("selector used local role instead of authenticated remote flag")
			}
		}
	}
	b.forgetServerHint(k)
	if b.browserProfileEligible(k, true) {
		t.Fatal("revoked hint survived")
	}
}

func TestH3SingleServerFlagLearnsAutomatically(t *testing.T) {
	for _, flags := range [][2]bool{{false, false}, {false, true}, {true, false}, {true, true}} {
		for _, first := range []int{0, 1} {
			t.Run(fmt.Sprintf("%t-%t-first%d", flags[0], flags[1], first), func(t *testing.T) {
				i := 0
				pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.Server = flags[i]; i++ })
				for _, b := range pair.backends {
					for k := range b.factory.peers {
						if b.peerServerHint(k) != serverUnknown {
							t.Fatal("fixture preconfigured remote server")
						}
					}
				}
				for cycle := 0; cycle < 2; cycle++ {
					fns := pair.open(t)
					for _, from := range []int{first, first ^ 1} {
						pk := pair.keys[from^1].Public().Raw32()
						ep, err := pair.backends[from].Bind().ParseEndpoint(hex.EncodeToString(pk[:]))
						if err != nil {
							t.Fatal(err)
						}
						want := bytes.Repeat([]byte{byte(cycle + 1), byte(from + 1)}, 512)
						if err := pair.backends[from].Bind().Send([][]byte{want}, ep, 0); err != nil {
							t.Fatal(err)
						}
						if got := readOne(t, fns[from^1]); !bytes.Equal(got, want) {
							t.Fatal("data mismatch")
						}
					}
					for n, b := range pair.backends {
						remote := pair.keys[n^1].Public().Raw32()
						want := serverNo
						if flags[n^1] {
							want = serverYes
						}
						deadline := time.Now().Add(time.Second)
						for b.peerServerHint(remote) != want && time.Now().Before(deadline) {
							time.Sleep(time.Millisecond)
						}
						if b.peerServerHint(remote) != want {
							t.Fatalf("node%d failed to learn flag", n)
						}
						if b.browserProfileEligible(remote, true) != flags[n^1] {
							t.Fatal("wrong next outbound selection")
						}
						if b.Snapshot()["browser_fingerprint"] != "none" {
							t.Fatal("claimed an unimplemented browser fingerprint")
						}
					}
					for _, b := range pair.backends {
						if err := b.Bind().Close(); err != nil {
							t.Fatal(err)
						}
					}
				}
			})
		}
	}
}
