// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
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
			want := !localServer && hint == serverYes
			if b.browserProfileEligible(k, true) != want {
				t.Fatalf("local=%t hint=%d: got %t want %t", localServer, hint, b.browserProfileEligible(k, true), want)
			}
		}
	}
	b.forgetServerHint(k)
	if b.browserProfileEligible(k, true) {
		t.Fatal("revoked hint survived")
	}
}

func TestBrowserProfileSelectionTruthTableAndSNI(t *testing.T) {
	fb := &Backend{factory: &Factory{cfg: Config{HTTP3: true}}, serverHints: map[[32]byte]*atomic.Uint32{}}
	for _, tc := range []struct {
		name        string
		localServer bool
		remoteHint  uint32
		outgoing    bool
		want        bool
	}{
		{"unknown-incoming", false, serverUnknown, false, false},
		{"unknown-outgoing", false, serverUnknown, true, false},
		{"ordinary-ordinary", false, serverNo, true, false},
		{"local-server-remote-server", true, serverYes, true, false},
		{"server-server", false, serverYes, true, true},
		{"incoming-to-server", false, serverYes, false, false},
	} {
		k := [32]byte{byte(len(tc.name))}
		fb.serverHints[k] = new(atomic.Uint32)
		fb.serverHints[k].Store(tc.remoteHint)
		fb.factory.cfg.Server = tc.localServer
		if got := fb.browserProfileEligible(k, tc.outgoing); got != tc.want {
			t.Fatalf("%s: got %t want %t", tc.name, got, tc.want)
		}
		if got := fb.browserProfileForPeer(k, tc.outgoing); got != "" && tc.want {
			if got != "chromium-h3" {
				t.Fatalf("%s: got %q want chromium-h3", tc.name, got)
			}
		} else if got != "" {
			t.Fatalf("%s: got %q want empty", tc.name, got)
		}
	}
	for _, tc := range []struct {
		url  string
		want string
	}{
		{"https://example.com/.well-known/masque/ip/", "example.com"},
		{"https://127.0.0.1/.well-known/masque/ip/", ""},
		{"https://node-123.invalid/.well-known/masque/ip/", ""},
	} {
		u, err := url.Parse(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		if got := http3ClientHelloServerName(u); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.url, got, tc.want)
		}
	}
	kYes, kNo := [32]byte{1}, [32]byte{2}
	b := &Backend{factory: &Factory{cfg: Config{HTTP3: true}}, serverHints: map[[32]byte]*atomic.Uint32{kYes: new(atomic.Uint32), kNo: new(atomic.Uint32)}}
	b.serverHints[kYes].Store(serverYes)
	b.serverHints[kNo].Store(serverNo)
	cfgYes := b.quicConfig()
	cfgYes.ClientHelloProfile = b.browserProfileForPeer(kYes, true)
	cfgNo := b.quicConfig()
	cfgNo.ClientHelloProfile = b.browserProfileForPeer(kNo, true)
	if cfgYes == cfgNo {
		t.Fatal("per-dial QUIC config not unique")
	}
	if cfgYes.ClientHelloProfile != "chromium-h3" {
		t.Fatal("eligible peer did not carry per-dial browser profile")
	}
	if cfgNo.ClientHelloProfile != "" {
		t.Fatal("ineligible peer unexpectedly carries a browser profile")
	}
	if b.factory.cfg.Server {
		t.Fatal("factory config mutated by a per-dial browser selection")
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
						eligible := !flags[n] && flags[n^1]
						if b.browserProfileEligible(remote, true) != eligible {
							t.Fatal("wrong next outbound selection")
						}
						p, err := b.active.Load().peer(remote, nil)
						if err != nil {
							t.Fatal(err)
						}
						p.closeSession("baseline for the next outbound after learning the authenticated server hint")
						if got := b.Snapshot()["browser_fingerprint"]; got != "none" {
							t.Fatalf("closed session leaked a browser profile: got %v", got)
						}
						if _, err := p.getSession(); err != nil {
							t.Fatal(err)
						}
						profile := "none"
						if eligible {
							profile = "chromium-h3"
						}
						if got := b.Snapshot()["browser_fingerprint"]; got != profile {
							t.Fatalf("actual browser fingerprint mismatch: got %v want %q", got, profile)
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
