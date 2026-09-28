// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestBrowserDirectionWinsSimultaneousH3Dials(t *testing.T) {
	for iteration := range 8 {
		t.Run(fmt.Sprint(iteration), func(t *testing.T) {
			index := 0
			pair := newTestPair(t, "http3-magicsock", func(c *Config) {
				c.Server = index == 1
				c.Peers[0].Server = index == 0
				c.HTTP3URL = "https://private.invalid/.well-known/masque/ip/*/*/"
				c.Peers[0].HTTP3URL = c.HTTP3URL
				index++
			})
			fns := pair.open(t)
			var peers [2]*peer
			for i := range peers {
				var err error
				peers[i], err = pair.backends[i].active.Load().peer(pair.keys[i^1].Public().Raw32(), nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Do not bias toward public-key ordering or whichever handshake completes
			// first. Both candidates are real TLS/H3 and both peer pins are enforced.
			var wg sync.WaitGroup
			start := make(chan struct{})
			for _, p := range peers {
				wg.Add(1)
				go func() { defer wg.Done(); <-start; _, _ = p.getSession() }()
			}
			close(start)
			wg.Wait()
			deadline := time.Now().Add(4 * time.Second)
			var selected [2]*session
			for {
				ready := true
				for i, p := range peers {
					p.mu.Lock()
					selected[i] = p.session
					p.mu.Unlock()
					s := selected[i]
					ready = ready && s != nil && s.q.Context().Err() == nil && s.outgoing == (i == 0)
				}
				if ready {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("duplicate election retained server-originated connection")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if selected[0].q.ConnectionState().ClientHelloProfile != "chromium-h3" || selected[1].q.ConnectionState().ClientHelloProfile != "" {
				t.Fatal("wrong actual ClientHello after election")
			}
			// Reverse application traffic is not a reverse TLS client role.
			for _, from := range []int{1, 0} {
				want := bytes.Repeat([]byte{byte(iteration), byte(from), 42}, 128)
				if err := peers[from].sendPacket(selected[from], want, make([]byte, 1500)); err != nil {
					t.Fatal(err)
				}
				if got := readOne(t, fns[from^1]); !bytes.Equal(got, want) {
					t.Fatal("elected session payload mismatch")
				}
			}
		})
	}
}

func TestDeclarationElectionSymmetricAndUnknown(t *testing.T) {
	for _, localServer := range []bool{false, true} {
		for _, remoteHint := range []uint32{serverUnknown, serverNo, serverYes} {
			for _, keyFirst := range []bool{false, true} {
				b := &Backend{factory: &Factory{cfg: Config{HTTP3: true, Server: localServer}, local: [32]byte{2}}}
				p := &peer{g: &generation{b: b}, cfg: peerConfig{key: [32]byte{1}}}
				if keyFirst {
					p.cfg.key = [32]byte{3}
				}
				want := keyFirst
				if remoteHint != serverUnknown && localServer != (remoteHint == serverYes) {
					want = !localServer
				}
				if p.preferredOutgoing(remoteHint) != want {
					t.Fatalf("local=%v remote=%d keyFirst=%v", localServer, remoteHint, keyFirst)
				}
			}
		}
	}
}
