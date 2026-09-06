// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgtransport"
)

type serverMeshBind struct {
	conn.Bind
	addresses map[string]string // set once after all sockets open, before traffic
}

func (b *serverMeshBind) ParseEndpoint(k string) (conn.Endpoint, error) {
	a, ok := b.addresses[k]
	if !ok {
		return nil, ErrUnknownPeer
	}
	return b.Bind.ParseEndpoint(a)
}

func TestH3ServerDeclarationsStayPerPeerUnderConcurrentMesh(t *testing.T) {
	const count, rounds = 4, 16
	var backends [count]*Backend
	var bases [count]*serverMeshBind
	var configs [count]Config
	var keys [count][32]byte
	var pins [count]string
	var ports [count]uint16
	var receives [count]conn.ReceiveFunc
	for i := range count {
		keys[i] = key.NewNode().Public().Raw32()
		cert, priv, pin := testIdentity(t)
		pins[i] = pin
		configs[i] = Config{Version: 2, Payload: "ip", IO: "magicsock", HTTP3: true, Server: i%2 == 1, LocalPublicKey: hex.EncodeToString(keys[i][:]), Certificate: cert, PrivateKey: priv, HTTP3URL: "https://mesh.test/.well-known/masque/ip/*/*/"}
	}
	for i := range count {
		for j := range count {
			if i != j {
				configs[i].Peers = append(configs[i].Peers, PeerConfig{PublicKey: hex.EncodeToString(keys[j][:]), SPKISHA256: pins[j], HTTP3URL: configs[j].HTTP3URL})
			}
		}
		f, err := NewFactory(configs[i])
		if err != nil {
			t.Fatal(err)
		}
		bases[i] = &serverMeshBind{Bind: conn.NewDefaultBind(), addresses: make(map[string]string)}
		backend, err := f.New(wgtransport.Host{Bind: bases[i], Logf: t.Logf, PeerAllowed: func(k [32]byte) bool { _, ok := f.peers[k]; return ok }})
		if err != nil {
			t.Fatal(err)
		}
		backends[i] = backend.(*Backend)
		b := backends[i]
		b.LocalIdentityChanged(keys[i])
		t.Cleanup(func() { b.Close() })
		fns, port, err := b.Bind().Open(0)
		if err != nil {
			t.Fatal(err)
		}
		receives[i] = fns[0]
		ports[i] = port
	}
	for i := range count {
		for j := range count {
			if i != j {
				bases[i].addresses[hex.EncodeToString(keys[j][:])] = fmt.Sprintf("127.0.0.1:%d", ports[j])
			}
		}
	}
	// DATAGRAM is unreliable. First settle each authenticated mesh connection
	// without application payload; simultaneous cold dials can replace a losing
	// connection and legitimately discard its datagrams. This test asserts
	// concurrent steady-session peer isolation, not transport reliability.
	for i := range count {
		for j := i + 1; j < count; j++ {
			p, err := backends[i].active.Load().peer(keys[j], nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.getSession(); err != nil {
				t.Fatal(err)
			}
		}
	}
	errorsCh := make(chan error, count*count*rounds)
	var wg sync.WaitGroup
	for to := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seen := make(map[[2]byte]bool)
			for len(seen) < (count-1)*rounds {
				buf := make([]byte, 2048)
				sizes := []int{0}
				eps := make([]conn.Endpoint, 1)
				n, err := receives[to]([][]byte{buf}, sizes, eps)
				if err != nil {
					errorsCh <- err
					return
				}
				if n != 1 || sizes[0] < 3 {
					errorsCh <- errors.New("empty concurrent receive")
					return
				}
				from, seq := int(buf[0]), int(buf[2])
				ep, ok := eps[0].(*endpoint)
				if from >= count || from == to || int(buf[1]) != to || seq >= rounds || !ok || ep.key != keys[from] {
					errorsCh <- errors.New("peer identity crossed concurrent server declarations")
					return
				}
				want := bytes.Repeat([]byte{byte(from), byte(to), byte(seq)}, 300)
				if !bytes.Equal(buf[:sizes[0]], want) {
					errorsCh <- errors.New("concurrent data corrupted")
					return
				}
				seen[[2]byte{byte(from), byte(seq)}] = true
			}
		}()
	}
	for from := range count {
		for to := range count {
			if from == to {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				ep, err := backends[from].Bind().ParseEndpoint(hex.EncodeToString(keys[to][:]))
				if err != nil {
					errorsCh <- err
					return
				}
				for seq := range rounds {
					data := bytes.Repeat([]byte{byte(from), byte(to), byte(seq)}, 300)
					if err := backends[from].Bind().Send([][]byte{data}, ep, 0); err != nil {
						errorsCh <- err
						return
					}
				}
			}()
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case err := <-errorsCh:
		t.Fatal(err)
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("concurrent H3 mesh timed out")
	}
	for i, b := range backends {
		for j := range count {
			if i == j {
				continue
			}
			want := serverNo
			if configs[j].Server {
				want = serverYes
			}
			if b.peerServerHint(keys[j]) != want {
				t.Fatalf("node%d learned wrong server flag for node%d", i, j)
			}
			if b.browserProfileEligible(keys[j], true) != configs[j].Server || b.browserProfileEligible(keys[j], false) {
				t.Fatal("browser selection leaked across peers or direction")
			}
		}
		stats := b.Snapshot()
		if stats["active_connections"] != count-1 {
			t.Fatal("mesh connections missing", stats)
		}
		if _, ok := stats["connection_stats"]; ok {
			t.Fatal("ambiguous last-peer statistics exposed")
		}
		if len(stats["peers"].([]map[string]any)) != count-1 {
			t.Fatal("per-peer diagnostics incomplete")
		}
	}
}
