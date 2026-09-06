// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgtransport"
)

func TestH3RoleValidation(t *testing.T) {
	for _, r := range []ConnectionRole{"", RoleMesh, RoleClient, RoleServer} {
		got, err := normalizeRole(r)
		if err != nil {
			t.Fatal(err)
		}
		if got.permits(true) != (got != RoleServer) || got.permits(false) != (got != RoleClient) {
			t.Fatalf("wrong role semantics %s", got)
		}
	}
	for _, r := range []ConnectionRole{"browser", "china", "CLIENT", "auto-server"} {
		if _, err := normalizeRole(r); err == nil {
			t.Fatalf("accepted unsupported policy %s", r)
		}
	}
	pair := newTestPair(t, "http3-magicsock")
	cfg := pair.backends[0].factory.cfg
	cfg.Peers = append([]PeerConfig(nil), cfg.Peers...)
	cfg.Peers[0].ConnectionRole = RoleClient
	cfg.HTTP3TCPListen = "127.0.0.1:443"
	if _, err := NewFactory(cfg); err == nil {
		t.Fatal("client-only config opened public listener")
	}
	cfg.HTTP3TCPListen = ""
	cfg.HTTP3 = false
	cfg.HTTP3URL = ""
	cfg.Peers[0].HTTP3URL = ""
	if _, err := NewFactory(cfg); err == nil {
		t.Fatal("explicit role changed old raw QUIC behavior")
	}
}

func waitRoleConnections(t *testing.T, backends []*Backend, want []int) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for {
		ready := true
		for i, b := range backends {
			ready = ready && b.Snapshot()["active_connections"] == want[i]
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			for i, b := range backends {
				t.Logf("peer %d: %+v", i, b.Snapshot())
			}
			t.Fatal("role connections did not establish")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestH3ClientProactivelyConnectsForServerFirstData(t *testing.T) {
	for _, ioMode := range []string{"magicsock", "udp"} {
		t.Run(ioMode, func(t *testing.T) {
			index := 0
			pair := newTestPair(t, "http3-"+ioMode, func(c *Config) {
				c.Peers[0].ConnectionRole = []ConnectionRole{RoleClient, RoleServer}[index]
				if index == 1 && ioMode == "udp" {
					c.Peers[0].Endpoint = ""
				} // dynamic client address learned via authenticated session
				index++
			})
			for cycle := 0; cycle < 2; cycle++ {
				fns := pair.open(t)
				waitRoleConnections(t, pair.backends[:], []int{1, 1})
				if pair.backends[0].active.Load().listener != nil {
					t.Fatal("outbound-only node exposed QUIC server")
				}
				if pair.backends[1].Counters().DialAttempts.Load() != 0 {
					t.Fatal("server initiated TLS")
				}
				if pair.backends[0].Snapshot()["client_connections"] != 1 || pair.backends[1].Snapshot()["server_connections"] != 1 {
					t.Fatal("actual role not reported")
				}
				before := [2]uint64{pair.backends[0].Counters().Connections.Load(), pair.backends[1].Counters().Connections.Load()}
				// Server's application speaks FIRST; client never sent an inner packet
				// to cause the connection. Reverse traffic retains the same TLS roles.
				for _, i := range []int{1, 0, 1, 0} {
					k := pair.keys[i^1].Public().Raw32()
					ep, err := pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(k[:]))
					if err != nil {
						t.Fatal(err)
					}
					want := bytes.Repeat([]byte{0x45, byte(i), byte(cycle)}, 300)
					if err := pair.backends[i].Bind().Send([][]byte{want}, ep, 0); err != nil {
						t.Fatal(err)
					}
					if got := readOne(t, fns[i^1]); !bytes.Equal(got, want) {
						t.Fatal("payload corrupted")
					}
				}
				for i, b := range pair.backends {
					if b.Counters().Connections.Load() != before[i] {
						t.Fatal("traffic direction recreated QUIC connection")
					}
					if err := b.Bind().Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestH3ServerWaitIsCancellableAndNeverDials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := &Backend{host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return true }}}
	b.identityOK.Store(true)
	p := &peer{g: &generation{b: b, ctx: ctx}, cfg: peerConfig{role: RoleServer}}
	done := make(chan error, 1)
	go func() { _, err := p.getSession(); done <- err }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server wait leaked")
	}
	if b.Counters().DialAttempts.Load() != 0 {
		t.Fatal("server silently dialed")
	}
}

// multiRoleBind maps logical node identities onto real localhost UDP endpoints.
// It is not a NAT emulator: test assertions cover roles/CID multiplexing only.
type multiRoleBind struct {
	conn.Bind
	mu        sync.Mutex
	endpoints map[string]string
}

func (b *multiRoleBind) ParseEndpoint(k string) (conn.Endpoint, error) {
	b.mu.Lock()
	s, ok := b.endpoints[k]
	b.mu.Unlock()
	if !ok {
		return nil, ErrUnknownPeer
	}
	return b.Bind.ParseEndpoint(s)
}

func TestH3OneNodeHasConcurrentClientAndServerPeers(t *testing.T) {
	const count = 4
	var keys [count]key.NodePrivate
	var bases [count]*multiRoleBind
	var bs [count]*Backend
	var configs [count]Config
	var pins [count]string
	var ports [count]uint16
	var readers [count]conn.ReceiveFunc
	roles := map[int]map[int]ConnectionRole{0: {1: RoleClient, 2: RoleClient, 3: RoleServer}, 1: {0: RoleServer}, 2: {0: RoleServer}, 3: {0: RoleClient}}
	keystr := func(i int) string { k := keys[i].Public().Raw32(); return hex.EncodeToString(k[:]) }
	for i := range count {
		keys[i] = key.NewNode()
		cert, priv, pin := testIdentity(t)
		pins[i] = pin
		configs[i] = Config{Version: 2, Payload: "ip", LocalPublicKey: keystr(i), Certificate: cert, PrivateKey: priv, IO: "magicsock", HTTP3: true, HTTP3URL: fmt.Sprintf("https://peer-%d.test:8443/connect-ip", i), InitialPacketSize: 1400}
		bases[i] = &multiRoleBind{Bind: conn.NewDefaultBind(), endpoints: make(map[string]string)}
	}
	for i := range count {
		for j, role := range roles[i] {
			configs[i].Peers = append(configs[i].Peers, PeerConfig{PublicKey: keystr(j), SPKISHA256: pins[j], HTTP3URL: configs[j].HTTP3URL, ConnectionRole: role})
			bases[i].endpoints[keystr(j)] = "127.0.0.1:9"
		}
		f, err := NewFactory(configs[i])
		if err != nil {
			t.Fatal(err)
		}
		own := i
		b, err := f.New(wgtransport.Host{Bind: bases[i], Logf: t.Logf, PeerAllowed: func(k [32]byte) bool {
			for j := range roles[own] {
				if keys[j].Public().Raw32() == k {
					return true
				}
			}
			return false
		}})
		if err != nil {
			t.Fatal(err)
		}
		bs[i] = b.(*Backend)
		t.Cleanup(func() { b.Close() })
		fs, port, err := b.Bind().Open(0)
		if err != nil {
			t.Fatal(err)
		}
		readers[i] = fs[0]
		ports[i] = port
		if port == 80 || port == 443 {
			t.Fatal("test unexpectedly used web port")
		}
	}
	for i := range count {
		bases[i].mu.Lock()
		for j := range roles[i] {
			bases[i].endpoints[keystr(j)] = fmt.Sprintf("127.0.0.1:%d", ports[j])
		}
		bases[i].mu.Unlock()
	}
	for i, b := range bs {
		b.LocalIdentityChanged(keys[i].Public().Raw32())
	}
	waitRoleConnections(t, bs[:], []int{3, 1, 1, 1})
	snapshot := bs[0].Snapshot()
	if snapshot["client_connections"] != 2 || snapshot["server_connections"] != 1 {
		t.Fatalf("roles mixed up: %+v", snapshot)
	}
	if _, ok := snapshot["connection_stats"]; ok {
		t.Fatal("multi-peer stats mislabeled one random peer as whole mesh")
	}
	if len(snapshot["peer_connections"].([]map[string]any)) != 3 {
		t.Fatal("missing per-peer stats")
	}
	if bs[3].active.Load().listener != nil {
		t.Fatal("client-only peer exposed listener")
	}
	// All six directed edges send concurrently. The central peer has a single
	// receive loop, and each payload is checked against its authenticated source.
	const rounds = 12
	errorsCh := make(chan error, 16)
	var work sync.WaitGroup
	for i := range count {
		work.Add(1)
		go func(i int) {
			defer work.Done()
			remaining := len(roles[i]) * rounds
			bufs := make([][]byte, bs[i].Bind().BatchSize())
			sizes := make([]int, len(bufs))
			eps := make([]conn.Endpoint, len(bufs))
			for j := range bufs {
				bufs[j] = make([]byte, 1500)
			}
			seen := make(map[[2]byte]bool)
			for remaining > 0 {
				n, err := readers[i](bufs, sizes, eps)
				if err != nil {
					errorsCh <- err
					return
				}
				for j := 0; j < n; j++ {
					if sizes[j] == 0 {
						continue
					}
					data := bufs[j][:sizes[j]]
					if len(data) != 1000 || int(data[1]) != i || int(data[0]) >= count {
						errorsCh <- errors.New("cross-peer payload routing")
						return
					}
					ep, ok := eps[j].(*endpoint)
					if !ok || ep.key != keys[int(data[0])].Public().Raw32() {
						errorsCh <- errors.New("wrong authenticated source")
						return
					}
					pair := [2]byte{data[0], data[2]}
					if seen[pair] {
						errorsCh <- errors.New("duplicate payload")
						return
					}
					seen[pair] = true
					remaining--
				}
			}
		}(i)
		for j := range roles[i] {
			work.Add(1)
			go func(i, j int) {
				defer work.Done()
				ep, err := bs[i].Bind().ParseEndpoint(keystr(j))
				if err != nil {
					errorsCh <- err
					return
				}
				for r := 0; r < rounds; r++ {
					payload := make([]byte, 1000)
					payload[0], payload[1], payload[2] = byte(i), byte(j), byte(r)
					if err := bs[i].Bind().Send([][]byte{payload}, ep, 0); err != nil {
						errorsCh <- err
						return
					}
				}
			}(i, j)
		}
	}
	done := make(chan struct{})
	go func() { work.Wait(); close(done) }()
	select {
	case <-done:
	case err := <-errorsCh:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("multi-peer transfer timed out")
	}
	select {
	case err := <-errorsCh:
		t.Fatal(err)
	default:
	}
	for i, b := range bs {
		if got := b.Snapshot()["active_connections"]; got != len(roles[i]) {
			t.Fatalf("node %d connections %v", i, got)
		}
	}
}
