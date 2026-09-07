// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/wgengine/wgtransport"
)

type actorTestBind struct {
	conn.Bind
	parse func(string)
}

func (b *actorTestBind) ParseEndpoint(k string) (conn.Endpoint, error) {
	if b.parse != nil {
		b.parse(k)
	}
	return b.Bind.ParseEndpoint("127.0.0.1:9")
}

func newActorTestGeneration(t *testing.T) (*generation, *actorTestBind) {
	t.Helper()
	bind := &actorTestBind{Bind: conn.NewDefaultBind()}
	b := &Backend{
		factory: &Factory{local: [32]byte{255}, cfg: Config{AutoTrust: true, HTTP3: true, QueuePackets: 2}},
		host:    wgtransport.Host{Bind: bind, PeerAllowed: func([32]byte) bool { return true }},
	}
	b.identityOK.Store(true)
	b.initServerHints()
	ctx, cancel := context.WithCancel(context.Background())
	g := &generation{b: b, ctx: ctx, cancel: cancel, peers: make(map[[32]byte]*peer)}
	b.active.Store(g)
	t.Cleanup(func() { cancel(); g.workers.Wait() })
	return g, bind
}

func actorTestKey(n int) (k [32]byte) {
	binary.LittleEndian.PutUint32(k[:4], uint32(n+1))
	k[31] = 1
	return k
}

func addTestActor(t *testing.T, g *generation, n int) *peer {
	t.Helper()
	p, err := g.peer(actorTestKey(n), nil)
	if err != nil {
		t.Fatalf("create peer %d: %v", n, err)
	}
	return p
}

func awaitRetiredActor(t *testing.T, p *peer) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("retired actor retained its worker")
	}
}

func TestAutoTrustReclaimsRevokedActorsAcrossKeyRotation(t *testing.T) {
	g, _ := newActorTestGeneration(t)
	var rotating *peer
	for i := range maxPeers {
		rotating = addTestActor(t, g, i)
	}
	if _, err := g.peer(actorTestKey(maxPeers), nil); err == nil {
		t.Fatal("actor limit evicted an authorized live peer")
	}
	original := rotating
	originalStamp := original.lifecycleStamp()
	// Keep 255 peers live while another node rotates more than 256 times.
	for i := maxPeers; i < 2*maxPeers+32; i++ {
		g.b.PeerRemoved(rotating.cfg.key)
		old := rotating
		rotating = addTestActor(t, g, i)
		awaitRetiredActor(t, old)
		if !old.retired.Load() || old.stampValid(old.lifecycleStamp()) {
			t.Fatal("evicted actor remained usable")
		}
		if len(g.peers) != maxPeers || len(g.b.serverHints) != maxPeers {
			t.Fatal("peer actors or server hints escaped their bound")
		}
	}
	g.b.PeerRemoved(rotating.cfg.key)
	rejoined := addTestActor(t, g, maxPeers-1)
	if rejoined == original || original.stampValid(originalStamp) {
		t.Fatal("re-adding the old key resurrected its retired actor or lifecycle")
	}
}

func TestRevivalCannotRestoreAnActorRetiredDuringEndpointLookup(t *testing.T) {
	g, bind := newActorTestGeneration(t)
	old := addTestActor(t, g, 0)
	for i := 1; i < maxPeers; i++ {
		addTestActor(t, g, i)
	}
	g.b.PeerRemoved(old.cfg.key)
	oldStamp := old.lifecycleStamp()
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	oldKey := hex.EncodeToString(old.cfg.key[:])
	bind.parse = func(k string) {
		if k == oldKey && calls.Add(1) == 2 {
			close(entered)
			<-release
		}
	}
	type result struct {
		p   *peer
		err error
	}
	finished := make(chan result, 1)
	go func() { p, err := g.peer(old.cfg.key, nil); finished <- result{p, err} }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("revival did not reach host endpoint refresh")
	}
	replacement := addTestActor(t, g, maxPeers)
	awaitRetiredActor(t, old)
	g.b.PeerRemoved(replacement.cfg.key)
	// Release the blocked lookup without racing a double close in cleanup.
	release <- struct{}{}
	select {
	case got := <-finished:
		if got.err != nil || got.p == old || got.p == nil || got.p.retired.Load() {
			t.Fatalf("revival returned retired actor: %p, %v", got.p, got.err)
		}
		if old.stampValid(oldStamp) {
			t.Fatal("old authentication attempt crossed actor retirement/re-addition")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revival did not finish after endpoint refresh")
	}
}

func TestRetiredActorDrainsAnEnqueueAlreadyInProgress(t *testing.T) {
	g, _ := newActorTestGeneration(t)
	old := addTestActor(t, g, 0)
	for i := 1; i < maxPeers; i++ {
		addTestActor(t, g, i)
	}
	g.b.PeerRemoved(old.cfg.key)
	// A sender may win its queue select just as cancellation becomes ready.
	// The final drain must wait for that in-flight sender to leave queueMu.
	old.queueMu.RLock()
	addTestActor(t, g, maxPeers)
	packet := acquirePacket([]byte{1, 2, 3, 4})
	packet.stamp = old.lifecycleStamp()
	g.txBytes.Add(int64(len(packet.data)))
	old.tx <- packet
	old.queueMu.RUnlock()
	awaitRetiredActor(t, old)
	if g.txBytes.Load() != 0 || len(old.tx) != 0 {
		t.Fatal("retirement leaked a concurrently enqueued packet or its byte budget")
	}
}

func TestStoppedActorRejectsEnqueuesAfterFinalDrain(t *testing.T) {
	g, _ := newActorTestGeneration(t)
	p := addTestActor(t, g, 0)
	g.cancel()
	awaitRetiredActor(t, p)
	// Normal generation shutdown does not set retired. Already-entered Send
	// calls still must not append to an actor after its final drain completes.
	for range 128 {
		if err := p.enqueue([][]byte{{1, 2, 3, 4}}, 0); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("enqueue after generation shutdown: %v", err)
		}
	}
	if g.txBytes.Load() != 0 || len(p.tx) != 0 {
		t.Fatal("late sender leaked packets after the generation's final drain")
	}
}

func TestRevivalCannotCrossNewerRemovalDuringEndpointLookup(t *testing.T) {
	g, bind := newActorTestGeneration(t)
	p := addTestActor(t, g, 0)
	g.b.PeerRemoved(p.cfg.key)
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	bind.parse = func(string) {
		if calls.Add(1) == 2 {
			close(entered)
			<-release
		}
	}
	finished := make(chan error, 1)
	go func() { _, err := g.peer(p.cfg.key, nil); finished <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("revival did not reach endpoint refresh")
	}
	g.b.PeerRemoved(p.cfg.key)
	release <- struct{}{}
	select {
	case err := <-finished:
		if !errors.Is(err, ErrUnknownPeer) || !p.disabled.Load() {
			t.Fatalf("stale endpoint refresh revived a newly removed actor: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint refresh did not finish")
	}
	if _, err := g.peer(p.cfg.key, nil); err != nil {
		t.Fatalf("fresh revival could not use the current lifecycle: %v", err)
	}
}

func TestActorReplacementSerializesHostNotifications(t *testing.T) {
	g, _ := newActorTestGeneration(t)
	old := addTestActor(t, g, 0)
	for i := 1; i < maxPeers; i++ {
		addTestActor(t, g, i)
	}
	g.b.PeerRemoved(old.cfg.key)
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	events := make(chan wgtransport.SessionState, 3)
	g.b.host.SessionChanged = func(_ [32]byte, state wgtransport.SessionState) {
		if state == wgtransport.SessionExpired {
			close(entered)
			<-release
		}
		events <- state
	}
	oldDone := make(chan struct{})
	go func() { old.publishState(wgtransport.SessionExpired); close(oldDone) }()
	<-entered
	replacement := addTestActor(t, g, maxPeers)
	g.b.PeerRemoved(replacement.cfg.key)
	rejoined := addTestActor(t, g, 0)
	newStarted, newDone := make(chan struct{}), make(chan struct{})
	go func() {
		close(newStarted)
		rejoined.publishState(wgtransport.SessionHandshake)
		close(newDone)
	}()
	<-newStarted
	select {
	case <-newDone:
		t.Fatal("replacement callback overtook an old notification still in progress")
	case <-time.After(30 * time.Millisecond):
	}
	release <- struct{}{}
	<-oldDone
	<-newDone
	if first, second := <-events, <-events; first != wgtransport.SessionExpired || second != wgtransport.SessionHandshake {
		t.Fatalf("host notification order = %v, %v", first, second)
	}
	old.publishState(wgtransport.SessionExpired)
	select {
	case event := <-events:
		t.Fatalf("retired actor delivered a late host notification: %v", event)
	default:
	}
}
