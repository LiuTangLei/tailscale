// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
)

type readyVectorTestBind struct{ conn.Bind }

func (*readyVectorTestBind) BatchSize() int { return 32 }

func TestH3AuthenticatedReadyVectorAvoidsActorCopy(t *testing.T) {
	pair := newTestPair(t, "http3-udp")
	for _, b := range pair.backends {
		b.host.Bind = &readyVectorTestBind{b.host.Bind}
	}
	fns := pair.open(t)
	b := pair.backends[0]
	key := pair.keys[1].Public().Raw32()
	ep, err := b.Bind().ParseEndpoint(hex.EncodeToString(key[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Bind().Send([][]byte{{1, 2, 3}}, ep, 0); err != nil {
		t.Fatal(err)
	}
	_ = readOne(t, fns[1])
	p := b.active.Load().peers[key]
	p.mu.Lock()
	s := p.session
	p.mu.Unlock()
	if _, ok := s.dgram.(*http3Channel).stream.(datagramBatchSender); !ok {
		t.Skip("batch dependency not selected")
	}
	// Wait for the cold-start actor to finish its bookkeeping; it is not the
	// subject of the established-session fast-path check.
	deadline := time.Now().Add(time.Second)
	for p.connectingPacket.Load() {
		if time.Now().After(deadline) {
			t.Fatal("startup actor did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	buffers := make([][]byte, 8)
	for i := range buffers {
		buffers[i] = append(make([]byte, 8), bytes.Repeat([]byte{byte(i + 20)}, 1000+i)...)
	}
	before := b.counters.IPBatchPackets.Load()
	// An established send must not need the actor's queue lock or retain caller
	// buffers. A timeout unlocks first, so regressions cannot hang test cleanup.
	p.queueMu.Lock()
	done := make(chan error, 1)
	go func() { done <- b.Bind().Send(buffers, ep, 8) }()
	select {
	case err := <-done:
		p.queueMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		p.queueMu.Unlock()
		<-done
		t.Fatal("ready vector still passed through actor queue")
	}
	for _, buf := range buffers {
		clear(buf)
	}
	for range 8 {
		data := readOne(t, fns[1])
		id := int(data[0]) - 20
		if id < 0 || id >= 8 || len(data) != 1000+id || !bytes.Equal(data, bytes.Repeat([]byte{byte(id + 20)}, len(data))) {
			t.Fatal("borrowed vector not copied before return")
		}
	}
	if b.counters.IPBatchPackets.Load()-before != 8 {
		t.Fatal("ready vector did not use H3 batch API")
	}
}
