// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
)

// Every producer delivery contains one packet. Batching must come from ready
// queued work, not a sleep or an already-large OS TUN vector.
func TestH3SingleCoreOnePacketProducerFormsBatches(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	pair := newTestPair(t, "http3-udp")
	fns := pair.open(t)
	timer := time.AfterFunc(10*time.Second, func() {
		for _, b := range pair.backends {
			b.Close()
		}
	})
	defer timer.Stop()
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
		t.Skip("optional unpublished batch dependency not selected")
	}
	const count = 128
	packet := bytes.Repeat([]byte{0x5a}, 1000)
	startCalls, startPackets := b.counters.IPBatchCalls.Load(), b.counters.IPBatchPackets.Load()
	for i := range count {
		binary.BigEndian.PutUint16(packet[:2], uint16(i))
		if err := b.Bind().Send([][]byte{packet}, ep, 0); err != nil {
			t.Fatal(err)
		}
	}
	clear(packet)
	buffers := make([][]byte, 16)
	for i := range buffers {
		buffers[i] = make([]byte, 2048)
	}
	sizes := make([]int, len(buffers))
	endpoints := make([]conn.Endpoint, len(buffers))
	seen := make(map[uint16]bool)
	for len(seen) < count {
		n, err := fns[1](buffers, sizes, endpoints)
		if err != nil {
			t.Fatal(err)
		}
		for i := range n {
			data := buffers[i][:sizes[i]]
			if len(data) != 1000 {
				t.Fatal("short packet")
			}
			id := binary.BigEndian.Uint16(data[:2])
			if id >= count || seen[id] || !bytes.Equal(data[2:], bytes.Repeat([]byte{0x5a}, 998)) {
				t.Fatal("producer ownership or delivery corrupted")
			}
			seen[id] = true
		}
	}
	calls := b.counters.IPBatchCalls.Load() - startCalls
	packets := b.counters.IPBatchPackets.Load() - startPackets
	if packets != count || calls >= packets {
		t.Fatalf("single-packet producer did not batch: packets=%d calls=%d", packets, calls)
	}
	t.Logf("%d single-packet sends delivered with %d H3 queue batch calls", packets, calls)
}
