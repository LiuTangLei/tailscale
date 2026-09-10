// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestH3ReadyIPBatchWireIntegrity(t *testing.T) {
	pair := newTestPair(t, "http3-udp")
	fns := pair.open(t)
	for from := range 2 {
		b := pair.backends[from]
		pk := pair.keys[from^1].Public().Raw32()
		ep, err := b.Bind().ParseEndpoint(hex.EncodeToString(pk[:]))
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Bind().Send([][]byte{{1, 2, 3}}, ep, 0); err != nil {
			t.Fatal(err)
		}
		_ = readOne(t, fns[from^1])
		g := b.active.Load()
		p := g.peers[pk]
		p.mu.Lock()
		s := p.session
		p.mu.Unlock()
		if _, ok := s.dgram.(*http3Channel).stream.(datagramBatchSender); !ok {
			t.Skip("optional unpublished batch dependency not selected")
		}
		for _, large := range []bool{false, true} {
			count := min(8, b.Bind().BatchSize())
			// Exercise the batch function directly on platforms where the OS Bind
			// reports a batch size of one; the carrier's real Linux path uses it.
			count = max(2, count)
			bufs := make([][]byte, count)
			originals := make([][]byte, count)
			for i := range bufs {
				size := 900 + i*10
				if large && i == 1 {
					size = 4096
				}
				originals[i] = bytes.Repeat([]byte{byte(i + 20)}, size)
				bufs[i] = append(make([]byte, 8), originals[i]...)
			}
			p.sendMu.Lock()
			handled, err := p.sendIPBatch(s, bufs, 8)
			p.sendMu.Unlock()
			if !handled || err != nil {
				t.Fatalf("handled %v error %v", handled, err)
			}
			seen := map[byte]bool{}
			for range bufs {
				got := readOne(t, fns[from^1])
				id := got[0]
				index := int(id) - 20
				if index < 0 || index >= count || seen[id] || !bytes.Equal(got, originals[index]) {
					t.Fatal("batch corrupt, duplicate or wrong source")
				}
				seen[id] = true
			}
			for i, buf := range bufs {
				if !bytes.Equal(buf[8:], originals[i]) {
					t.Fatal("batch overwrote borrowed caller data")
				}
			}
		}
		if b.counters.IPBatchPackets.Load() == 0 {
			t.Fatal("no packet entered optimized path")
		}
	}
}
