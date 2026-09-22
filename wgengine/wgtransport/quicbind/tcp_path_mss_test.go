// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestH3FixedPathMSSLimits(t *testing.T) {
	base := Config{HTTP3: true, IO: "magicsock", InitialPacketSize: 1200}
	for _, tc := range []struct {
		name   string
		cfg    Config
		v4, v6 uint16
	}{
		{"managed", base, 1096, 1076},
		{"default", Config{HTTP3: true, IO: "magicsock"}, 1096, 1076},
		{"historical1400", Config{HTTP3: true, IO: "magicsock", InitialPacketSize: 1400}, 1296, 1276},
		{"udp-pmtu-unchanged", Config{HTTP3: true, IO: "udp", InitialPacketSize: 1200}, 0, 0},
		{"raw-quic-unchanged", Config{IO: "magicsock", InitialPacketSize: 1200}, 0, 0},
		{"reliable-stream-unchanged", Config{HTTP3: true, IO: "magicsock", TCPStreams: true, InitialPacketSize: 1200}, 0, 0},
		{"explicit-lower-cap", Config{HTTP3: true, IO: "magicsock", InitialPacketSize: 1200, TCPMSS: 800}, 800, 800},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.tcpMSSLimit(4); got != tc.v4 {
				t.Fatalf("IPv4: got %d, want %d", got, tc.v4)
			}
			if got := tc.cfg.tcpMSSLimit(6); got != tc.v6 {
				t.Fatalf("IPv6: got %d, want %d", got, tc.v6)
			}
		})
	}
}

func TestH3FixedPathMSSWireAndBatchIntegrity(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.InitialPacketSize = 1200 })
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
		g.peersMu.Lock()
		p := g.peers[pk]
		g.peersMu.Unlock()
		p.mu.Lock()
		s := p.session
		p.mu.Unlock()
		for _, v6 := range []bool{false, true} {
			for _, odd := range []bool{false, true} {
				for _, ack := range []bool{false, true} {
					packet, off := mssPacketForTest(v6, odd, 1460)
					if ack {
						packet[off+13] |= 0x10
						binary.BigEndian.PutUint16(packet[off+16:], 0)
						binary.BigEndian.PutUint16(packet[off+16:], checksumForTest(packet[off:]))
					}
					original := bytes.Clone(packet)
					want := bytes.Clone(packet)
					limit := b.factory.cfg.tcpMSSLimit(packet[0] >> 4)
					if !clampTCPMSS(want, limit) {
						t.Fatal("invalid fixture")
					}
					// A later SYN must not cause a partially accepted prefix to be
					// retried. Borrowed caller memory must remain untouched.
					before := b.counters.SentPackets.Load()
					p.sendMu.Lock()
					handled, err := p.sendIPBatch(s, [][]byte{{9, 8, 7}, packet}, 0)
					p.sendMu.Unlock()
					if handled || err != nil || b.counters.SentPackets.Load() != before {
						t.Fatal("SYN batch accepted a prefix before fallback")
					}
					if err := b.Bind().Send([][]byte{packet}, ep, 0); err != nil {
						t.Fatal(err)
					}
					got := readOne(t, fns[from^1])
					if !bytes.Equal(got, want) || checksumForTest(got[off:]) != 0 {
						t.Fatal("MSS wire bytes or incremental checksum mismatch")
					}
					if !bytes.Equal(packet, original) {
						t.Fatal("borrowed SYN was modified")
					}
				}
				// A lower offered MSS stays lower.
				low, _ := mssPacketForTest(v6, odd, 536)
				if err := b.Bind().Send([][]byte{low}, ep, 0); err != nil {
					t.Fatal(err)
				}
				if got := readOne(t, fns[from^1]); !bytes.Equal(got, low) {
					t.Fatal("lower MSS increased")
				}
			}
		}
		if got := b.counters.TCPMSSClamps.Load(); got != 8 {
			t.Fatalf("clamps=%d, want 8", got)
		}
		// Steady data still batches, and negotiated large IP/UDP payloads
		// still use the unchanged bounded fragmentation path.
		for _, size := range []int{1100, 4096} {
			data := bytes.Repeat([]byte{0x70}, size)
			if err := b.Bind().Send([][]byte{data}, ep, 0); err != nil {
				t.Fatal(err)
			}
			if got := readOne(t, fns[from^1]); !bytes.Equal(got, data) {
				t.Fatal("data/fragment integrity changed")
			}
		}
		if b.counters.IPBatchPackets.Load() == 0 || b.counters.FragmentedPackets.Load() == 0 {
			t.Fatal("fast batch or large-packet fragmentation was disabled")
		}
	}
}

func FuzzH3FixedPathSYNFilter(f *testing.F) {
	packet, _ := mssPacketForTest(false, false, 1460)
	f.Add(packet)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Any packet that the full validator can change must enter the SYN
		// slow path. The quick gate may overmatch but must not miss a rewrite.
		copy := bytes.Clone(data)
		if clampTCPMSS(copy, 1096) && !isTCPSYN(data) {
			t.Fatal("batch gate missed MSS rewrite")
		}
	})
}
