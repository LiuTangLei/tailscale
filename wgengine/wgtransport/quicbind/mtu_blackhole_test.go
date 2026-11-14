// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
)

// mtuLimitedBind models a path that silently discards oversized UDP payloads.
// It does not fake a TLS handshake or skip the actual HTTP/3 authentication.
type mtuLimitedBind struct {
	conn.Bind
	limit atomic.Int64
	drops atomic.Int64
	// oddDrops counts dropped packets that were not of the probed size.
	probeSize, oddDrops atomic.Int64
}

func (b *mtuLimitedBind) Send(packets [][]byte, endpoint conn.Endpoint, offset int) error {
	accepted := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		if int64(len(packet)-offset) > b.limit.Load() {
			b.drops.Add(1)
			if int64(len(packet)-offset) != b.probeSize.Load() {
				b.oddDrops.Add(1)
			}
			continue // UDP reports successful local transmission, not delivery.
		}
		accepted = append(accepted, packet)
	}
	if len(accepted) == 0 {
		return nil
	}
	return b.Bind.Send(accepted, endpoint, offset)
}

func TestHTTP3InitialMTUBlackhole(t *testing.T) {
	for _, initial := range []uint16{1400, 1200} {
		name := "safe_1200"
		if initial == 1400 {
			name = "old_1400_blackholes"
		}
		t.Run(name, func(t *testing.T) {
			pair := newTestPair(t, "http3-magicsock", func(c *Config) {
				c.InitialPacketSize = initial
				c.AutoTrust = true
			})
			var links [2]*mtuLimitedBind
			for i := range links {
				links[i] = &mtuLimitedBind{Bind: pair.bases[i].Bind}
				links[i].limit.Store(1200)
				links[i].probeSize.Store(defaultMaxPacketSize)
				pair.bases[i].Bind = links[i]
			}
			receive := pair.open(t)
			remote := pair.keys[1].Public().Raw32()
			endpoint, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
			if err != nil {
				t.Fatal(err)
			}
			peer, err := pair.backends[0].active.Load().peer(remote, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			session, err := peer.getSessionContext(ctx, nil)
			if initial == 1400 {
				if err == nil || session != nil || links[0].drops.Load() == 0 {
					t.Fatalf("old Initial must be silently lost: session=%v err=%v drops=%d", session != nil, err, links[0].drops.Load())
				}
				t.Logf("old 1400-byte Initial failed as expected; oversized datagrams dropped=%d", links[0].drops.Load())
				return
			}
			if err != nil || session == nil {
				t.Fatalf("1200-byte Initial did not authenticate over the restricted path: %v", err)
			}
			for i := range 2 {
				other := pair.keys[i^1].Public().Raw32()
				endpoint, err = pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(other[:]))
				if err != nil {
					t.Fatal(err)
				}
				for _, size := range []int{32, 1280, 2048, 16000} {
					payload := bytes.Repeat([]byte{byte(41 + i)}, size)
					wire := append(make([]byte, 8), payload...)
					if err := pair.backends[i].Bind().Send([][]byte{wire}, endpoint, 8); err != nil {
						t.Fatal(err)
					}
					if got := readOne(t, receive[i^1]); !bytes.Equal(got, payload) {
						t.Fatalf("direction %d size %d payload mismatch", i, size)
					}
				}
			}
			// The only packets above the path limit are the few probes of the
			// larger size. They are lost, and the size is never used.
			if odd := links[0].oddDrops.Load() + links[1].oddDrops.Load(); odd != 0 {
				t.Fatalf("safe magicsock transport exceeded the path limit: %d packets that were not probes", odd)
			}
			if drops := links[0].drops.Load() + links[1].drops.Load(); drops > 8 {
				t.Fatalf("too many probes of a size the path does not carry: %d", drops)
			}
			if size := session.q.PacketSize(); size != 1200 {
				t.Fatalf("packet size %d in use on a 1200-byte path", size)
			}
		})
	}
}
