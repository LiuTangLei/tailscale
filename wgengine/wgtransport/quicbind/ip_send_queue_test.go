// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"context"
	"testing"

	"tailscale.com/wgengine/wgtransport"
)

func TestQueuedIPBatchDoesNotReviveOldAuthorization(t *testing.T) {
	for _, reset := range []string{"peer", "local-identity"} {
		t.Run(reset, func(t *testing.T) {
			b := &Backend{host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return true }}}
			b.identityOK.Store(true)
			g := &generation{b: b, ctx: context.Background()}
			p := &peer{g: g, ctx: context.Background(), tx: make(chan *packetBuffer, 2)}
			first := acquirePacket([]byte{1, 2, 3})
			second := acquirePacket([]byte{4, 5, 6})
			first.stamp, second.stamp = p.lifecycleStamp(), p.lifecycleStamp()
			g.txBytes.Store(6)
			p.tx <- second
			if reset == "peer" {
				p.epoch.Add(1)
			} else {
				b.identityEpoch.Add(1)
			}
			// The live policy again allows the peer, but queued data belongs to
			// the old lifecycle. Reaching getSession would fail this fixture.
			p.sendQueuedIPBatch(first)
			if g.txBytes.Load() != 0 || len(p.tx) != 0 || p.connectingPacket.Load() {
				t.Fatal("stale queue budget or worker ownership was retained")
			}
			if b.counters.SendQueueDrops.Load() != 2 || b.counters.SentPackets.Load() != 0 {
				t.Fatal("old queued data survived identity revocation")
			}
		})
	}
}
