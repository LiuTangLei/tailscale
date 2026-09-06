// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestH3ClientWarmupNeedsLiveHostAuthorization(t *testing.T) {
	i := 0
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.Peers[0].ConnectionRole = []ConnectionRole{RoleClient, RoleServer}[i]; i++ })
	var permitted atomic.Bool
	pair.backends[0].host.PeerAllowed = func([32]byte) bool { return permitted.Load() }
	pair.open(t)
	time.Sleep(650 * time.Millisecond)
	if pair.backends[0].Counters().DialAttempts.Load() != 0 {
		t.Fatal("pinned but unauthorized peer was dialed")
	}
	permitted.Store(true)
	waitRoleConnections(t, pair.backends[:], []int{1, 1})
	permitted.Store(false)
	pair.backends[0].PeerRemoved(pair.keys[1].Public().Raw32())
	attempts := pair.backends[0].Counters().DialAttempts.Load()
	time.Sleep(650 * time.Millisecond)
	if pair.backends[0].Counters().DialAttempts.Load() != attempts || pair.backends[0].Snapshot()["active_connections"] != 0 {
		t.Fatal("client role resurrected revoked peer")
	}
}
