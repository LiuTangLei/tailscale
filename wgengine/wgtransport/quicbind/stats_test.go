// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"github.com/LiuTangLei/wireguard-go/conn"
	"testing"
)

func TestBackendSnapshotDoesNotFollowSharedFactoryLast(t *testing.T) {
	pair := newTestPair(t, "magicsock")
	first := pair.backends[0]
	host := first.host
	host.Bind = conn.NewDefaultBind()
	created, err := first.factory.New(host)
	if err != nil {
		t.Fatal(err)
	}
	second := created.(*Backend)
	t.Cleanup(func() { second.Close() })
	first.counters.SentPackets.Store(11)
	second.counters.SentPackets.Store(22)
	if got := first.Snapshot()["sent_packets"]; got != uint64(11) {
		t.Fatalf("first backend read another engine's counters: %v", got)
	}
	if got := second.Snapshot()["sent_packets"]; got != uint64(22) {
		t.Fatalf("second counters: %v", got)
	}
}
