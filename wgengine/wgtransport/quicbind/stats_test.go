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

func TestConnectionSetupDiagnostics(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock")
	pair.open(t)
	p, err := pair.backends[0].active.Load().peer(pair.keys[1].Public().Raw32(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.getSession(); err != nil {
		t.Fatal(err)
	}
	setup := p.setup.Load()
	if setup == nil || setup.Stage != "established" || setup.TLSMicros <= 0 || setup.TotalMicros < setup.TLSMicros+setup.SettingsMicros+setup.AuthMicros {
		t.Fatalf("invalid setup timings: %+v", setup)
	}
}
