// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgtransport

import "testing"

type snapshotBackend struct {
	testBackend
	values map[string]any
}

func (b *snapshotBackend) Snapshot() map[string]any { return b.values }

func TestSnapshotUsesActualBackendAndDoesNotInventFallback(t *testing.T) {
	var absent *Manager
	if absent.Snapshot()["diagnostics_available"] != false {
		t.Fatal("nil manager claimed diagnostics")
	}
	if (&Manager{mode: Native}).Snapshot()["quic"] != false {
		t.Fatal("native snapshot")
	}
	unknown := (&Manager{mode: QUICIP, backend: &testBackend{}}).Snapshot()
	if unknown["diagnostics_available"] != false {
		t.Fatal("unknown backend claimed counters")
	}
	if _, exists := unknown["quic"]; exists {
		t.Fatal("unavailable counters falsely classified QUIC/native")
	}
	b := &snapshotBackend{values: map[string]any{"quic": true, "sent_packets": uint64(12)}}
	s := (&Manager{mode: QUICIP, backend: b}).Snapshot()
	if s["mode"] != "quic-ip" || s["sent_packets"] != uint64(12) || s["diagnostics_available"] != true {
		t.Fatalf("snapshot=%+v", s)
	}
	if _, exists := b.values["mode"]; exists {
		t.Fatal("snapshot mutated backend-owned map")
	}
}
