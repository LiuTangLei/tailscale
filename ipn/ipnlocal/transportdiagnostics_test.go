// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"tailscale.com/tsd"
	"tailscale.com/wgengine"
)

type transportDiagnosticTestEngine struct{ wgengine.Engine }

func (*transportDiagnosticTestEngine) PacketTransportDiagnostics() map[string]any {
	return map[string]any{"mode": "http3-ip", "diagnostics_available": true, "handshake_errors": uint64(7)}
}

func TestPacketTransportDiagnosticsReportsActualEngine(t *testing.T) {
	sys := new(tsd.System)
	sys.Engine.Set(&transportDiagnosticTestEngine{})
	b := &LocalBackend{sys: sys}
	got, err := b.PacketTransportDiagnostics()
	if err != nil || got["mode"] != "http3-ip" || got["handshake_errors"] != uint64(7) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestPacketTransportDiagnosticsUnavailableIsNotNative(t *testing.T) {
	for _, b := range []*LocalBackend{{}, {sys: new(tsd.System)}} {
		if got, err := b.PacketTransportDiagnostics(); err == nil || got != nil {
			t.Fatalf("unavailable engine returned %v, %v", got, err)
		}
	}
	sys := new(tsd.System)
	sys.Engine.Set(struct{ wgengine.Engine }{})
	if got, err := (&LocalBackend{sys: sys}).PacketTransportDiagnostics(); err == nil || got != nil {
		t.Fatalf("unsupported engine returned %v, %v", got, err)
	}
}
