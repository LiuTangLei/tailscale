// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

// PacketTransportDiagnostics returns the running carrier's sanitized counters.
// It is intentionally optional rather than part of Engine: hosts and wrappers
// without carrier diagnostics must report unavailable instead of false native
// status. This method does not read or mutate persistent transport profiles.
func (e *userspaceEngine) PacketTransportDiagnostics() map[string]any {
	stats := e.transport.Snapshot()
	// Report accepted capability, not merely a compiled call site. Older
	// TUN modules and non-Linux devices must not claim this optimization.
	stats["tun_ready_read_batching"] = e.tunReadBatching
	return stats
}
