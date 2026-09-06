// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

// PacketTransportDiagnostics returns the running carrier's sanitized counters.
// It is intentionally optional rather than part of Engine: hosts and wrappers
// without carrier diagnostics must report unavailable instead of false native
// status. This method does not read or mutate persistent transport profiles.
func (e *userspaceEngine) PacketTransportDiagnostics() map[string]any {
	return e.transport.Snapshot()
}
