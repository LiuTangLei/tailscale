// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgtransport

import "maps"

// Snapshot returns cold-path counters from this manager's actual backend, not
// the last backend that happened to be constructed with a shared Factory.
// Backends that implement Snapshot must expose no private identity material or
// packet contents, and must permit calls concurrent with their lifecycle.
func (m *Manager) Snapshot() map[string]any {
	if m == nil {
		return map[string]any{"diagnostics_available": false}
	}
	if m.mode == Native {
		return map[string]any{"mode": string(Native), "quic": false, "diagnostics_available": true}
	}
	if backend, ok := m.backend.(interface{ Snapshot() map[string]any }); ok {
		out := maps.Clone(backend.Snapshot())
		if out == nil {
			out = make(map[string]any)
		}
		out["mode"] = string(m.mode)
		out["diagnostics_available"] = true
		return out
	}
	// An absent diagnostics interface is not evidence of native fallback.
	return map[string]any{"mode": string(m.mode), "diagnostics_available": false}
}
