// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import "errors"

// PacketTransportDiagnostics returns only the running engine's sanitized
// counters. Lack of diagnostics is never reported as a native-mode fallback.
func (b *LocalBackend) PacketTransportDiagnostics() (map[string]any, error) {
	if b.sys == nil {
		return nil, errors.New("running engine unavailable")
	}
	engine, ok := b.sys.Engine.GetOK()
	if !ok || engine == nil {
		return nil, errors.New("running engine unavailable")
	}
	diag, ok := engine.(interface{ PacketTransportDiagnostics() map[string]any })
	if !ok {
		return nil, errors.New("running engine has no packet transport diagnostics")
	}
	return diag.PacketTransportDiagnostics(), nil
}
