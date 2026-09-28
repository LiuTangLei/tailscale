// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import "errors"

// PacketTransportDiagnostics returns this server's active carrier counters,
// including when the carrier was loaded from a managed profile rather than
// injected through Server.Transport. Like LocalClient, it starts s if needed.
// The result contains no private keys or packet contents. Missing diagnostics
// is an error, never a claim that the server silently fell back to WireGuard.
func (s *Server) PacketTransportDiagnostics() (map[string]any, error) {
	if err := s.Start(); err != nil {
		return nil, err
	}
	engine := s.sys.Engine.Get()
	diag, ok := engine.(interface{ PacketTransportDiagnostics() map[string]any })
	if !ok {
		return nil, errors.New("running engine has no packet transport diagnostics")
	}
	return diag.PacketTransportDiagnostics(), nil
}
