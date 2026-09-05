// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package ipnlocal

import (
	"errors"
	"tailscale.com/ipn"
)

// Legacy AWG commands keep their normal meaning in native mode, but must not
// disable a running IP-native engine by introducing contradictory preferences.
// An unchanged historical value does not block unrelated preference updates;
// clearing AWG is always allowed as a recovery operation.
func validateAWGForTransport(mode string, current ipn.PrefsView, proposed *ipn.Prefs) error {
	if mode != "quic-ip" && mode != "http3-ip" {
		return nil
	}
	if proposed.AmneziaWG.IsZero() || (current.Valid() && current.AmneziaWG() == proposed.AmneziaWG) {
		return nil
	}
	return errors.New("AWG set/sync is not available while native QUIC-IP or HTTP/3-IP is active; stage native, restart deliberately, then configure AWG")
}
