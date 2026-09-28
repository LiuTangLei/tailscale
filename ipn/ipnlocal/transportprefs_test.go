// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package ipnlocal

import (
	"tailscale.com/ipn"
	"testing"
)

func TestAWGPreferencesCannotDisableQUIC(t *testing.T) {
	empty := &ipn.Prefs{}
	awg := &ipn.Prefs{AmneziaWG: ipn.AmneziaWGPrefs{JC: 1, JMin: 50, JMax: 100}}
	for _, mode := range []string{"native", "quic-ip", "http3-ip"} {
		err := validateAWGForTransport(mode, empty.View(), awg)
		if (err != nil) != (mode != "native") {
			t.Fatalf("%s: %v", mode, err)
		}
		if err := validateAWGForTransport(mode, awg.View(), empty); err != nil {
			t.Fatal("reset blocked", err)
		}
		if err := validateAWGForTransport(mode, awg.View(), awg); err != nil {
			t.Fatal("unchanged historical config blocked", err)
		}
	}
}
