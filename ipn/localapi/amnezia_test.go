// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"testing"

	"tailscale.com/ipn"
)

func TestIsAmneziaWGZeroIncludesV3Fields(t *testing.T) {
	if !isAmneziaWGZero(ipn.AmneziaWGPrefs{}) {
		t.Fatal("zero AWG config reported as enabled")
	}
	if isAmneziaWGZero(ipn.AmneziaWGPrefs{
		RekeyAfterTime: ipn.MagicHeaderRange{Min: 120, Max: 180},
	}) {
		t.Fatal("v3-only AWG config reported as zero")
	}
}
