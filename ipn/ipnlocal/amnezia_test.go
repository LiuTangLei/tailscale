// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestValidateAmneziaWGPrefsChangePreservesUnrelatedLocalAPIEdits(t *testing.T) {
	// A legacy profile containing <c> is no longer applicable by the current
	// AWG core. It must not prevent Android/iOS from changing an unrelated pref.
	current := &ipn.Prefs{AmneziaWG: ipn.AmneziaWGPrefs{I1: "<c>"}}
	proposed := current.Clone()
	proposed.CorpDNS = true
	if err := validateAmneziaWGPrefsChange(current.View(), proposed); err != nil {
		t.Fatalf("unrelated preference edit rejected: %v", err)
	}

	proposed.AmneziaWG = ipn.AmneziaWGPrefs{I1: "<b 0xc0><r 32>"}
	if err := validateAmneziaWGPrefsChange(current.View(), proposed); err != nil {
		t.Fatalf("valid historical v2 replacement rejected: %v", err)
	}

	proposed.AmneziaWG.I1 = "<b 0xc0>\nprivate_key=00"
	err := validateAmneziaWGPrefsChange(current.View(), proposed)
	if err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("unsafe AWG replacement error = %v", err)
	}
}
