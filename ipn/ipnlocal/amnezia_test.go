// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"strings"
	"testing"

	"tailscale.com/envknob"
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

func TestValidateAmneziaWGPrefsChangeValidatesEffectiveConfig(t *testing.T) {
	envknob.Setenv("TS_AMNEZIA_HEADER_PROTECTION_KEY", strings.Repeat("42", 32))
	defer envknob.Setenv("TS_AMNEZIA_HEADER_PROTECTION_KEY", "")

	current := (&ipn.Prefs{}).View()
	// This is a valid historical v2 profile on its own, but the configured
	// environment overlay enables v3 header protection and therefore requires
	// every S padding value to be at least 12.
	proposed := &ipn.Prefs{AmneziaWG: ipn.AmneziaWGPrefs{S1: 10, S2: 15, S3: 8}}
	err := validateAmneziaWGPrefsChange(current, proposed)
	if err == nil || !strings.Contains(err.Error(), "S1 must be at least 12") {
		t.Fatalf("effective AWG validation error = %v, want v3 padding error", err)
	}

	// An unchanged historical profile must remain compatible with unrelated
	// LocalAPI edits even if today's effective-profile validator rejects it.
	legacy := &ipn.Prefs{AmneziaWG: ipn.AmneziaWGPrefs{I1: "<c>"}}
	unchanged := legacy.Clone()
	unchanged.CorpDNS = true
	if err := validateAmneziaWGPrefsChange(legacy.View(), unchanged); err != nil {
		t.Fatalf("unchanged historical profile rejected: %v", err)
	}
}
