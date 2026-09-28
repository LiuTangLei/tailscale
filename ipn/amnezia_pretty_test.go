// Copyright (c) 2026 Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"strings"
	"testing"
)

func TestMaskedPrefsPrettyAWGRedacted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile AmneziaWGPrefs
		want    string
	}{
		{"enabled", AmneziaWGPrefs{JC: 4, HeaderProtectionKey: strings.Repeat("42", 32), I1: "private-packet-signature"}, "MaskedPrefs{AmneziaWG=configured}"},
		{"reset", AmneziaWGPrefs{}, "MaskedPrefs{AmneziaWG=disabled}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mp := &MaskedPrefs{Prefs: Prefs{AmneziaWG: tc.profile}, AmneziaWGSet: true}
			if got := mp.Pretty(); got != tc.want {
				t.Fatalf("Pretty() = %q; want %q", got, tc.want)
			}
		})
	}
}
