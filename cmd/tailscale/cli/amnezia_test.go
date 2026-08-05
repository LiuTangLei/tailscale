// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestAmneziaConfigVersionCompatibility(t *testing.T) {
	v2 := ipn.AmneziaWGPrefs{
		JC:   4,
		JMin: 40,
		JMax: 70,
		S1:   5,
		S2:   7,
		S3:   9,
		S4:   11,
		H1:   ipn.MagicHeaderRange{Min: 1001, Max: 1001},
		H2:   ipn.MagicHeaderRange{Min: 1002, Max: 1002},
		H3:   ipn.MagicHeaderRange{Min: 1003, Max: 1003},
		H4:   ipn.MagicHeaderRange{Min: 1004, Max: 1004},
	}
	if err := validateAmneziaWGConfig(v2); err != nil {
		t.Fatalf("valid AWG v2 config rejected: %v", err)
	}
	if got := amneziaConfigVersion(v2); got != "AWG v2" {
		t.Fatalf("v2 config version = %q", got)
	}

	v3 := v2
	v3.S1, v3.S2, v3.S3, v3.S4 = 12, 13, 14, 15
	v3.HeaderProtectionKey = strings.Repeat("42", 32)
	v3.ContentPaddingAddition = ipn.MagicHeaderRange{Min: 5, Max: 31}
	if err := validateAmneziaWGConfig(v3); err != nil {
		t.Fatalf("valid AWG v3 config rejected: %v", err)
	}
	if got := amneziaConfigVersion(v3); got != "AWG v3" {
		t.Fatalf("v3 config version = %q", got)
	}

	v3.S1 = 11
	if err := validateAmneziaWGConfig(v3); err == nil || !strings.Contains(err.Error(), "S1 must be at least 12") {
		t.Fatalf("short AWG v3 padding error = %v", err)
	}

	if got := amneziaConfigVersion(ipn.AmneziaWGPrefs{}); got != "standard WireGuard" {
		t.Fatalf("zero config version = %q", got)
	}
}
