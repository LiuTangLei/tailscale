// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateAmneziaWGConfigHistoricalV2(t *testing.T) {
	config := AmneziaWGPrefs{
		JC: 10, JMin: 10, JMax: 15,
		S1: 10, S2: 15, S3: 8,
		H1: MagicHeaderRange{Min: 100000, Max: 200000},
		H2: MagicHeaderRange{Min: 300000, Max: 350000},
		H3: MagicHeaderRange{Min: 400000, Max: 450000},
		H4: MagicHeaderRange{Min: 500000, Max: 550000},
		I1: "<b 0xc0><r 32>",
	}
	if err := ValidateAmneziaWGConfig(config); err != nil {
		t.Fatalf("historical v2 configuration rejected: %v", err)
	}

	config.I1 = "<b 0xc0><t><r 32><rc 4><rd 3><d><ds><dz 2>"
	if err := ValidateAmneziaWGConfig(config); err != nil {
		t.Fatalf("supported upstream CPS tags rejected: %v", err)
	}
}

func TestValidateAmneziaWGConfigRejectsUnsafeValues(t *testing.T) {
	tests := []struct {
		name   string
		config AmneziaWGPrefs
		want   string
	}{
		{"retired-c", AmneziaWGPrefs{I1: "<b 0xc0><c>"}, "retired CPS tag <c>"},
		{"uapi-newline", AmneziaWGPrefs{I1: "<b 0xc0>\nprivate_key=00"}, "control character"},
		{"outside-text", AmneziaWGPrefs{I1: "prefix<b 0xc0>"}, "outside CPS tags"},
		{"missing-close", AmneziaWGPrefs{I1: "<r 32"}, "missing enclosing >"},
		{"unknown-tag", AmneziaWGPrefs{I1: "<nope 1>"}, "unknown CPS tag"},
		{"negative-random", AmneziaWGPrefs{I1: "<r -1>"}, "cannot be negative"},
		{"oversized-random", AmneziaWGPrefs{I1: "<r 65536>"}, "safe limit"},
		{"invalid-bytes", AmneziaWGPrefs{I1: "<b 0xz1>"}, "invalid hexadecimal"},
		{"headers-overlap-explicit", AmneziaWGPrefs{H1: MagicHeaderRange{Min: 100, Max: 200}, H2: MagicHeaderRange{Min: 200, Max: 300}}, "overlaps"},
		{"headers-overlap-default", AmneziaWGPrefs{H2: MagicHeaderRange{Min: 1, Max: 1}}, "H1 (1) overlaps H2 (1)"},
		{"junk-range", AmneziaWGPrefs{JMin: 20, JMax: 10}, "cannot be greater"},
		{"junk-count", AmneziaWGPrefs{JC: maxAmneziaJunkPackets + 1}, "safe limit"},
		{"junk-bytes", AmneziaWGPrefs{JC: 2000, JMax: 40000}, "bytes of junk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAmneziaWGConfig(tt.config)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validation error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateAmneziaWGConfigV3HeaderProtection(t *testing.T) {
	valid := AmneziaWGPrefs{
		S1: 12, S2: 13, S3: 14, S4: 15,
		HeaderProtectionKey: strings.Repeat("42", 32),
	}
	if err := ValidateAmneziaWGConfig(valid); err != nil {
		t.Fatalf("valid v3 config rejected: %v", err)
	}
	valid.S4 = 11
	if err := ValidateAmneziaWGConfig(valid); err == nil || !strings.Contains(err.Error(), "S4 must be at least 12") {
		t.Fatalf("short v3 padding validation error = %v", err)
	}

	zeroKey := AmneziaWGPrefs{HeaderProtectionKey: zeroHeaderProtectionKey}
	if zeroKey.IsV3() || !zeroKey.IsZero() {
		t.Fatalf("all-zero disabled header key classification: IsV3=%v IsZero=%v", zeroKey.IsV3(), zeroKey.IsZero())
	}
	if err := ValidateAmneziaWGConfig(zeroKey); err != nil {
		t.Fatalf("disabled all-zero key rejected: %v", err)
	}
}

func TestMarshalAmneziaWGConfigForDiscoUsesValidationLimit(t *testing.T) {
	p := AmneziaWGPrefs{I1: "<b 0xc0><r 32>"}
	encoded, err := MarshalAmneziaWGConfigForDisco(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `\u003c`) || !strings.Contains(string(encoded), p.I1) {
		t.Fatalf("CPS expression was unnecessarily HTML-escaped: %s", encoded)
	}
	if err := ValidateAmneziaWGConfig(p); err != nil {
		t.Fatalf("wire-encodable config rejected: %v", err)
	}

	// Each <d> tag is valid and emits no fixed bytes for an i-packet, so this
	// reaches the aggregate disco-size check rather than the CPS output limit.
	p.I1 = strings.Repeat("<d>", maxAmneziaCPSBytes/len("<d>"))
	if err := ValidateAmneziaWGConfig(p); err == nil || !strings.Contains(err.Error(), "disco limit") {
		t.Fatalf("validated-but-unsyncable config error = %v, want disco size limit", err)
	}
	if _, err := MarshalAmneziaWGConfigForDisco(p); err == nil || !strings.Contains(err.Error(), "disco limit") {
		t.Fatalf("oversized disco marshal error = %v, want disco size limit", err)
	}
}

func TestAmneziaWGPrefsJSONRejectsDamagedTypedValues(t *testing.T) {
	for _, input := range []string{
		`{"jc":70000}`,
		`{"h1":{"min":20,"max":10}}`,
		`{"header_protection_key":123}`,
	} {
		var got AmneziaWGPrefs
		if err := json.Unmarshal([]byte(input), &got); err == nil {
			t.Fatalf("json.Unmarshal(%s) succeeded with %#v, want error", input, got)
		}
	}
}
