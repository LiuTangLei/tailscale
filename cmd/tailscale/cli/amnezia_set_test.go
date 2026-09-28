// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestGenerateAWGProfileVersions(t *testing.T) {
	t.Run("v2", func(t *testing.T) {
		config, err := generateAWGProfile(awgProfileV2, awgTestRandom())
		if err != nil {
			t.Fatal(err)
		}
		if got := amneziaConfigVersion(config); got != "AWG v2" {
			t.Fatalf("profile version = %q", got)
		}
		if hasV3Config(config) {
			t.Fatalf("generated v2 profile contains v3 fields: %#v", config)
		}
		for i, header := range []ipn.MagicHeaderRange{config.H1, config.H2, config.H3, config.H4} {
			if header.Min == 0 || header.Min != header.Max {
				t.Errorf("H%d = %v; legacy v2 generator should emit one scalar value", i+1, header)
			}
		}
		if err := validateAmneziaWGConfig(config); err != nil {
			t.Fatalf("generated v2 profile is invalid: %v", err)
		}
		checkAWGJSONRoundTrip(t, config)
	})

	t.Run("v3", func(t *testing.T) {
		config, err := generateAWGProfile(awgProfileV3, awgTestRandom())
		if err != nil {
			t.Fatal(err)
		}
		if got := amneziaConfigVersion(config); got != "AWG v3" {
			t.Fatalf("profile version = %q", got)
		}
		key, err := hex.DecodeString(config.HeaderProtectionKey)
		if err != nil || len(key) != 32 {
			t.Fatalf("HeaderProtectionKey is not 32-byte hex: %q, %v", config.HeaderProtectionKey, err)
		}
		for i, prefix := range []uint16{config.S1, config.S2, config.S3, config.S4} {
			if prefix < 12 {
				t.Errorf("S%d = %d; want at least 12 for v3 header protection", i+1, prefix)
			}
		}
		for i, header := range []ipn.MagicHeaderRange{config.H1, config.H2, config.H3, config.H4} {
			if header.Max <= header.Min {
				t.Errorf("H%d = %v; v3 generator should emit a range", i+1, header)
			}
		}
		if err := validateAmneziaWGConfig(config); err != nil {
			t.Fatalf("generated v3 profile is invalid: %v", err)
		}
		checkAWGJSONRoundTrip(t, config)
	})
}

func TestPromptAWGProfileDefaultsToV3(t *testing.T) {
	var out bytes.Buffer
	config, err := promptAWGProfile(
		bufio.NewScanner(strings.NewReader("\n\n")),
		&out,
		awgTestRandom(),
		ipn.AmneziaWGPrefs{JC: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := amneziaConfigVersion(config); got != "AWG v3" {
		t.Fatalf("blank selection generated %q, want AWG v3", got)
	}
	for _, want := range []string{
		"Current profile: AWG v2",
		"AWG v3 (recommended, default)",
		"Generated AWG v3 profile",
		"Copy this exact JSON",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("wizard output missing %q:\n%s", want, out.String())
		}
	}
}

func TestPromptAWGProfileCanGenerateV2(t *testing.T) {
	var out bytes.Buffer
	config, err := promptAWGProfile(
		bufio.NewScanner(strings.NewReader("invalid\n2\nmaybe\ny\n")),
		&out,
		awgTestRandom(),
		ipn.AmneziaWGPrefs{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := amneziaConfigVersion(config); got != "AWG v2" {
		t.Fatalf("explicit v2 selection generated %q", got)
	}
	for _, want := range []string{
		"Enter 1 for AWG v3, 2 for AWG v2",
		"Enter y to apply or n to cancel",
		"AWG v3-only fields: disabled",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("wizard output missing %q:\n%s", want, out.String())
		}
	}
}

func TestPromptAWGProfileCancellationAndEOF(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  error
	}{
		{name: "cancel", input: "q\n", want: errAWGSetupCancelled},
		{name: "eof", input: "", want: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := promptAWGProfile(
				bufio.NewScanner(strings.NewReader(test.input)),
				new(bytes.Buffer),
				awgTestRandom(),
				ipn.AmneziaWGPrefs{},
			)
			if test.want != nil {
				if !errors.Is(err, test.want) {
					t.Fatalf("error = %v, want %v", err, test.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), "input closed") {
				t.Fatalf("EOF error = %v, want closed-input error", err)
			}
		})
	}
}

func TestParseConfigFromArgsKeepsHistoricalV2JSON(t *testing.T) {
	for _, input := range []string{
		`{"JC":5,"JMin":500,"JMax":1000,"S1":15,"S2":18,"S3":20,"S4":25,"H1":123456,"H2":67543,"H3":123123,"H4":32345}`,
		`{"jc":5,"jmin":500,"jmax":1000,"s1":15,"s2":18,"s3":20,"s4":25,"h1":{"min":123456,"max":123500},"h2":67543,"h3":123123,"h4":32345}`,
	} {
		config, err := parseConfigFromArgs(context.Background(), []string{input})
		if err != nil {
			t.Fatalf("parse %s: %v", input, err)
		}
		if got := amneziaConfigVersion(config); got != "AWG v2" {
			t.Fatalf("historical JSON decoded as %q: %#v", got, config)
		}
		if config.JC != 5 || config.H1.Min != 123456 || hasV3Config(config) {
			t.Fatalf("historical v2 JSON changed during decode: %#v", config)
		}
	}
}

func awgTestRandom() *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0x42}, 256))
}

func checkAWGJSONRoundTrip(t *testing.T, want ipn.AmneziaWGPrefs) {
	t.Helper()
	encoded, err := formatConfigAsJSON(want)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, `"JC"`) || !strings.Contains(encoded, `"jc"`) {
		t.Fatalf("generated JSON does not use canonical lower-case fields: %s", encoded)
	}
	if hasV3Config(want) {
		if !strings.Contains(encoded, `"header_protection_key"`) || !strings.Contains(encoded, `"h1":{"min":`) {
			t.Fatalf("v3 JSON is missing canonical range/extension fields: %s", encoded)
		}
	} else if strings.Contains(encoded, `"header_protection_key"`) || strings.Contains(encoded, `"h1":{`) {
		t.Fatalf("v2 JSON is not legacy-compatible: %s", encoded)
	}
	got, err := parseConfigFromArgs(context.Background(), []string{encoded})
	if err != nil {
		t.Fatalf("parse generated JSON %s: %v", encoded, err)
	}
	if got != want {
		t.Fatalf("generated JSON round trip changed profile:\n got: %#v\nwant: %#v", got, want)
	}
}
