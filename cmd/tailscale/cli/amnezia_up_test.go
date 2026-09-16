// Copyright (c) 2026 Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
)

func TestUpPreservesAWGProfile(t *testing.T) {
	profiles := map[string]ipn.AmneziaWGPrefs{
		"disabled": {},
		"v2":       {JC: 4, JMin: 700, JMax: 899, S1: 19, S2: 29},
		"v3": {JC: 4, JMin: 700, JMax: 899, S1: 19, S2: 29, S3: 15, S4: 20,
			HeaderProtectionKey:    strings.Repeat("42", 32),
			ContentPaddingAddition: ipn.MagicHeaderRange{Min: 5, Max: 31}},
	}
	for name, profile := range profiles {
		for _, tc := range []struct {
			name, state string
			flags       []string
			fullStart   bool
		}{
			{"container_authkey", "Running", []string{"--auth-key=tskey-auth-test-only", "--accept-dns=false", "--accept-routes", "--login-server=http://127.0.0.1:18440"}, true},
			{"container_starting", "Starting", []string{"--accept-dns=false", "--accept-routes"}, true},
			{"reauth", "Running", []string{"--force-reauth"}, true},
			{"reset_up_flags", "Running", []string{"--reset", "--auth-key=tskey-auth-test-only"}, true},
			{"edit_running", "Running", []string{"--accept-routes"}, false},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				var args upArgsT
				fs := newUpFlagSet("linux", &args, "up")
				if err := fs.Parse(tc.flags); err != nil {
					t.Fatal(err)
				}
				next, err := prefsFromUpArgs(args, func(string, ...any) {}, &ipnstate.Status{}, "linux")
				if err != nil {
					t.Fatal(err)
				}
				current := next.Clone()
				current.AmneziaWG = profile
				before := current.Clone()
				_, edits, err := updatePrefs(next, current, upCheckEnv{goos: "linux", flagSet: fs, upArgs: args, backendState: tc.state})
				if err != nil {
					t.Fatal(err)
				}
				if tc.fullStart && edits != nil {
					t.Fatal("did not exercise full Start(UpdatePrefs) path")
				}
				if next.AmneziaWG != profile {
					t.Fatal("up discarded the separately managed AWG profile")
				}
				if edits != nil {
					if edits.AmneziaWGSet {
						t.Fatal("up must not own the AWG mask")
					}
					current.ApplyEdits(edits)
					if current.AmneziaWG != profile {
						t.Fatal("masked up edit discarded AWG")
					}
				}
				// The full preferences payload must retain the profile through
				// the same JSON encoding used by LocalAPI and the state store.
				data, err := json.Marshal(next)
				if err != nil {
					t.Fatal(err)
				}
				var restored ipn.Prefs
				if err := json.Unmarshal(data, &restored); err != nil {
					t.Fatal(err)
				}
				if restored.AmneziaWG != profile || before.AmneziaWG != profile {
					t.Fatal("AWG did not round-trip")
				}
			})
		}
	}
}
