// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/transportprofile"
)

func TestTransportSelectionAWGWriteOrderingAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		conflict bool
		failAWG  bool
	}{
		{"success", false, false},
		{"stale_revision", true, false},
		{"state_write_failure", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pub := key.NewNode().Public().String()
			previous, err := transportprofile.Apply(transportprofile.Profile{Version: 1, Mode: "native"}, ipn.TransportControlRequest{Action: "mode", Mode: "http3-ip"}, pub)
			if err != nil {
				t.Fatal(err)
			}
			revision, err := transportprofile.Save(root, previous, "0")
			if err != nil {
				t.Fatal(err)
			}
			next, err := transportprofile.Apply(previous, ipn.TransportControlRequest{Action: "mode", Mode: "native"}, pub)
			if err != nil {
				t.Fatal(err)
			}
			if tc.conflict {
				revision = "stale"
			}
			calls := 0
			err = saveTransportWithAWGUpdate(root, previous, next, revision, func() error {
				calls++
				p, _, err := transportprofile.Read(root)
				if err != nil || p.Mode != "native" {
					t.Fatal("AWG write happened before the native selection was saved")
				}
				if tc.failAWG {
					return errors.New("test state store rejected write")
				}
				return nil
			})
			if (err != nil) != (tc.conflict || tc.failAWG) {
				t.Fatalf("unexpected result: %v", err)
			}
			if tc.conflict && calls != 0 {
				t.Fatal("failed transport save invoked the AWG write")
			}
			p, _, readErr := transportprofile.Read(root)
			if readErr != nil {
				t.Fatal(readErr)
			}
			wantMode := "native"
			if err != nil {
				wantMode = "http3-ip"
			}
			if p.Mode != wantMode || p.PrivateKey != previous.PrivateKey {
				t.Fatal("selection or existing identity was lost")
			}
		})
	}
}

func TestPendingAWGDoesNotEnterRunningQUICEngine(t *testing.T) {
	profile := ipn.AmneziaWGPrefs{JC: 4, JMin: 700, JMax: 899}
	for _, mode := range []string{"http3-ip", "quic-ip"} {
		if got := awgForRunningTransport(mode, profile); !got.IsZero() {
			t.Fatalf("%s applied pending AWG before restart", mode)
		}
	}
	if got := awgForRunningTransport("native", profile); got != profile {
		t.Fatal("native restart did not select saved AWG")
	}
}
