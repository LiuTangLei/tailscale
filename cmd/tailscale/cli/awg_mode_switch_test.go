// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func stubRestart(t *testing.T) {
	t.Helper()
	old := restartTailscaled
	restartTailscaled = func() error { return nil }
	t.Cleanup(func() { restartTailscaled = old })
}

type awgSetupFake struct {
	*menuTransportClient
	prefs ipn.Prefs
	edits int
	fail  error
}

func (c *awgSetupFake) GetPrefs(context.Context) (*ipn.Prefs, error) {
	return c.prefs.Clone(), nil
}

func (c *awgSetupFake) EditPrefs(_ context.Context, m *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	c.edits++
	c.prefs.ApplyEdits(m)
	return c.prefs.Clone(), nil
}

func (c *awgSetupFake) ConfigureTransport(ctx context.Context, r ipn.TransportControlRequest) (ipn.TransportControlStatus, error) {
	if c.fail != nil {
		return c.state, c.fail
	}
	if r.Action == "awg" {
		c.writes = append(c.writes, r)
		c.prefs.AmneziaWG = *r.AWG
		c.state.DesiredMode = "native"
		c.state.PendingRestart = c.state.ActiveMode != "native"
		c.state.AWGConfigured = !r.AWG.IsZero()
		return c.state, nil
	}
	if r.Action == "mode" && r.Mode == "http3-ip" {
		c.prefs.AmneziaWG = ipn.AmneziaWGPrefs{}
		c.state.AWGConfigured = false
	}
	return c.menuTransportClient.ConfigureTransport(ctx, r)
}

func TestAWGSetQUICSelectionAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, input  string
		args         []string
		yes, changed bool
	}{
		{"menu", "3\ny\n", nil, false, true},
		{"menu_cancel", "3\nn\n", nil, false, false},
		{"menu_eof", "3\n", nil, false, false},
		{"direct", "", []string{"quic"}, true, true},
		{"old_alias", "", []string{"http3-ip"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubRestart(t)
			c := &awgSetupFake{menuTransportClient: menuClient(), prefs: ipn.Prefs{AmneziaWG: ipn.AmneziaWGPrefs{JC: 4}}}
			c.state.AWGConfigured = true
			var out bytes.Buffer
			changed, err := configureAWGSetWithOptions(context.Background(), c, tc.args, tc.yes, true, bufio.NewScanner(strings.NewReader(tc.input)), &out)
			if err != nil || changed != tc.changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			if !tc.changed {
				if len(c.writes) != 0 || c.edits != 0 || c.prefs.AmneziaWG.JC != 4 {
					t.Fatal("cancel changed state")
				}
				return
			}
			if len(c.writes) != 1 || c.writes[0].Mode != "http3-ip" || c.writes[0].AutoTrust == nil || !*c.writes[0].AutoTrust || c.edits != 0 || !c.prefs.AmneziaWG.IsZero() {
				t.Fatal("QUIC selection must use one coordinated request")
			}
			if c.state.ActiveMode != "native" || !c.state.PendingRestart || !strings.Contains(out.String(), "clear") {
				t.Fatal("running and next-start modes were confused")
			}
		})
	}
}

func TestAWGSetAndSyncStageNativeWithoutClearingActiveQUIC(t *testing.T) {
	for _, active := range []string{"http3-ip", "quic-ip", "native"} {
		t.Run(active, func(t *testing.T) {
			c := &awgSetupFake{menuTransportClient: menuClient()}
			c.state.ActiveMode, c.state.DesiredMode = active, "http3-ip"
			profile := ipn.AmneziaWGPrefs{JC: 4, JMin: 700, JMax: 899}
			pending, err := applyAWGForClient(context.Background(), c, profile)
			if err != nil {
				t.Fatal(err)
			}
			if pending != (active != "native") || c.state.ActiveMode != active || c.state.DesiredMode != "native" || c.prefs.AmneziaWG != profile || c.edits != 0 {
				t.Fatal("AWG was not saved with a native selection")
			}
			if len(c.writes) != 1 || c.writes[0].Action != "awg" || c.writes[0].ExpectedRevision != "revision-7" {
				t.Fatal("missing atomic AWG selection with revision")
			}
		})
	}
}

func TestAWGSwitchFailureDoesNotFallBackToRawEdit(t *testing.T) {
	c := &awgSetupFake{menuTransportClient: menuClient(), fail: errors.New("store failure")}
	c.state.ActiveMode, c.state.DesiredMode = "http3-ip", "http3-ip"
	if _, err := applyAWGForClient(context.Background(), c, ipn.AmneziaWGPrefs{JC: 4}); err == nil {
		t.Fatal("failure was ignored")
	}
	if c.edits != 0 || !c.prefs.AmneziaWG.IsZero() || c.state.DesiredMode != "http3-ip" {
		t.Fatal("failed switch changed preferences")
	}
}

func TestQUICToAWGStatusDoesNotTellUserToReset(t *testing.T) {
	var out bytes.Buffer
	if err := renderTransportStatus(ipn.TransportControlStatus{ActiveMode: "http3-ip", DesiredMode: "native", PendingRestart: true, AWGConfigured: true}, &out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "saved for the next native start") || strings.Contains(out.String(), "clears") {
		t.Fatal(out.String())
	}
}
