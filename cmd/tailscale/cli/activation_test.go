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
	"time"

	"tailscale.com/ipn"
)

// Only fake clients and restart hooks are used. Tests must never restart the
// developer's service, including when they run inside a Linux CI container.
func activationFixture(t *testing.T) (*awgSetupFake, *int) {
	t.Helper()
	oldRestart, oldOS, oldContainer, oldSocket := restartTailscaled, restartGOOS, restartInContainer, localClient.Socket
	t.Cleanup(func() {
		restartTailscaled, restartGOOS, restartInContainer, localClient.Socket = oldRestart, oldOS, oldContainer, oldSocket
	})
	restartGOOS = func() string { return "darwin" }
	restartInContainer = func() bool { return false }
	localClient.Socket = ""
	client := &awgSetupFake{menuTransportClient: menuClient()}
	count := new(int)
	restartTailscaled = func() error {
		*count++
		client.state.ActiveMode = client.state.DesiredMode
		client.state.PendingRestart = false
		return nil
	}
	return client, count
}

func TestQUICSelectionActivatesByDefault(t *testing.T) {
	c, count := activationFixture(t)
	c.prefs.AmneziaWG = ipn.AmneziaWGPrefs{JC: 4, JMin: 64, JMax: 128}
	c.state.AWGConfigured = true
	var out bytes.Buffer
	changed, err := configureAWGSetWithOptions(context.Background(), c, []string{"quic"}, true, false, bufio.NewScanner(strings.NewReader("")), &out)
	if err != nil || !changed || *count != 1 || c.state.ActiveMode != "http3-ip" || c.state.PendingRestart || !c.prefs.AmneziaWG.IsZero() {
		t.Fatalf("QUIC not active: changed=%v restarts=%d status=%+v err=%v", changed, *count, c.state, err)
	}
	changed, err = configureAWGSetWithOptions(context.Background(), c, []string{"quic"}, true, false, bufio.NewScanner(strings.NewReader("")), &out)
	if err != nil || changed || *count != 1 {
		t.Fatalf("idempotent selection restarted: changed=%v count=%d err=%v", changed, *count, err)
	}
	if strings.Contains(out.String(), "Restart Tailscale now") {
		t.Fatal("redundant restart confirmation")
	}
}

func TestAWGSelectionActivatesNativeAfterQUIC(t *testing.T) {
	c, count := activationFixture(t)
	c.state.ActiveMode, c.state.DesiredMode = "http3-ip", "http3-ip"
	changed, err := configureAWGSetWithOptions(context.Background(), c, []string{`{"jc":4,"jmin":64,"jmax":128}`}, true, false, bufio.NewScanner(strings.NewReader("")), &bytes.Buffer{})
	if err != nil || !changed || *count != 1 || c.state.ActiveMode != "native" || c.state.PendingRestart || c.prefs.AmneziaWG.JC != 4 {
		t.Fatalf("AWG not active: changed=%v restarts=%d status=%+v err=%v", changed, *count, c.state, err)
	}
}

func TestActivationCancellationAndPreflightDoNotMutate(t *testing.T) {
	for _, scenario := range []string{"cancel", "eof", "custom-socket", "container"} {
		t.Run(scenario, func(t *testing.T) {
			c, count := activationFixture(t)
			yes, input := true, ""
			switch scenario {
			case "cancel":
				yes, input = false, "n\n"
			case "eof":
				yes = false
			case "custom-socket":
				localClient.Socket = "/isolated-test/socket"
			case "container":
				restartGOOS = func() string { return "linux" }
				restartInContainer = func() bool { return true }
			}
			changed, err := configureAWGSetWithOptions(context.Background(), c, []string{"quic"}, yes, false, bufio.NewScanner(strings.NewReader(input)), &bytes.Buffer{})
			if scenario == "custom-socket" || scenario == "container" {
				if err == nil {
					t.Fatal("unsafe restart accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if changed || *count != 0 || len(c.writes) != 0 || c.edits != 0 {
				t.Fatalf("cancel/preflight mutated or restarted: %+v count=%d", c.state, *count)
			}
		})
	}
}

func TestNoRestartIsExplicitStaging(t *testing.T) {
	c, count := activationFixture(t)
	localClient.Socket = "/isolated-test/socket"
	changed, err := configureAWGSetWithOptions(context.Background(), c, []string{"quic"}, true, true, bufio.NewScanner(strings.NewReader("")), &bytes.Buffer{})
	if err != nil || !changed || *count != 0 || c.state.ActiveMode != "native" || c.state.DesiredMode != "http3-ip" || !c.state.PendingRestart {
		t.Fatalf("explicit staging wrong: changed=%v count=%d status=%+v err=%v", changed, *count, c.state, err)
	}
}

func TestActivationFailuresAreNotReportedAsApplied(t *testing.T) {
	for _, scenario := range []string{"restart-failed", "verify-timeout"} {
		t.Run(scenario, func(t *testing.T) {
			c, _ := activationFixture(t)
			restartTailscaled = func() error {
				if scenario == "restart-failed" {
					return errors.New("service manager unavailable")
				}
				return nil // deliberately leave the old engine active
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			var out bytes.Buffer
			_, err := configureAWGSetWithOptions(ctx, c, []string{"quic"}, true, false, bufio.NewScanner(strings.NewReader("")), &out)
			if err == nil || !strings.Contains(err.Error(), "saved") || !c.state.PendingRestart || c.state.ActiveMode != "native" {
				t.Fatalf("failure was hidden: status=%+v err=%v", c.state, err)
			}
			if strings.Contains(out.String(), "QUIC is active") {
				t.Fatal("false success output")
			}
		})
	}
}

func TestAWGVerificationRequiresActiveNativeAndRedactsKeys(t *testing.T) {
	c, _ := activationFixture(t)
	want := ipn.AmneziaWGPrefs{HeaderProtectionKey: strings.Repeat("43", 32)}
	c.prefs.AmneziaWG = want
	c.state.ActiveMode, c.state.DesiredMode = "http3-ip", "http3-ip"
	if err := waitForAWGConfig(context.Background(), c, want); err == nil {
		t.Fatal("stored prefs mistaken for active AWG")
	}
	c.state.ActiveMode, c.state.DesiredMode = "native", "native"
	c.prefs.AmneziaWG = ipn.AmneziaWGPrefs{}
	err := waitForAWGConfig(context.Background(), c, want)
	if err == nil || strings.Contains(err.Error(), want.HeaderProtectionKey) {
		t.Fatalf("missing failure or private key in failure: %v", err)
	}
}
