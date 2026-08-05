// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/types/key"
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

func TestValidateAmneziaWGConfigRejectsRetiredCounterTag(t *testing.T) {
	tests := []struct {
		name      string
		config    ipn.AmneziaWGPrefs
		wantField string
	}{
		{
			name:      "issue-15-i1",
			config:    ipn.AmneziaWGPrefs{I1: "<b 0xc0><r 32><c><t>"},
			wantField: "I1",
		},
		{
			name:      "whitespace-i2",
			config:    ipn.AmneziaWGPrefs{I2: "<c >"},
			wantField: "I2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAmneziaWGConfig(tt.config)
			if err == nil || !strings.Contains(err.Error(), tt.wantField+" contains the retired CPS tag <c>") {
				t.Fatalf("validation error = %v", err)
			}
		})
	}

	for _, spec := range []string{"<b 0xc0><r 32><t>", "<rc 10><rd 10>"} {
		if err := validateAmneziaWGConfig(ipn.AmneziaWGPrefs{I1: spec}); err != nil {
			t.Errorf("supported CPS %q rejected: %v", spec, err)
		}
	}
}

func TestRequestAWGConfigsFromPeersRetriesAndClassifies(t *testing.T) {
	configKey := key.NewNode().Public()
	standardKey := key.NewNode().Public()
	failedKey := key.NewNode().Public()
	peers := []peerInfo{
		{Name: "config", IP: "100.64.0.1", NodeKey: configKey},
		{Name: "standard", IP: "100.64.0.2", NodeKey: standardKey},
		{Name: "failed", IP: "100.64.0.3", NodeKey: failedKey},
	}

	calls := map[key.NodePublic]int{}
	request := func(_ context.Context, nodeKey key.NodePublic) (ipn.AmneziaWGPrefs, error) {
		calls[nodeKey]++
		switch nodeKey {
		case configKey:
			if calls[nodeKey] == 1 {
				return ipn.AmneziaWGPrefs{}, context.DeadlineExceeded
			}
			return ipn.AmneziaWGPrefs{JC: 1}, nil
		case standardKey:
			return ipn.AmneziaWGPrefs{}, nil
		default:
			return ipn.AmneziaWGPrefs{}, errors.New("peer does not support AWG sync")
		}
	}
	policy := awgSyncPolicy{
		MaxConcurrent:  1,
		AttemptTimeout: time.Second,
		MaxAttempts:    2,
	}
	var out bytes.Buffer
	configs, stats, err := requestAWGConfigsFromPeersWith(context.Background(), peers, request, policy, &out)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 || configs[0].PeerName != "config" || configs[0].Config.JC != 1 {
		t.Fatalf("configs = %#v", configs)
	}
	if stats.Total != 3 || stats.WithConfig != 1 || stats.Standard != 1 || stats.Failed != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if calls[configKey] != 2 || calls[standardKey] != 1 || calls[failedKey] != 1 {
		t.Fatalf("calls = %#v", calls)
	}
	for _, want := range []string{
		"[OK] config (100.64.0.1): AWG config found (2 attempts,",
		"[--] standard (100.64.0.2): standard WireGuard",
		"[ERR] failed (100.64.0.3): peer does not support AWG sync",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRequestAWGConfigsFromPeersPreservesPeerOrder(t *testing.T) {
	firstKey := key.NewNode().Public()
	secondKey := key.NewNode().Public()
	secondStarted := make(chan struct{})
	request := func(_ context.Context, nodeKey key.NodePublic) (ipn.AmneziaWGPrefs, error) {
		if nodeKey == firstKey {
			<-secondStarted
			return ipn.AmneziaWGPrefs{JC: 1}, nil
		}
		close(secondStarted)
		return ipn.AmneziaWGPrefs{JC: 2}, nil
	}
	peers := []peerInfo{
		{Name: "first", NodeKey: firstKey},
		{Name: "second", NodeKey: secondKey},
	}
	policy := awgSyncPolicy{MaxConcurrent: 2, AttemptTimeout: time.Second, MaxAttempts: 1}
	configs, _, err := requestAWGConfigsFromPeersWith(context.Background(), peers, request, policy, new(bytes.Buffer))
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 || configs[0].PeerName != "first" || configs[1].PeerName != "second" {
		t.Fatalf("config order = %#v", configs)
	}
}

func TestPrintNoAWGConfigsDistinguishesFailures(t *testing.T) {
	for _, tt := range []struct {
		name    string
		stats   awgDiscoveryStats
		want    string
		notWant string
	}{
		{
			name:    "all-standard",
			stats:   awgDiscoveryStats{Total: 3, Standard: 3},
			want:    "All peers are using standard WireGuard",
			notWant: "failed",
		},
		{
			name:    "all-failed",
			stats:   awgDiscoveryStats{Total: 3, Failed: 3},
			want:    "all 3 peer requests failed",
			notWant: "All peers are using standard WireGuard",
		},
		{
			name:    "partial-failure",
			stats:   awgDiscoveryStats{Total: 3, Standard: 2, Failed: 1},
			want:    "2 peer(s) reported standard WireGuard and 1 request(s) failed",
			notWant: "All peers are using standard WireGuard",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			printNoAWGConfigs(&out, tt.stats)
			if !strings.Contains(out.String(), tt.want) || strings.Contains(out.String(), tt.notWant) {
				t.Fatalf("output = %q, want %q and not %q", out.String(), tt.want, tt.notWant)
			}
		})
	}
}

func TestIsRetryableAWGSyncError(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{context.DeadlineExceeded, true},
		{errors.New("500 Internal Server Error: no path available for peer"), true},
		{errors.New("408 Request Timeout: request timed out"), true},
		{context.Canceled, false},
		{errors.New("404 Not Found"), false},
	} {
		if got := isRetryableAWGSyncError(tt.err); got != tt.want {
			t.Errorf("isRetryableAWGSyncError(%q) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
