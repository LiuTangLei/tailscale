// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/types/key"
)

func TestIsAmneziaWGZeroIncludesV3Fields(t *testing.T) {
	if !isAmneziaWGZero(ipn.AmneziaWGPrefs{}) {
		t.Fatal("zero AWG config reported as enabled")
	}
	if isAmneziaWGZero(ipn.AmneziaWGPrefs{
		RekeyAfterTime: ipn.MagicHeaderRange{Min: 120, Max: 180},
	}) {
		t.Fatal("v3-only AWG config reported as zero")
	}
}

func TestAWGSyncPeerLocalAPIContract(t *testing.T) {
	nodeKey := key.NewNode().Public()
	config := ipn.AmneziaWGPrefs{JC: 1}
	encoded, err := json.Marshal(awgSyncPeerResult{
		NodeKey:     nodeKey.String(),
		Hostname:    "phone",
		TailscaleIP: "100.64.0.2",
		Config:      &config,
	})
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatal(err)
	}
	wantFields := []string{"config", "hostname", "nodeKey", "tailscaleIP"}
	gotFields := make([]string, 0, len(top))
	for field := range top {
		gotFields = append(gotFields, field)
	}
	slices.Sort(gotFields)
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("AWG sync LocalAPI fields = %q, want %q", gotFields, wantFields)
	}
	var gotNodeKey string
	if err := json.Unmarshal(top["nodeKey"], &gotNodeKey); err != nil {
		t.Fatal(err)
	}
	if gotNodeKey != nodeKey.String() || !strings.HasPrefix(gotNodeKey, "nodekey:") {
		t.Fatalf("nodeKey = %q, want full parseable key %q", gotNodeKey, nodeKey.String())
	}
	var parsed key.NodePublic
	if err := parsed.UnmarshalText([]byte(gotNodeKey)); err != nil {
		t.Fatalf("mobile-returned nodeKey cannot be sent to awg-sync-apply: %v", err)
	}

	standard, err := json.Marshal(awgSyncPeerResult{NodeKey: nodeKey.String(), Hostname: "standard"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(standard), `"config":null`) {
		t.Fatalf("standard peer response must keep nullable config field: %s", standard)
	}
	failed, err := json.Marshal(awgSyncPeerResult{NodeKey: nodeKey.String(), Hostname: "failed", Err: "timeout"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(failed), `"config":null`) || !strings.Contains(string(failed), `"error":"timeout"`) {
		t.Fatalf("failed peer response lost nullable/error contract: %s", failed)
	}
}

func TestRequestAmneziaWGConfigWithRetry(t *testing.T) {
	calls := 0
	got, err := requestAmneziaWGConfigWithRetry(context.Background(), func(context.Context) (ipn.AmneziaWGPrefs, error) {
		calls++
		if calls == 1 {
			return ipn.AmneziaWGPrefs{}, context.DeadlineExceeded
		}
		return ipn.AmneziaWGPrefs{JC: 2}, nil
	})
	if err != nil || got.JC != 2 || calls != 2 {
		t.Fatalf("retry result = %#v, %v after %d calls", got, err, calls)
	}

	calls = 0
	wantErr := errors.New("invalid peer")
	_, err = requestAmneziaWGConfigWithRetry(context.Background(), func(context.Context) (ipn.AmneziaWGPrefs, error) {
		calls++
		return ipn.AmneziaWGPrefs{}, wantErr
	})
	if !errors.Is(err, wantErr) || calls != 1 {
		t.Fatalf("non-retryable error = %v after %d calls", err, calls)
	}
}

func TestWithAWGSyncBudgetIncludesQueueTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sem := make(chan struct{}, 1)
		sem <- struct{}{} // Keep every worker queued for its entire budget.

		const workerCount = 4
		const budget = 30 * time.Millisecond
		start := time.Now()
		var wg sync.WaitGroup
		errs := make(chan error, workerCount)
		for range workerCount {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := withAWGSyncBudget(context.Background(), sem, budget, func(context.Context) (struct{}, error) {
					t.Error("queued worker unexpectedly acquired a slot")
					return struct{}{}, nil
				})
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queued worker error = %v, want deadline exceeded", err)
			}
		}
		if elapsed := time.Since(start); elapsed != budget {
			t.Fatalf("worker budgets stacked by batch: elapsed %v, want %v", elapsed, budget)
		}
		if got := len(sem); got != 1 {
			t.Fatalf("cancelled waiters changed semaphore occupancy to %d", got)
		}
	})
}
