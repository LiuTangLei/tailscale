// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// Opt-in throughput acceptance. The socket/inner IP path and offered UDP load
// match the impairment tests, but no test-only shaper consumes the CPU budget.
func TestH3NativeThroughputLoad(t *testing.T) {
	if os.Getenv("TS_H3_THROUGHPUT") != "1" {
		t.Skip("set TS_H3_THROUGHPUT=1 for native IP throughput profiling")
	}
	seconds, trials := 5, 3
	if n, e := strconv.Atoi(os.Getenv("TS_H3_REPAIR_SECONDS")); e == nil && n > 0 {
		seconds = n
	}
	if n, e := strconv.Atoi(os.Getenv("TS_H3_REPAIR_TRIALS")); e == nil && n > 0 {
		trials = n
	}
	var results []repairLoadResult
	defer func() {
		data, _ := json.MarshalIndent(results, "", "  ")
		t.Logf("THROUGHPUT_RESULTS=%s", data)
		if path := os.Getenv("TS_H3_REPAIR_RESULT"); path != "" {
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Error(e)
			}
		}
	}()
	for trial := range trials {
		order := []bool{false, true}
		if trial%2 != 0 {
			order = []bool{true, false}
		}
		for _, enabled := range order {
			t.Run(fmt.Sprintf("trial%d/repair_%t", trial, enabled), func(t *testing.T) {
				results = append(results, runTCPRepairLoad(t, "unshaped", enabled, trial, time.Duration(seconds)*time.Second))
			})
		}
	}
}
