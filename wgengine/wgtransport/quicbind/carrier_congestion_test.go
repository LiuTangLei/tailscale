// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type congestionPolicyResult struct {
	Scenario     string  `json:"scenario"`
	Congestion   string  `json:"congestion"`
	Trial        int     `json:"trial"`
	TCPMbps      float64 `json:"tcp_mbps"`
	UDPDelivered float64 `json:"udp_delivered_percent"`
	UDPP50MS     float64 `json:"udp_p50_ms"`
	UDPP99MS     float64 `json:"udp_p99_ms"`
	LinkDrops    uint64  `json:"link_drops"`
	LocalDrops   uint64  `json:"local_drops"`
}

// TestCarrierCongestionPolicy is an opt-in closed-loop measurement of BBRv3.
// Real inner TCP connections and latency-probing UDP
// run through the native IP DATAGRAM path over a rate-limited, delayed,
// tail-dropping link, so the inner flows react to loss exactly as they do in
// production. An open-loop flood cannot evaluate a tunnel policy: nothing in
// it backs off.
//
//	TS_H3_CONGESTION=1 go test -run TestCarrierCongestionPolicy -v
func TestCarrierCongestionPolicy(t *testing.T) {
	if os.Getenv("TS_H3_CONGESTION") != "1" {
		t.Skip("set TS_H3_CONGESTION=1 for the BBRv3 carrier measurement")
	}
	seconds := blastEnvInt("TS_H3_CONGESTION_SECONDS", 6)
	trials := blastEnvInt("TS_H3_CONGESTION_TRIALS", 2)
	scenarios := []string{"shaped", "asymmetric", "burst", "reorder"}
	if list := os.Getenv("TS_H3_CONGESTION_SCENARIOS"); list != "" {
		scenarios = strings.Split(list, ",")
	}
	var results []congestionPolicyResult
	defer func() {
		data, _ := json.MarshalIndent(results, "", " ")
		t.Logf("CONGESTION_RESULTS=%s", data)
		if path := os.Getenv("TS_H3_CONGESTION_RESULT"); path != "" {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Error(err)
			}
		}
	}()
	for _, scenario := range scenarios {
		for trial := range trials {
			t.Run(scenario+"/bbr-v3", func(t *testing.T) {
				r := runTCPRepairLoad(t, scenario, false, trial, time.Duration(seconds)*time.Second)
				out := congestionPolicyResult{Scenario: scenario, Congestion: "bbr-v3", Trial: trial, LinkDrops: r.LinkDrops, LocalDrops: r.LocalDrops}
				out.TCPMbps = float64(r.TCPBytes) * 8 / float64(seconds) / 1e6
				var offered, delivered int
				for _, u := range r.UDP {
					offered += u.Offered
					delivered += u.Delivered
					out.UDPP50MS = max(out.UDPP50MS, u.P50MS)
					out.UDPP99MS = max(out.UDPP99MS, u.P99MS)
				}
				if offered > 0 {
					out.UDPDelivered = 100 * float64(delivered) / float64(offered)
				}
				results = append(results, out)
			})
		}
	}
}
