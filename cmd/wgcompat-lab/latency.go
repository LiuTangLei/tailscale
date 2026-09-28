// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"context"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"tailscale.com/tailcfg"
)

type latencyResult struct {
	Target  string    `json:"target"`
	Samples []float64 `json:"samples_ms"`
	Failed  int       `json:"failed"`
	Median  float64   `json:"median_ms"`
	P95     float64   `json:"p95_ms"`
	Maximum float64   `json:"max_ms"`
}

// latency measures encrypted data-plane RTT, not merely discovery. It does not
// acquire the benchmark mutex, so it can also be used during a transfer.
func (n *node) latency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	ip, err := netip.ParseAddr(r.URL.Query().Get("target"))
	if err != nil {
		http.Error(w, "invalid peer IP", 400)
		return
	}
	count, err := strconv.Atoi(r.URL.Query().Get("samples"))
	if err != nil || count < 1 || count > 30 {
		http.Error(w, "samples must be 1..30", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	st, err := n.lc.Status(ctx)
	if err != nil || !ipInPeerStatus(st, ip) {
		http.Error(w, "unknown peer", 400)
		return
	}
	out := latencyResult{Target: ip.String()}
	for i := 0; i < count; i++ {
		pingCtx, pingCancel := context.WithTimeout(ctx, 3*time.Second)
		p, err := n.lc.Ping(pingCtx, ip, tailcfg.PingTSMP)
		pingCancel()
		if err != nil || p == nil || p.Err != "" {
			out.Failed++
		} else {
			out.Samples = append(out.Samples, p.LatencySeconds*1000)
		}
		if ctx.Err() != nil {
			out.Failed += count - i - 1
			break
		}
	}
	out.Median, out.P95, out.Maximum = latencyQuantiles(out.Samples)
	writeJSON(w, out)
}

func latencyQuantiles(values []float64) (median, p95, maximum float64) {
	if len(values) == 0 {
		return
	}
	x := slices.Clone(values)
	slices.Sort(x)
	median = x[len(x)/2]
	if len(x)%2 == 0 {
		median = (x[len(x)/2-1] + median) / 2
	}
	return median, x[int(math.Ceil(float64(len(x))*0.95))-1], x[len(x)-1]
}
