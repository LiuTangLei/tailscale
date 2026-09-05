// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import "testing"

func TestLatencyQuantiles(t *testing.T) {
	for _, tc := range []struct {
		in               []float64
		median, p95, max float64
	}{
		{nil, 0, 0, 0}, {[]float64{3}, 3, 3, 3}, {[]float64{4, 1, 3, 2}, 2.5, 4, 4},
	} {
		m, p, x := latencyQuantiles(tc.in)
		if m != tc.median || p != tc.p95 || x != tc.max {
			t.Fatalf("%v: got %v %v %v", tc.in, m, p, x)
		}
	}
}
