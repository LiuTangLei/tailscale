//go:build !linux

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

// CPU measurements are reported only for the Linux real-host benchmark.
func processCPU() (float64, float64) { return 0, 0 }
