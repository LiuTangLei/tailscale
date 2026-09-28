//go:build linux

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import "syscall"

func processCPU() (user, system float64) {
	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) == nil {
		user = float64(r.Utime.Sec) + float64(r.Utime.Usec)/1e6
		system = float64(r.Stime.Sec) + float64(r.Stime.Usec)/1e6
	}
	return
}
