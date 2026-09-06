// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !linux

package main

import (
	"errors"
	"github.com/LiuTangLei/wireguard-go/tun"
)

func openKernelBenchTUN(string) (tun.Device, error) {
	return nil, errors.New("kernel network-namespace benchmark requires Linux")
}
