// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"net/netip"
	"slices"

	"tailscale.com/ipn"
	"tailscale.com/types/key"
)

//go:generate go run tailscale.com/cmd/cloner -type=Config

// Config is a WireGuard configuration.
// It only supports the set of things Tailscale uses.
//
// Peers are not part of the config: wireguard-go learns the peer set
// and each peer's allowed IPs from the live per-peer config source
// installed via [tailscale.com/wgengine.Engine.SetPeerConfigFunc].
type Config struct {
	PrivateKey key.NodePrivate
	Addresses  []netip.Prefix

	// AmneziaWG contains the device-wide AWG parameters. Its zero value keeps
	// standard WireGuard behavior. Both legacy AWG v2 and AWG v3 fields live in
	// the same preferences value so switching versions clears stale settings.
	AmneziaWG ipn.AmneziaWGPrefs
}

func (c *Config) Equal(o *Config) bool {
	if c == nil || o == nil {
		return c == o
	}
	return c.PrivateKey.Equal(o.PrivateKey) &&
		slices.Equal(c.Addresses, o.Addresses) &&
		c.AmneziaWG == o.AmneziaWG
}
