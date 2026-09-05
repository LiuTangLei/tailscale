// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicip

func (d *Device) SnapshotCounters() map[string]uint64 {
	c := &d.counters
	return map[string]uint64{
		"wireguard_devices": 0,
		"malformed_ip":      c.Malformed.Load(),
		"source_denied":     c.SourceDenied.Load(),
		"peer_denied":       c.PeerDenied.Load(),
		"no_route":          c.NoRoute.Load(),
		"send_errors":       c.SendErrors.Load(),
		"tun_errors":        c.TunErrors.Load(),
	}
}
