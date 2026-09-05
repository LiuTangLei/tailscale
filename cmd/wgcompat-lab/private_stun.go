// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"golang.org/x/time/rate"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
)

func attachPrivateSTUN(m *tailcfg.DERPMap, address string) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Port() == 0 || !ap.Addr().Is4() || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
		return errors.New("private STUN server requires a literal unicast IPv4:port")
	}
	region := m.Regions[901]
	if region == nil {
		return errors.New("missing isolated DERP region")
	}
	n := &tailcfg.DERPNode{Name: "lab-private-stun", RegionID: 901, HostName: ap.Addr().String(), IPv4: ap.Addr().String(), STUNPort: int(ap.Port()), STUNOnly: true}
	region.Nodes = append([]*tailcfg.DERPNode{n}, region.Nodes...)
	return nil
}

// An optional bounded STUN binding responder exists only for this lab process.
// It does not forward traffic and never changes firewall or production sockets.
func startPrivateSTUN(ctx context.Context, address string) (func(), error) {
	if address == "" {
		return func() {}, nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !ap.Addr().Is4() {
		return nil, errors.New("invalid test STUN listen address")
	}
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	limit := rate.NewLimiter(20, 40)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	go func() {
		defer close(done)
		b := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			tx, err := stun.ParseBindingRequest(b[:n])
			if err != nil || !limit.Allow() {
				continue
			}
			_, _ = c.WriteToUDPAddrPort(stun.Response(tx, from), from)
		}
	}()
	return func() { stop(); c.Close(); <-done }, nil
}
