// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// startLabDERP supplies the live relay needed for the Tailscale Starting state
// to transition to Running before a direct peer handshake. This is a dedicated
// loopback-only test relay, never a public relay or an open proxy. On real hosts
// both this TLS port and the control port are forwarded over authenticated SSH.
// The generated test certificate is pinned in the isolated DERP map; TLS
// verification is not globally disabled. UDP data can still select a direct
// physical path independently of this bootstrap/relay channel.
func startLabDERP(addr string, logf logger.Logf) (*tailcfg.DERPMap, func(), error) {
	if err := requireLoopback(addr); err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	d := derpserver.New(key.NewNode(), logf)
	s := httptest.NewUnstartedServer(derpserver.Handler(d))
	s.Listener.Close()
	s.Listener = ln
	s.Config.ErrorLog = logger.StdLogger(logf)
	s.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	s.StartTLS()
	endpoint := ln.Addr().(*net.TCPAddr)
	hash := sha256.Sum256(s.Certificate().Raw)
	m := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		901: {
			RegionID: 901, RegionCode: "wgcompat-lab", RegionName: "Isolated compatibility test relay",
			Nodes: []*tailcfg.DERPNode{{
				Name: "wgcompat-lab-1", RegionID: 901,
				HostName: endpoint.IP.String(), IPv4: endpoint.IP.String(), IPv6: "none",
				DERPPort: endpoint.Port, STUNPort: -1,
				CertName: "sha256-raw:" + hex.EncodeToString(hash[:]),
			}},
		},
	}}
	return m, func() {
		d.Close()
		s.CloseClientConnections()
		s.Close()
	}, nil
}
