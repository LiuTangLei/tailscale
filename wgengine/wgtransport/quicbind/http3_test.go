// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"tailscale.com/wgengine/wgtransport"
)

func TestProductionRejectsLegacyConfig(t *testing.T) {
	if _, err := NewFactory(Config{Version: 1}); !errors.Is(err, wgtransport.ErrUnsupported) {
		t.Fatalf("legacy config: %v", err)
	}
	// Rejection is before reading any key material, even when paths are missing.
	if _, err := NewFactory(Config{Version: 1, Payload: "wireguard", Certificate: "missing"}); !errors.Is(err, wgtransport.ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestHTTP3PublicPageDoesNotAuthorizeTunnel(t *testing.T) {
	p := newTestPair(t, "http3-udp", func(c *Config) { c.Server = true })
	p.open(t)
	a, b := p.backends[0], p.backends[1]
	cfg := a.factory.tlsConfig(&b.factory.local)
	cfg.Certificates = nil // genuine unauthenticated browser-style TLS client
	cfg.ServerName = "quic-ip.test"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q, err := a.active.Load().transport.Dial(ctx, a.factory.peers[b.factory.local].address, cfg, a.quicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer q.CloseWithError(0, "")
	client := (&http3.Transport{EnableDatagrams: true}).NewClientConn(q)
	req, err := http.NewRequestWithContext(ctx, "GET", "https://quic-ip.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || res.ProtoMajor != 3 || !strings.Contains(string(body), "Welcome") || !strings.Contains(res.Header.Get("Alt-Svc"), "h3=") {
		t.Fatalf("public site: %v status=%d proto=%s body=%s", err, res.StatusCode, res.Proto, body)
	}
	if res.Header.Get(serverHintHeader) != "" {
		t.Fatal("public site leaked private node declaration")
	}
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !client.Settings().EnableDatagrams || !client.Settings().EnableExtendedConnect {
		t.Fatal("missing HTTP/3 settings")
	}
	str, err := client.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = str.SetDeadline(time.Now().Add(5 * time.Second))
	u := b.factory.http3URL
	if err := str.SendRequestHeader(&http.Request{Method: "CONNECT", Proto: "connect-ip", Host: u.Host, URL: u, Header: http.Header{http3.CapsuleProtocolHeader: []string{"?1"}, serverHintHeader: []string{"?1"}}}); err != nil {
		t.Fatal(err)
	}
	reply, err := str.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if reply.StatusCode != 404 {
		t.Fatalf("unauthed CONNECT accepted: %d", reply.StatusCode)
	}
	str.CancelRead(0)
	str.CancelWrite(0)
	if b.peerServerHint(a.factory.local) != serverUnknown {
		t.Fatal("unauthenticated request poisoned server metadata")
	}
	if reply.Header.Get(serverHintHeader) != "" {
		t.Fatal("unauthenticated response leaked server metadata")
	}
	if b.counters.HTTP3Tunnels.Load() != 0 || b.counters.ReceivedPackets.Load() != 0 {
		t.Fatal("public request created a tunnel")
	}
}

func TestHTTP3ConfigValidation(t *testing.T) {
	p := newTestPair(t, "http3-udp")
	original := p.backends[0].factory.cfg
	cases := []func(*Config){
		func(c *Config) { c.HTTP3URL = "http://quic-ip.test/vpn" },
		func(c *Config) { c.HTTP3URL = "https://user:pass@quic-ip.test/vpn" },
		func(c *Config) { c.HTTP3URL = "https://quic-ip.test/{target}" },
		func(c *Config) { c.InitialPacketSize = 1199 },
		func(c *Config) { c.Payload = "wireguard" },
		func(c *Config) { c.HTTP3 = false },
	}
	for i, change := range cases {
		c := original
		change(&c)
		if _, err := NewFactory(c); err == nil {
			t.Errorf("invalid config %d accepted", i)
		}
	}
}

func TestHTTP3CapsuleValidation(t *testing.T) {
	// Address assignment: request ID 0, IPv4, address, /32.
	if err := validateIPCapsule(1, []byte{0, 4, 10, 0, 0, 1, 32}); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{{0}, {0, 5}, {0, 4, 10, 0, 0, 1, 33}} {
		if err := validateIPCapsule(1, data); err == nil {
			t.Fatalf("accepted malformed capsule %x", data)
		}
	}
	if err := validateIPCapsule(3, []byte{4, 10, 0, 0, 2, 10, 0, 0, 1, 0}); err == nil {
		t.Fatal("accepted inverted route")
	}
}
